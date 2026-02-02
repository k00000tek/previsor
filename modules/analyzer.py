from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Union

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, f1_score

from config import (
    LABEL_ENCODER_PATH,
    FEATURE_SCHEMA_PATH,
    RF_MODEL_PATH,
    XGB_MODEL_PATH,
    LAST_REPORT_PATH,
    LAST_REPORT_XGB_PATH,
)

# xgboost может отсутствовать в окружении — делаем импорт безопасным
try:
    from xgboost import XGBClassifier  # type: ignore
except Exception:  # pragma: no cover
    XGBClassifier = None  # type: ignore

logger = logging.getLogger(__name__)
if not logging.getLogger().handlers:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


def _env_bool(name: str, default: bool) -> bool:
    """Читает булеву переменную окружения.

    Args:
        name: Имя переменной окружения.
        default: Значение по умолчанию.

    Returns:
        Булево значение.
    """
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "y", "on"}


@dataclass
class RiskPolicy:
    """Политика формирования риска/алерта по выходам классификатора и TI.

    Attributes:
        precheck: Порог, при котором допустимо делать дорогую проверку TI (репутация IP).
        alert_threshold: Порог итогового риска для формирования алерта по классификатору.
        enable_ti: Разрешить ли TI-обогащение (AbuseIPDB и т.п.).
    """
    precheck: float = float(os.getenv("PREVISOR_PRECHECK_THRESHOLD", "0.80"))
    alert_threshold: float = float(os.getenv("PREVISOR_ALERT_THRESHOLD", "0.95"))
    enable_ti: bool = _env_bool("PREVISOR_ENABLE_TI", True)


class Analyzer:
    """Классификатор угроз (RF/XGB) + расчёт риска.

    Ответственность модуля:
    - обучение и сохранение модели (RF/XGB)
    - оценка качества на тестовой выборке
    - инференс: выдача списка алертов с полями:
        * base_probability — уверенность модели
        * probability — итоговый риск (может быть обогащён TI)
        * type — человекочитаемый тип угрозы (через label_encoder)

    Важно:
    - Пути к артефактам берём из config.py (models/runtime).
    - LabelEncoder загружается один раз и кэшируется в self.label_encoder.
    """

    def __init__(self, model_type: str = "rf", policy: Optional[RiskPolicy] = None) -> None:
        self.model_type = model_type.lower().strip()
        if self.model_type not in {"rf", "xgb"}:
            raise ValueError("model_type должен быть 'rf' или 'xgb'")

        self.model: Optional[Any] = None
        self.label_encoder: Optional[Any] = None

        self.model_path = RF_MODEL_PATH if self.model_type == "rf" else XGB_MODEL_PATH
        self.report_path = LAST_REPORT_PATH if self.model_type == "rf" else LAST_REPORT_XGB_PATH

        # Путь к схеме признаков (нужен для стабильного инференса)
        self.feature_schema_path = FEATURE_SCHEMA_PATH

        self.policy = policy or RiskPolicy()

        # Убеждаемся, что runtime-папки существуют
        os.makedirs(os.path.dirname(self.model_path) or ".", exist_ok=True)

    # ---------------------------
    # Обучение / оценка
    # ---------------------------

    def train_model(self, X_train: Union[pd.DataFrame, np.ndarray], y_train: Union[pd.Series, np.ndarray]) -> Any:
        """Обучает модель классификации угроз.

        Args:
            X_train: Матрица признаков обучения.
            y_train: Вектор меток (обычно label_encoded).

        Returns:
            Обученная модель.
        """
        logger.info("Запуск обучения модели: %s", self.model_type.upper())

        if self.model_type == "rf":
            self.model = RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1)
        else:
            if XGBClassifier is None:
                raise RuntimeError("xgboost не установлен в окружении, невозможно обучить XGB.")
            self.model = XGBClassifier(
                use_label_encoder=False,
                eval_metric="mlogloss",
                random_state=42,
            )

        self.model.fit(X_train, y_train)
        logger.info("Обучение завершено")

        # 1) Сохраняем схему признаков (если есть имена колонок)
        self._save_feature_schema(X_train)

        # 2) Сохраняем модель
        self.save_model()
        return self.model

    def evaluate(self, X_test: Union[pd.DataFrame, np.ndarray], y_test: Union[pd.Series, np.ndarray]) -> Dict[str, Any]:
        """Оценивает модель на тестовой выборке и сохраняет текстовый отчёт.

        Args:
            X_test: Матрица признаков.
            y_test: Истинные метки.

        Returns:
            Словарь с f1_score и report (dict-версия classification_report).
        """
        if self.model is None:
            raise ValueError("Модель не обучена. Сначала вызовите train_model() или load_model().")

        y_pred = self.model.predict(X_test)
        f1 = f1_score(y_test, y_pred, average="weighted")
        report_dict = classification_report(y_test, y_pred, output_dict=True)

        os.makedirs(os.path.dirname(self.report_path) or ".", exist_ok=True)
        with open(self.report_path, "w", encoding="utf-8") as f:
            f.write(f"Отчёт по модели {self.model_type.upper()} ({datetime.now().isoformat()})\n")
            f.write(f"F1-score (weighted): {f1:.4f}\n\n")
            f.write(classification_report(y_test, y_pred))
            f.write("\nМатрица ошибок:\n")
            f.write(str(confusion_matrix(y_test, y_pred)))

        logger.info("F1-score: %.4f", f1)
        logger.info("Отчёт сохранён: %s", self.report_path)
        return {"f1_score": float(f1), "report": report_dict}

    # ---------------------------
    # Инференс / алерты
    # ---------------------------

    def analyze(self, X: Union[pd.DataFrame, np.ndarray], source_ips: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Выполняет инференс и возвращает список алертов.

        Логика:
        1) predict_proba -> base_probability = max(probabilities)
        2) label -> decode (через LabelEncoder при наличии)
        3) risk_score = base_probability (по умолчанию)
        4) (опционально) TI-обогащение: если не normal или base_prob >= precheck
        5) alert = not normal AND risk_score >= alert_threshold

        Args:
            X: Матрица признаков.
            source_ips: Список source_ip по строкам X (опционально).

        Returns:
            Список алертов (dict).
        """
        if self.model is None:
            self.load_model()

        if self.model is None:
            raise ValueError(f"Модель не найдена: {self.model_path}. Обучите или загрузите модель.")

        # Загружаем LabelEncoder один раз (если есть)
        if self.label_encoder is None:
            self._load_label_encoder()

        # Пытаемся получить вероятности. Если модель не поддерживает predict_proba — деградируем аккуратно.
        probs = self._predict_proba_safe(X)
        pred = self.model.predict(X)

        if probs is not None:
            max_prob = np.max(probs, axis=1)
        else:
            # fallback: если нет predict_proba, используем 1.0 как “неизвестно, но уверенно”
            max_prob = np.ones(shape=(len(pred),), dtype=float)

        alerts: List[Dict[str, Any]] = []

        for i, (p, base_prob) in enumerate(zip(pred, max_prob)):
            ip = source_ips[i] if source_ips and i < len(source_ips) else None
            label = self._decode_label(p)

            base_prob_f = float(base_prob)

            is_normal = self._is_normal_label(label)
            risk_score = base_prob_f

            if self.policy.enable_ti and ((not is_normal) or (base_prob_f >= self.policy.precheck)):
                risk_score = self._enrich_with_ti(label=label, base_probability=base_prob_f, ip=ip)

            is_alert = bool((not is_normal) and (float(risk_score) >= self.policy.alert_threshold))

            alert = {
                "alert": int(is_alert),
                "type": str(label),
                "base_probability": float(base_prob_f),
                "probability": float(risk_score),
                "timestamp": datetime.now().isoformat(),
                "source_ip": ip,
            }
            alerts.append(alert)

            if is_alert:
                logger.warning(
                    "УГРОЗА: %s (base_prob=%.2f, risk=%.2f, IP=%s)",
                    label,
                    base_prob_f,
                    float(risk_score),
                    ip,
                )

        return alerts

    # ---------------------------
    # IO артефактов
    # ---------------------------

    def save_model(self) -> None:
        """Сохраняет текущую модель на диск."""
        if self.model is None:
            raise ValueError("Нечего сохранять: модель не инициализирована.")
        os.makedirs(os.path.dirname(self.model_path) or ".", exist_ok=True)
        joblib.dump(self.model, self.model_path)
        logger.info("Модель сохранена: %s", self.model_path)

    def load_model(self) -> None:
        """Загружает модель с диска."""
        if os.path.exists(self.model_path):
            self.model = joblib.load(self.model_path)
            logger.info("Модель загружена: %s", self.model_path)
        else:
            logger.error("Модель не найдена: %s", self.model_path)
            self.model = None

    # ---------------------------
    # Внутренние утилиты
    # ---------------------------

    def _save_feature_schema(self, X_train: Union[pd.DataFrame, np.ndarray]) -> None:
        """Сохраняет схему признаков (feature columns), если X_train — DataFrame.

        Args:
            X_train: Матрица признаков обучения.
        """
        try:
            if hasattr(X_train, "columns"):
                cols = list(getattr(X_train, "columns"))
                os.makedirs(os.path.dirname(self.feature_schema_path) or ".", exist_ok=True)
                joblib.dump(cols, self.feature_schema_path)
                logger.info("Схема признаков сохранена: %s (%d колонок)", self.feature_schema_path, len(cols))
            else:
                logger.warning("X_train не DataFrame — схема признаков не сохранена (нужны имена колонок).")
        except Exception as exc:
            logger.warning("Не удалось сохранить feature schema: %s", exc)

    def _load_label_encoder(self) -> None:
        """Пробует загрузить LabelEncoder из runtime-пути.

        Если файл отсутствует — оставляет self.label_encoder=None, и decode будет через fallback.
        """
        try:
            if os.path.exists(LABEL_ENCODER_PATH):
                self.label_encoder = joblib.load(LABEL_ENCODER_PATH)
                logger.info("LabelEncoder загружен: %s", LABEL_ENCODER_PATH)
        except Exception as exc:
            logger.warning("Не удалось загрузить LabelEncoder (%s): %s", LABEL_ENCODER_PATH, exc)
            self.label_encoder = None

    def _decode_label(self, encoded: Any) -> str:
        """Преобразует предсказанный класс в человекочитаемую метку.

        Стратегия:
        - если encoded уже строка -> возвращаем как есть
        - иначе пытаемся inverse_transform через LabelEncoder
        - иначе fallback: str(encoded)

        Args:
            encoded: Предсказанный класс модели (int/str).

        Returns:
            Строковая метка класса.
        """
        if isinstance(encoded, str):
            return encoded

        if self.label_encoder is not None:
            try:
                return str(self.label_encoder.inverse_transform([encoded])[0])
            except Exception:
                pass

        # Доп. fallback: если модель хранит classes_ строками
        try:
            classes = getattr(self.model, "classes_", None)
            if classes is not None and len(classes) > 0:
                # Если classes_ строковые, а предсказание — индекс/значение, просто приводим к строке
                return str(encoded)
        except Exception:
            pass

        return str(encoded)

    @staticmethod
    def _is_normal_label(label: str) -> bool:
        """Определяет, является ли метка “нормальным” трафиком.

        Args:
            label: Метка класса.

        Returns:
            True если benign/normal/background, иначе False.
        """
        label_lower = str(label).strip().lower()
        return (
            label_lower.startswith("normal")
            or "benign" in label_lower
            or "background" in label_lower
            or label_lower in {"0", "normal traffic", "normal"}
        )

    def _predict_proba_safe(self, X: Union[pd.DataFrame, np.ndarray]) -> Optional[np.ndarray]:
        """Безопасно вызывает predict_proba.

        Args:
            X: Матрица признаков.

        Returns:
            Массив вероятностей (n_samples, n_classes) или None, если метод недоступен.
        """
        try:
            if hasattr(self.model, "predict_proba"):
                probs = self.model.predict_proba(X)
                return np.asarray(probs)
        except Exception as exc:
            logger.warning("predict_proba недоступен/ошибка: %s", exc)
        return None

    def _enrich_with_ti(self, *, label: str, base_probability: float, ip: Optional[str]) -> float:
        """TI-обогащение риска (репутация IP).

        Важно: TI — потенциально дорогая операция (сетевой запрос).
        Мы вызываем её только по правилам policy и оборачиваем в try/except, чтобы пайплайн не падал.

        Args:
            label: Метка типа угрозы.
            base_probability: Базовая уверенность модели.
            ip: IP адрес источника (может быть None).

        Returns:
            Итоговый риск (float).
        """
        if not ip:
            return float(base_probability)

        try:
            from utils.api_integration import enrich_alert_with_reputation  # локальный импорт

            risk = enrich_alert_with_reputation(label, base_probability, ip)
            return float(risk)
        except Exception as exc:
            logger.warning("TI-обогащение не выполнено (%s). Использую base_probability.", exc)
            return float(base_probability)
