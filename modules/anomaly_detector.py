from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple, Union

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from config import IFOREST_MODEL_PATH

logger = logging.getLogger(__name__)
if not logging.getLogger().handlers:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


def _env_float(name: str, default: float) -> float:
    """Безопасно читает float из переменной окружения."""
    raw = os.getenv(name)
    if raw is None:
        return float(default)
    try:
        return float(raw)
    except Exception:
        return float(default)


def _env_int(name: str, default: int) -> int:
    """Безопасно читает int из переменной окружения."""
    raw = os.getenv(name)
    if raw is None:
        return int(default)
    try:
        return int(raw)
    except Exception:
        return int(default)


@dataclass
class AnomalyPolicy:
    """Политика детекции аномалий.

    Attributes:
        contamination: Доля аномалий для IsolationForest (грубая априорная оценка).
        quantile: Квантиль anomaly_score для отбора (например 0.99 = топ-1%).
        max_alerts: Максимум алертов-анoмалий за прогон.
        require_pred_minus1: Требовать ли условие IsolationForest preds == -1.
        decision_threshold: Порог по decision_function для режима threshold.
    """

    contamination: float = _env_float("PREVISOR_ANOMALY_CONTAMINATION", 0.02)
    quantile: float = _env_float("PREVISOR_ANOMALY_QUANTILE", 0.99)
    max_alerts: int = _env_int("PREVISOR_ANOMALY_MAX_ALERTS", 50)
    require_pred_minus1: bool = os.getenv("PREVISOR_ANOMALY_REQUIRE_MINUS1", "true").strip().lower() in {"1", "true", "yes", "y", "on"}
    decision_threshold: float = _env_float("PREVISOR_ANOMALY_DECISION_THRESHOLD", -0.1)


class AnomalyDetector:
    """Детектор аномалий на основе IsolationForest.

    Назначение:
    - хранит/загружает baseline-модель IsolationForest;
    - выдаёт предсказания (preds) и decision_function.

    Важная инженерная оговорка (для стабильности пайплайна):
    - если baseline-модель отсутствует, мы можем "bootstrap"-обучить её на текущем батче,
      сохранить и вернуть пустой список аномалий на первом прогоне. Это позволяет пользователю
      запустить систему "из коробки": первый прогон инициализирует baseline, а со второго
      уже возможна полноценная детекция.
    """

    def __init__(
        self,
        *,
        contamination: Optional[float] = None,
        random_state: int = 42,
        model_path: str = IFOREST_MODEL_PATH,
    ) -> None:
        self.model_path = model_path

        if contamination is None:
            contamination = _env_float("PREVISOR_ANOMALY_CONTAMINATION", 0.02)

        self.model = IsolationForest(
            contamination=float(contamination),
            random_state=int(random_state),
            n_estimators=200,
            n_jobs=-1,
        )

    def fit(self, X: Union[pd.DataFrame, np.ndarray]) -> None:
        """Обучает IsolationForest и сохраняет модель на диск.

        Args:
            X: Матрица признаков (DataFrame или numpy array).
        """
        os.makedirs(os.path.dirname(self.model_path) or ".", exist_ok=True)
        self.model.fit(X)
        joblib.dump(self.model, self.model_path)
        logger.info("IsolationForest обучен и сохранён: %s", self.model_path)

    def load(self) -> bool:
        """Загружает модель с диска.

        Returns:
            True, если модель успешно загружена, иначе False.
        """
        if os.path.exists(self.model_path):
            self.model = joblib.load(self.model_path)
            return True
        return False

    def predict(self, X: Union[pd.DataFrame, np.ndarray]) -> Tuple[np.ndarray, np.ndarray]:
        """Возвращает предсказания и decision_function.

        Args:
            X: Матрица признаков.

        Returns:
            preds: -1 = аномалия, 1 = норма.
            decision: decision_function (чем меньше, тем объект “аномальнее”).
        """
        preds = self.model.predict(X)
        decision = self.model.decision_function(X)
        return preds, decision


def detect_anomalies(
    X: Union[pd.DataFrame, np.ndarray],
    *,
    source_ips: Optional[List[str]] = None,
    # Старый режим: если threshold задан, используем (pred=-1 AND decision < threshold)
    threshold: Optional[float] = None,
    # Новый режим по умолчанию: выбираем аномалии по квантилю аномальности
    strategy: str = "quantile",  # "quantile" | "threshold"
    quantile: float = 0.99,
    max_alerts: int = 50,
    require_pred_minus1: bool = True,
    # Поведение при отсутствии baseline модели:
    # True  -> обучаем на текущем батче и возвращаем []
    # False -> возвращаем [] без обучения
    bootstrap_if_missing: bool = True,
) -> List[Dict[str, Any]]:
    """Ищет аномалии в X и возвращает список алертов в едином формате.

    Ключевые определения:
    - decision_function: чем меньше, тем объект аномальнее.
    - anomaly_score = -decision_function: чем больше, тем объект аномальнее.
    - probability: нормированный anomaly_score в диапазоне 0..1 (нормировка на текущем батче).

    Args:
        X: Матрица признаков.
        source_ips: Список IP, параллельный строкам X (опционально).
        threshold: Порог decision_function для режима threshold.
        strategy: "quantile" (по умолчанию) или "threshold".
        quantile: Квантиль anomaly_score (например 0.99 = топ-1%).
        max_alerts: Максимум аномалий за прогон.
        require_pred_minus1: Требовать ли условие preds == -1.
        bootstrap_if_missing: Если baseline отсутствует — обучить на текущем X и вернуть [].

    Returns:
        Список словарей-алертов. Поле probability нормировано 0..1.
    """
    policy = AnomalyPolicy()

    # Применяем env-конфигурацию, если параметр не задан явно вызывающим кодом
    if max_alerts == 50:
        max_alerts = policy.max_alerts
    if quantile == 0.99:
        quantile = policy.quantile
    if require_pred_minus1 is True:
        require_pred_minus1 = policy.require_pred_minus1

    det = AnomalyDetector(contamination=policy.contamination, model_path=IFOREST_MODEL_PATH)

    if not det.load():
        if bootstrap_if_missing:
            # Bootstrap baseline: чтобы pipeline работал "из коробки" для real режима.
            if isinstance(X, pd.DataFrame) and X.empty:
                logger.warning("IsolationForest отсутствует и X пустой — bootstrap невозможен. Аномалии пропущены.")
                return []
            if isinstance(X, np.ndarray) and X.size == 0:
                logger.warning("IsolationForest отсутствует и X пустой — bootstrap невозможен. Аномалии пропущены.")
                return []

            logger.info("IsolationForest модель не найдена: %s. Выполняю bootstrap-обучение baseline на текущем батче.", det.model_path)
            try:
                det.fit(X)
            except Exception as exc:
                logger.warning("Bootstrap-обучение IsolationForest не удалось: %s. Аномалии пропущены.", exc)
            return []

        logger.warning("IsolationForest модель не найдена: %s (аномалии пропущены)", det.model_path)
        return []

    preds, decision = det.predict(X)

    # anomaly_score: больше = аномальнее
    anomaly_score = -decision.astype(float)

    # Нормировка в 0..1 на текущем батче
    s_min = float(np.min(anomaly_score))
    s_max = float(np.max(anomaly_score))
    if s_max > s_min:
        norm = (anomaly_score - s_min) / (s_max - s_min)
    else:
        norm = np.zeros_like(anomaly_score)

    # Выбор индексов-кандидатов
    if threshold is not None or strategy == "threshold":
        thr = float(threshold) if threshold is not None else float(policy.decision_threshold)
        mask = decision < thr
    else:
        q = float(quantile)
        q = min(max(q, 0.5), 0.9999)
        thr_score = float(np.quantile(anomaly_score, q))
        mask = anomaly_score >= thr_score

    if require_pred_minus1:
        mask = mask & (preds == -1)

    idx = np.where(mask)[0].tolist()
    if not idx:
        return []

    # Сортируем по убыванию аномальности
    idx.sort(key=lambda i: anomaly_score[i], reverse=True)
    if max_alerts > 0:
        idx = idx[:max_alerts]

    alerts: List[Dict[str, Any]] = []
    now = datetime.now().isoformat()

    for i in idx:
        ip = source_ips[i] if source_ips and i < len(source_ips) else None
        alerts.append(
            {
                "alert": 1,
                "type": "Anomaly",
                "probability": float(norm[i]),  # 0..1
                "timestamp": now,
                "source_ip": ip,
            }
        )

    return alerts
