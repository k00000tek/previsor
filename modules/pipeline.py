from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Optional, Dict, Any, List

import joblib
import pandas as pd

import config as cfg
from config import (
    MODE,
    FEATURE_SCHEMA_PATH,
    ANOMALY_ENABLED,
    IFOREST_MODEL_PATH,
    HEURISTICS_ENABLED,
    LOG_TRAFFIC,
)
from modules.data_collector import collect_traffic
from modules.preprocessor import preprocess_data
from modules.analyzer import Analyzer
from modules.anomaly_detector import detect_anomalies
from modules.heuristics import detect_heuristic_alerts
from modules.database import save_traffic_logs

logger = logging.getLogger(__name__)
if not logging.getLogger().handlers:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


@dataclass
class PipelineResult:
    """Результат выполнения пайплайна.

    Атрибуты:
        processed_df: Обработанный DataFrame (после очистки/кодирования/масштабирования).
        X: Матрица признаков, подаваемая на модели.
        alerts: Список алертов в унифицированном формате.
    """
    processed_df: pd.DataFrame
    X: pd.DataFrame
    alerts: List[Dict[str, Any]]


class PreVisorPipeline:
    """Единый пайплайн PreVisor.

    Общая схема:
        collect -> preprocess -> align_features -> classify -> anomalies -> normalize/merge

    Используется одинаково:
    - во Flask (ручной запуск /analyze)
    - в фоновом мониторинге (непрерывные батчи)

    Ключевая часть стабильности: выравнивание признаков по схеме обучения (feature schema),
    чтобы инференс не ломался при различиях в наборах колонок.
    """

    def __init__(
        self,
        model_type: str = "rf",
        feature_schema_path: str = FEATURE_SCHEMA_PATH,
        *,
        enable_classifier: bool = True,
        enable_anomalies: bool = True,
        enable_heuristics: bool = HEURISTICS_ENABLED,
        enable_traffic_logs: bool = LOG_TRAFFIC,
        anomaly_strategy: Optional[str] = None,     # "baseline" | "quantile" | "threshold"
        anomaly_quantile: Optional[float] = None,         # top 1% по "аномальности"
        anomaly_threshold: Optional[float] = None,  # legacy: decision_function < threshold
        max_anomaly_alerts: int = 50,            # ограничение числа аномалий на прогон
    ) -> None:
        """Инициализирует пайплайн.

        Args:
            model_type: Тип модели классификатора.
            feature_schema_path: Путь к схеме признаков.
            enable_classifier: Включить классификатор.
            enable_anomalies: Включить детектор аномалий.
            enable_heuristics: Включить эвристики.
            enable_traffic_logs: Логировать трафик в БД.
            anomaly_strategy: Стратегия выбора аномалий.
            anomaly_quantile: Квантиль для аномалий.
            anomaly_threshold: Порог decision_function.
            max_anomaly_alerts: Максимум аномалий за прогон.
        """
        self.model_type = str(model_type).strip().lower()
        self.feature_schema_path = feature_schema_path
        self.feature_schema_fallback_path = getattr(cfg, "FEATURE_SCHEMA_PRETRAINED_PATH", None)

        self.enable_classifier = enable_classifier
        self.enable_heuristics = enable_heuristics
        self.enable_traffic_logs = enable_traffic_logs

        # Детектор аномалий включаем только при выполнении условий рабочего сценария.
        # Требование:
        #   - ANOMALY_ENABLED=1 (или PREVISOR_ANOMALY_ENABLED=1)
        #   - baseline-модель IsolationForest существует
        self.enable_anomalies = self._should_enable_anomalies(enable_anomalies)
        self._requested_anomalies = bool(enable_anomalies)

        if anomaly_strategy is None or not str(anomaly_strategy).strip():
            anomaly_strategy = os.getenv("PREVISOR_ANOMALY_STRATEGY", "baseline")
        self.anomaly_strategy = str(anomaly_strategy).strip().lower()

        if anomaly_quantile is None:
            anomaly_quantile = float(os.getenv("PREVISOR_ANOMALY_QUANTILE", "0.99"))
        self.anomaly_quantile = float(anomaly_quantile)
        self.anomaly_threshold = anomaly_threshold
        self.max_anomaly_alerts = max_anomaly_alerts

        # Кэшируем Analyzer, чтобы не перечитывать модель с диска на каждом прогоне.
        self.analyzer = Analyzer(model_type=self.model_type)

    @staticmethod
    def _should_enable_anomalies(requested: bool) -> bool:
        """Определяет, можно ли включить аномалии в текущем окружении.

        Args:
            requested: Желание вызывающего кода включить аномалии.

        Returns:
            True, если аномалии следует включить.
        """
        if not requested:
            return False
        if not ANOMALY_ENABLED:
            return False
        if not IFOREST_MODEL_PATH or not os.path.exists(IFOREST_MODEL_PATH):
            logger.info("ANOMALY_ENABLED=1, но IsolationForest не найден (%s) — anomaly_detector выключен", IFOREST_MODEL_PATH)
            return False
        return True

    def run(
        self,
        *,
        mode: str = MODE,
        model_type: Optional[str] = None,
        input_df: Optional[pd.DataFrame] = None,
        input_csv: Optional[str] = None,
        collect_params: Optional[Dict[str, Any]] = None,
        preprocess_params: Optional[Dict[str, Any]] = None,
    ) -> PipelineResult:
        """Запуск пайплайна.

        Источник данных выбирается по приоритету:
        1) input_df
        2) input_csv
        3) collect_traffic(mode=...)

        Режимы:
            - real: пользовательский режим (реальный сбор)
            - demo/test/dataset: внутренние режимы

        Args:
            mode: Режим работы ("real"/"demo"/"test"/"dataset").
            model_type: Если задано — переопределяет тип модели классификатора ("rf"|"xgb") для текущего запуска.
            input_df: Сырые данные DataFrame (если уже собраны).
            input_csv: Путь к CSV (если уже сохранены).
            collect_params: Параметры для collect_traffic() (кроме mode/save_csv).
            preprocess_params: Параметры для preprocess_data() (purpose всегда будет inference).

        Returns:
            PipelineResult: processed_df, X и список алертов (classifier + anomaly_detector).
        """
        if model_type is not None:
            model_type_norm = str(model_type).strip().lower()
            if model_type_norm and model_type_norm != self.model_type:
                self.model_type = model_type_norm
                self.analyzer = Analyzer(model_type=self.model_type)
        if mode not in {"real", "demo", "test", "dataset"}:
            raise ValueError(f"Неизвестный режим mode={mode!r}. Ожидается: real/demo/test/dataset")

        # Модель аномалий может появиться после запуска приложения (auto-train),
        # поэтому проверяем возможность включения anomaly_detector на каждом прогоне.
        if self._requested_anomalies and not self.enable_anomalies:
            self.enable_anomalies = self._should_enable_anomalies(True)

        collect_params = dict(collect_params or {})
        preprocess_params = dict(preprocess_params or {})

        # Защита от конфликтов аргументов: mode/save_csv задаёт сам pipeline.
        collect_params.pop("mode", None)
        collect_params.pop("save_csv", None)

        # Для real-режима явно прокидываем параметры захвата, чтобы учитывать env/runtime-настройки.
        if mode == "real":
            collect_params.setdefault(
                "iface",
                os.getenv("PREVISOR_NET_IFACE", getattr(cfg, "NETWORK_INTERFACE", "auto")),
            )
            collect_params.setdefault(
                "num_packets",
                int(os.getenv("PREVISOR_PACKET_COUNT", str(getattr(cfg, "PACKET_COUNT_PER_COLLECTION", 200)))),
            )
            collect_params.setdefault(
                "timeout_sec",
                int(os.getenv("PREVISOR_PACKET_TIMEOUT", str(getattr(cfg, "PACKET_SNIFF_TIMEOUT_SEC", 30)))),
            )
            collect_params.setdefault(
                "bpf_filter",
                os.getenv("PREVISOR_BPF_FILTER", getattr(cfg, "BPF_FILTER", "")),
            )

        # На уровне пайплайна фиксируем инференс-предобработку.
        preprocess_params["purpose"] = "inference"

        # 1) Получаем сырые данные + предобработка
        raw_df: Optional[pd.DataFrame] = None
        if input_df is not None:
            raw_df = input_df.copy()
            pre = preprocess_data(raw_df, **preprocess_params)
        elif input_csv is not None:
            raw_df = pd.read_csv(input_csv)
            pre = preprocess_data(raw_df, **preprocess_params)
        else:
            raw_df = collect_traffic(mode=mode, save_csv=True, **collect_params)
            pre = preprocess_data(raw_df, **preprocess_params)

        processed_df = pre["processed_df"]

        # 2) Источник IP для алертов
        source_ips = processed_df["source_ip"].tolist() if "source_ip" in processed_df.columns else None

        # 2a) Логирование трафика (сырые строки)
        traffic_log_ids: Optional[List[int]] = None
        if self.enable_traffic_logs and raw_df is not None:
            try:
                ids = save_traffic_logs(raw_df, mode=mode, return_ids=True)
                if isinstance(ids, list):
                    traffic_log_ids = ids
            except Exception:
                logger.exception("Не удалось сохранить traffic_logs")

        # 3) Формируем X и выравниваем по schema обучения
        X = self._build_X(pre, processed_df)
        if X is None or (hasattr(X, "empty") and X.empty):
            return PipelineResult(processed_df=processed_df, X=X, alerts=[])
        X = self._align_features(X)

        alerts: List[Dict[str, Any]] = []

        # 4) Классификация (RF/XGB)
        if self.enable_classifier:
            class_alerts = self.analyzer.analyze(X, source_ips=source_ips)
            alerts.extend(self._normalize_class_alerts(class_alerts, traffic_log_ids=traffic_log_ids))

        # 4a) Эвристики (DDoS/port-scan/HTTP)
        if self.enable_heuristics and raw_df is not None:
            require_private_target = (
                mode == "real"
                and os.getenv("PREVISOR_HEURISTICS_REQUIRE_PRIVATE_TARGET", "true").strip().lower()
                in {"1", "true", "yes", "y", "on"}
            )
            try:
                heur_alerts = detect_heuristic_alerts(
                    raw_df,
                    require_private_target=require_private_target,
                )
                alerts.extend(self._normalize_heur_alerts(heur_alerts, traffic_log_ids=traffic_log_ids))
            except Exception:
                logger.exception("Ошибка эвристического детектора")

        # 5) Аномалии (IsolationForest)
        if self.enable_anomalies:
            anom_alerts = detect_anomalies(
                X,
                source_ips=source_ips,
                threshold=self.anomaly_threshold,
                strategy=self.anomaly_strategy,
                quantile=self.anomaly_quantile,
                max_alerts=self.max_anomaly_alerts,
                require_pred_minus1=True,
            )
            alerts.extend(self._normalize_anom_alerts(anom_alerts, traffic_log_ids=traffic_log_ids))

        return PipelineResult(processed_df=processed_df, X=X, alerts=alerts)

    def _build_X(self, pre: Dict[str, Any], processed_df: pd.DataFrame) -> pd.DataFrame:
        """Строит матрицу признаков X для моделей.

        Предпочтительно использует pre["X"], т.к. это “контрактный” результат preprocess_data.

        Args:
            pre: Результат preprocess_data (словарь).
            processed_df: Обработанный DataFrame.

        Returns:
            DataFrame X.
        """
        X = pre.get("X")
        if isinstance(X, pd.DataFrame):
            return X.copy()

        numeric = processed_df.select_dtypes(include=["number"]).copy()
        if "label_encoded" in numeric.columns:
            numeric = numeric.drop(columns=["label_encoded"], errors="ignore")
        return numeric

    def _align_features(self, X: pd.DataFrame) -> pd.DataFrame:
        """Выравнивает признаки по сохранённой схеме обучения (feature schema).

        - добавляет отсутствующие колонки (0.0)
        - удаляет лишние
        - приводит порядок колонок

        Если schema отсутствует — возвращает X как есть.

        Args:
            X: Матрица признаков.

        Returns:
            X с выровненными колонками.
        """
        X = X.copy()

        schema_path = self.feature_schema_path
        if not schema_path or not os.path.exists(schema_path):
            fallback = self.feature_schema_fallback_path
            if fallback and os.path.exists(fallback):
                schema_path = fallback
            else:
                logger.warning("feature schema не найдена (%s) — инференс может быть нестабилен", self.feature_schema_path)
                return X

        feature_cols = joblib.load(schema_path)
        if not isinstance(feature_cols, (list, tuple)) or not all(isinstance(c, str) for c in feature_cols):
            logger.warning("Некорректный формат feature schema (%s) — пропускаю align_features", type(feature_cols))
            return X

        for col in feature_cols:
            if col not in X.columns:
                X[col] = 0.0

        # удаляем лишние и фиксируем порядок
        return X[list(feature_cols)]

    @staticmethod
    def _get_alert_type(a: Dict[str, Any]) -> str:
        """Устойчиво извлекает тип алерта из разных форматов."""
        return str(a.get("alert_type") or a.get("type") or "Unknown")

    def _normalize_class_alerts(
        self,
        alerts: List[Dict[str, Any]],
        *,
        traffic_log_ids: Optional[List[int]] = None,
    ) -> List[Dict[str, Any]]:
        """Приводит алерты классификатора к единому формату.

        Args:
            alerts: Алерты классификатора.
            traffic_log_ids: Список ID из таблицы traffic_logs, параллельный raw_df.

        Returns:
            Список алертов в унифицированном формате.
        """
        norm: List[Dict[str, Any]] = []
        for a in alerts:
            row_index = a.get("row_index")
            traffic_log_id = None
            if traffic_log_ids is not None and row_index is not None:
                try:
                    traffic_log_id = traffic_log_ids[int(row_index)]
                except Exception:
                    traffic_log_id = None
            norm.append(
                {
                    "alert": int(a.get("alert", 0)),
                    "alert_type": self._get_alert_type(a),
                    "model_type": self.model_type,
                    "base_probability": a.get("base_probability"),
                    "probability": a.get("probability"),
                    "timestamp": a.get("timestamp"),
                    "source_ip": a.get("source_ip"),
                    "detection_source": "classifier",
                    "traffic_log_id": traffic_log_id,
                }
            )
        return norm

    def _normalize_anom_alerts(
        self,
        alerts: List[Dict[str, Any]],
        *,
        traffic_log_ids: Optional[List[int]] = None,
    ) -> List[Dict[str, Any]]:
        """Приводит алерты детектора аномалий к единому формату.

        Args:
            alerts: Алерты детектора аномалий.
            traffic_log_ids: Список ID из таблицы traffic_logs, параллельный raw_df.

        Returns:
            Список алертов в унифицированном формате.
        """
        norm: List[Dict[str, Any]] = []
        for a in alerts:
            row_index = a.get("row_index")
            traffic_log_id = None
            if traffic_log_ids is not None and row_index is not None:
                try:
                    traffic_log_id = traffic_log_ids[int(row_index)]
                except Exception:
                    traffic_log_id = None
            norm.append(
                {
                    "alert": int(a.get("alert", 0)),
                    "alert_type": self._get_alert_type(a) if a.get("type") else "Anomaly",
                    "model_type": "iforest",
                    "base_probability": None,
                    "probability": a.get("probability"),
                    "timestamp": a.get("timestamp"),
                    "source_ip": a.get("source_ip"),
                    "detection_source": "anomaly_detector",
                    "traffic_log_id": traffic_log_id,
                }
            )
        return norm

    def _normalize_heur_alerts(
        self,
        alerts: List[Dict[str, Any]],
        *,
        traffic_log_ids: Optional[List[int]] = None,
    ) -> List[Dict[str, Any]]:
        """Приводит алерты эвристик к единому формату.

        Args:
            alerts: Алерты эвристик.
            traffic_log_ids: Список ID из таблицы traffic_logs, параллельный raw_df.

        Returns:
            Список алертов в унифицированном формате.
        """
        norm: List[Dict[str, Any]] = []
        for a in alerts:
            row_index = a.get("row_index")
            traffic_log_id = None
            if traffic_log_ids is not None and row_index is not None:
                try:
                    traffic_log_id = traffic_log_ids[int(row_index)]
                except Exception:
                    traffic_log_id = None
            norm.append(
                {
                    "alert": int(a.get("alert", 0)),
                    "alert_type": self._get_alert_type(a),
                    "model_type": "heuristics",
                    "base_probability": None,
                    "probability": a.get("probability"),
                    "timestamp": a.get("timestamp"),
                    "source_ip": a.get("source_ip"),
                    "detection_source": a.get("detection_source") or "heuristics",
                    "details": a.get("details"),
                    "traffic_log_id": traffic_log_id,
                }
            )
        return norm
