from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass

import joblib
import pandas as pd

import config as cfg
from modules.anomaly_detector import (
    AnomalyDetector,
    AnomalyPolicy,
    compute_anomaly_stats,
    save_anomaly_stats,
    load_anomaly_stats,
)
from modules.preprocessor import preprocess_data
from modules.database import count_baseline_candidates, load_baseline_candidates_df

logger = logging.getLogger(__name__)
if not logging.getLogger().handlers:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


def _env_int(name: str, default: int) -> int:
    """Читает int из переменной окружения.

    Args:
        name: Имя переменной.
        default: Значение по умолчанию.

    Returns:
        int.
    """
    raw = os.getenv(name)
    if raw is None:
        return int(default)
    try:
        return int(raw)
    except Exception:
        return int(default)


def _env_bool(name: str, default: bool) -> bool:
    """Читает bool из переменной окружения.

    Args:
        name: Имя переменной.
        default: Значение по умолчанию.

    Returns:
        bool.
    """
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "y", "on"}


def _align_features(X: pd.DataFrame, feature_schema_path: str) -> pd.DataFrame:
    """Выравнивает матрицу признаков по схеме обучения.

    Args:
        X: Матрица признаков.
        feature_schema_path: Путь к feature schema.

    Returns:
        Матрица признаков в согласованном порядке.
    """
    schema_path = feature_schema_path
    if not schema_path or not os.path.exists(schema_path):
        fallback = getattr(cfg, "FEATURE_SCHEMA_PRETRAINED_PATH", None)
        if fallback and os.path.exists(fallback):
            schema_path = fallback
        else:
            logger.warning("feature schema не найдена (%s) - обучение baseline будет без align", feature_schema_path)
            return X

    feature_cols = joblib.load(schema_path)
    if not isinstance(feature_cols, (list, tuple)) or not all(isinstance(c, str) for c in feature_cols):
        logger.warning("Некорректный формат feature schema (%s) - пропускаю align", type(feature_cols))
        return X

    X = X.copy()
    for col in feature_cols:
        if col not in X.columns:
            X[col] = 0.0

    return X[list(feature_cols)]


@dataclass
class BaselinePolicy:
    """Политика накопления baseline и ретренинга аномалий."""
    auto_enabled: bool = _env_bool("PREVISOR_BASELINE_AUTO_ENABLED", True)
    min_rows: int = _env_int("PREVISOR_BASELINE_TARGET_ROWS", 5000)
    anomaly_auto_train: bool = _env_bool("PREVISOR_ANOMALY_AUTO_TRAIN", True)
    anomaly_retrain_hours: int = _env_int("PREVISOR_ANOMALY_RETRAIN_HOURS", 24)
    anomaly_retrain_rows: int = _env_int(
        "PREVISOR_ANOMALY_RETRAIN_ROWS",
        int(getattr(cfg, "PREVISOR_ANOMALY_RETRAIN_ROWS", 5000)),
    )


def count_baseline_rows(*, mode: str = "real") -> int:
    """Возвращает размер baseline-пула в БД (traffic_logs).

    Baseline формируется из traffic_logs (обычно mode="real").
    В пул входят записи, у которых нет связанных алертов со статусом, отличным от false_positive.

    Args:
        mode: Фильтр по traffic_logs.mode.

    Returns:
        Количество baseline-кандидатов.
    """
    return int(count_baseline_candidates(mode=mode))


def maybe_train_anomaly_model_from_db(*, feature_schema_path: str, mode: str = "real") -> bool:
    """Переобучает IsolationForest при выполнении условий (baseline из БД).

    Источник baseline:
        таблица traffic_logs (фильтр по mode) за вычетом записей,
        связанных с алертами (кроме false_positive).

    Args:
        feature_schema_path: Путь к feature schema.
        mode: Режим baseline-пула (обычно "real").

    Returns:
        True, если модель была переобучена.
    """
    policy = BaselinePolicy()
    if not policy.anomaly_auto_train:
        return False

    current_rows = int(count_baseline_candidates(mode=mode))
    if current_rows < policy.min_rows:
        return False

    model_path = getattr(cfg, "IFOREST_MODEL_PATH", os.path.join(cfg.MODELS_RUNTIME_DIR, "isolation_forest.pkl"))
    if os.path.exists(model_path):
        mtime = os.path.getmtime(model_path)
        too_soon = (time.time() - mtime) < (policy.anomaly_retrain_hours * 3600)

        # Доп. условие: ретренинг по приросту baseline строк
        stats_path = getattr(cfg, "IFOREST_STATS_PATH", None)
        stats = load_anomaly_stats(stats_path, getattr(cfg, "IFOREST_STATS_PRETRAINED_PATH", None))
        prev_rows = None
        if isinstance(stats, dict):
            prev_rows = stats.get("baseline_rows")
            if prev_rows is None:
                prev_rows = stats.get("rows")
        enough_new_rows = False
        if prev_rows is not None and policy.anomaly_retrain_rows > 0:
            try:
                enough_new_rows = (current_rows - int(prev_rows)) >= policy.anomaly_retrain_rows
            except Exception:
                enough_new_rows = False

        if too_soon and not enough_new_rows:
            return False

    df = load_baseline_candidates_df(mode=mode, limit=None)
    if df.empty:
        return False

    pre = preprocess_data(df, purpose="inference", save_csv=False)
    X = pre.get("X")
    if not isinstance(X, pd.DataFrame) or X.empty:
        return False

    X = _align_features(X, feature_schema_path)
    det = AnomalyDetector(model_path=model_path)
    det.fit(X)
    stats_path = getattr(cfg, "IFOREST_STATS_PATH", None)
    if stats_path:
        policy_stats = AnomalyPolicy()
        stats = compute_anomaly_stats(
            X,
            model=det.model,
            quantiles=policy_stats.baseline_quantiles,
            baseline_rows=current_rows,
        )
        save_anomaly_stats(stats, stats_path)
    logger.info("IsolationForest auto-trained on baseline from DB: %s", model_path)
    return True
