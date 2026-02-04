from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass
from typing import Optional

import joblib
import pandas as pd

import config as cfg
from modules.anomaly_detector import AnomalyDetector
from modules.preprocessor import preprocess_data

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


def _count_csv_rows(path: str) -> int:
    """Считает количество строк (без заголовка) в CSV.

    Args:
        path: Путь к CSV.

    Returns:
        Количество строк.
    """
    if not os.path.exists(path):
        return 0
    try:
        with open(path, "rb") as fh:
            return max(0, sum(1 for _ in fh) - 1)
    except Exception:
        return 0


def _align_features(X: pd.DataFrame, feature_schema_path: str) -> pd.DataFrame:
    """Выравнивает матрицу признаков по схеме обучения.

    Args:
        X: Матрица признаков.
        feature_schema_path: Путь к feature schema.

    Returns:
        Матрица признаков в согласованном порядке.
    """
    if not feature_schema_path or not os.path.exists(feature_schema_path):
        logger.warning("feature schema не найдена (%s) - обучение baseline будет без align", feature_schema_path)
        return X

    feature_cols = joblib.load(feature_schema_path)
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


def count_baseline_rows(path: str) -> int:
    """Возвращает количество строк baseline CSV.

    Args:
        path: Путь к baseline CSV.

    Returns:
        Количество строк.
    """
    return _count_csv_rows(path)


def append_baseline(df: pd.DataFrame, *, path: Optional[str] = None) -> int:
    """Добавляет строки в baseline CSV.

    Args:
        df: DataFrame с трафиком.
        path: Путь к baseline CSV.

    Returns:
        Число добавленных строк.
    """
    if df is None or df.empty:
        return 0

    path = path or getattr(cfg, "BASELINE_TRAFFIC_CSV", os.path.join(cfg.DATA_RUNTIME_DIR, "baseline_traffic.csv"))
    os.makedirs(os.path.dirname(path), exist_ok=True)

    file_exists = os.path.exists(path) and os.path.getsize(path) > 0
    df.to_csv(path, mode="a", header=not file_exists, index=False)
    return len(df)


def maybe_train_anomaly_model(*, baseline_csv: str, feature_schema_path: str) -> bool:
    """Переобучает IsolationForest при выполнении условий.

    Args:
        baseline_csv: Путь к baseline CSV.
        feature_schema_path: Путь к feature schema.

    Returns:
        True, если модель была переобучена.
    """
    policy = BaselinePolicy()
    if not policy.anomaly_auto_train:
        return False

    if not os.path.exists(baseline_csv):
        return False

    if _count_csv_rows(baseline_csv) < policy.min_rows:
        return False

    model_path = getattr(cfg, "IFOREST_MODEL_PATH", os.path.join(cfg.MODELS_RUNTIME_DIR, "isolation_forest.pkl"))
    if os.path.exists(model_path):
        mtime = os.path.getmtime(model_path)
        if (time.time() - mtime) < (policy.anomaly_retrain_hours * 3600):
            return False

    df = pd.read_csv(baseline_csv)
    if df.empty:
        return False

    pre = preprocess_data(df, purpose="inference", save_csv=False)
    X = pre.get("X")
    if not isinstance(X, pd.DataFrame) or X.empty:
        return False

    X = _align_features(X, feature_schema_path)
    det = AnomalyDetector(model_path=model_path)
    det.fit(X)
    logger.info("IsolationForest auto-trained on baseline: %s", model_path)
    return True
