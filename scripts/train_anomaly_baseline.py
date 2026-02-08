from __future__ import annotations

import argparse
import logging
import os
from typing import List

import joblib
import pandas as pd
from pathlib import Path
import sys
# --- Bootstrap imports: чтобы работало при запуске `python scripts/...` на Windows ---
PROJECT_ROOT = Path(__file__).resolve().parents[1]  # .../previsor
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
# -------------------------------------------------------------------------------

import config as cfg
from modules.anomaly_detector import (
    AnomalyDetector,
    AnomalyPolicy,
    compute_anomaly_stats,
    save_anomaly_stats,
)
from modules.preprocessor import preprocess_data

logger = logging.getLogger(__name__)
if not logging.getLogger().handlers:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


def _align_features(X: pd.DataFrame, feature_schema_path: str) -> pd.DataFrame:
    """Выравнивает X по схеме признаков обучения (feature schema).

    Это нужно, чтобы IsolationForest обучался на том же наборе/порядке признаков,
    который использует пайплайн при инференсе.

    Args:
        X: Матрица признаков.
        feature_schema_path: Путь к сохранённому списку колонок.

    Returns:
        Выравненный DataFrame.
    """
    if not feature_schema_path or not os.path.exists(feature_schema_path):
        logger.warning("feature schema не найдена (%s) — обучение baseline будет без align", feature_schema_path)
        return X

    feature_cols = joblib.load(feature_schema_path)
    if not isinstance(feature_cols, (list, tuple)) or not all(isinstance(c, str) for c in feature_cols):
        logger.warning("Некорректный формат feature schema (%s) — пропускаю align", type(feature_cols))
        return X

    X = X.copy()
    for col in feature_cols:
        if col not in X.columns:
            X[col] = 0.0

    # удаляем лишние и фиксируем порядок
    return X[list(feature_cols)]


def _parse_args() -> argparse.Namespace:
    """Парсит аргументы CLI для обучения baseline.

    Returns:
        argparse.Namespace.
    """
    parser = argparse.ArgumentParser(description="Train IsolationForest baseline for PreVisor")
    parser.add_argument(
        "--input",
        default=getattr(cfg, "BASELINE_TRAFFIC_CSV", os.path.join(cfg.DATA_RUNTIME_DIR, "baseline_traffic.csv")),
        help="Path to baseline_traffic.csv (raw collected traffic)",
    )
    return parser.parse_args()


def main() -> int:
    """Обучает IsolationForest на baseline CSV.

    Returns:
        Код завершения.
    """
    args = _parse_args()
    input_path = str(args.input)

    if not os.path.exists(input_path):
        logger.error("Baseline CSV не найден: %s", input_path)
        return 2

    df = pd.read_csv(input_path)
    if df.empty:
        logger.error("Baseline CSV пустой: %s", input_path)
        return 3

    pre = preprocess_data(df, purpose="inference", save_csv=False)
    X = pre.get("X")
    if not isinstance(X, pd.DataFrame) or X.empty:
        logger.error("Не удалось получить матрицу признаков X из baseline (проверьте формат входных данных)")
        return 4

    X = _align_features(X, getattr(cfg, "FEATURE_SCHEMA_PATH", ""))

    det = AnomalyDetector(model_path=getattr(cfg, "IFOREST_MODEL_PATH", os.path.join(cfg.MODELS_RUNTIME_DIR, "isolation_forest.pkl")))
    det.fit(X)
    stats_path = getattr(cfg, "IFOREST_STATS_PATH", os.path.join(cfg.MODELS_RUNTIME_DIR, "isolation_forest_stats.json"))
    policy_stats = AnomalyPolicy()
    stats = compute_anomaly_stats(X, model=det.model, quantiles=policy_stats.baseline_quantiles)
    save_anomaly_stats(stats, stats_path)

    logger.info("Baseline IsolationForest сохранён: %s", det.model_path)
    logger.info("Для включения детектора в пайплайне установите ANOMALY_ENABLED=1")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
