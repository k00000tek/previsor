from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path
from typing import List, Optional

import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest

# --- Bootstrap imports: чтобы работало при запуске `python scripts/...` на Windows ---
PROJECT_ROOT = Path(__file__).resolve().parents[1]  # .../previsor
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
# -------------------------------------------------------------------------------

from modules.preprocessor import preprocess_data

logger = logging.getLogger(__name__)
if not logging.getLogger().handlers:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


def _models_runtime_dir(root: Path) -> Path:
    """Возвращает директорию для runtime-артефактов (анomaly baseline).

    Args:
        root: Корень проекта.

    Returns:
        Путь к models/runtime.
    """
    d = root / "models" / "runtime"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _default_input(root: Path) -> Path:
    """Дефолтный CSV для обучения baseline аномалий."""
    return root / "data" / "runtime" / "collected_traffic.csv"


def main(argv: Optional[List[str]] = None) -> None:
    """CLI обучения IsolationForest baseline.

    Примеры:
        python scripts/train_anomaly_baseline.py --input data/runtime/collected_traffic.csv
        python scripts/train_anomaly_baseline.py --input data/runtime/datasets/cicids2017_processed.csv
    """
    parser = argparse.ArgumentParser(description="PreVisor: обучение baseline аномалий (IsolationForest)")
    parser.add_argument("--input", default=None, help="Путь к CSV. По умолчанию data/runtime/collected_traffic.csv")
    parser.add_argument("--contamination", type=float, default=0.10, help="Доля аномалий (0..0.5).")
    parser.add_argument("--n_estimators", type=int, default=200, help="Количество деревьев.")
    args = parser.parse_args(argv)

    root = PROJECT_ROOT
    models_dir = _models_runtime_dir(root)

    input_path = Path(args.input).expanduser().resolve() if args.input else _default_input(root)
    if not input_path.exists():
        raise RuntimeError(
            f"Файл не найден: {input_path}\n"
            "Подсказка: для baseline можно временно использовать любой processed CSV из data/runtime/datasets/..."
        )

    df = pd.read_csv(input_path, low_memory=False)

    # Для baseline аномалий метка не нужна → inference-предобработка
    result = preprocess_data(df, purpose="inference", save_csv=False)

    X = result.get("X")
    if X is None:
        processed_df = result.get("processed_df")
        if processed_df is None:
            raise RuntimeError("Предобработка не вернула X/processed_df.")
        X = processed_df.select_dtypes(include=["number"]).copy()

    model = IsolationForest(
        n_estimators=int(args.n_estimators),
        contamination=float(args.contamination),
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X)

    out_path = models_dir / "isolation_forest.pkl"
    joblib.dump(model, out_path)
    logger.info("IsolationForest baseline сохранён: %s", out_path)
    print("IsolationForest baseline обучен и сохранён")


if __name__ == "__main__":
    main()
