from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path
from typing import List, Optional

import pandas as pd

# --- Bootstrap imports: чтобы работало при запуске `python scripts/...` на Windows ---
PROJECT_ROOT = Path(__file__).resolve().parents[1]  # .../previsor
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
# -------------------------------------------------------------------------------

from modules.preprocessor import preprocess_data
from modules.analyzer import Analyzer

logger = logging.getLogger(__name__)
if not logging.getLogger().handlers:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


def _models_runtime_dir(root: Path) -> Path:
    """Возвращает директорию для runtime-артефактов модели.

    Args:
        root: Корень проекта.

    Returns:
        Путь к models/runtime, директория создаётся при необходимости.
    """
    d = root / "models" / "runtime"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _default_inputs(root: Path) -> List[Path]:
    """Выбирает дефолтные processed-датасеты для обучения классификатора.

    Предпочитаем:
      data/runtime/datasets/*_processed.csv

    Args:
        root: Корень проекта.

    Returns:
        Список существующих файлов.
    """
    cand = [
        root / "data" / "runtime" / "datasets" / "cicids2017_processed.csv",
        root / "data" / "runtime" / "datasets" / "mscad_processed.csv",
        root / "data" / "runtime" / "datasets" / "csic2010_processed.csv",
    ]
    return [p for p in cand if p.exists()]


def _load_and_concat(paths: List[Path]) -> pd.DataFrame:
    """Загружает CSV и объединяет их в единый DataFrame.

    Args:
        paths: Пути к CSV.

    Returns:
        Объединённый DataFrame.

    Raises:
        RuntimeError: если ни один CSV не удалось загрузить.
    """
    frames: List[pd.DataFrame] = []
    for p in paths:
        logger.info("Загрузка: %s", p)
        frames.append(pd.read_csv(p, low_memory=False))

    if not frames:
        raise RuntimeError("Не удалось загрузить ни одного датасета для обучения.")

    df = pd.concat(frames, ignore_index=True)
    logger.info("Объединено строк: %s", len(df))
    return df


def main(argv: Optional[List[str]] = None) -> None:
    """CLI обучения классификатора (RF/XGB) на одном или нескольких датасетах.

    Примеры:
        python scripts/train_classifier.py --model rf
        python scripts/train_classifier.py --model xgb
        python scripts/train_classifier.py --model rf --inputs data/runtime/datasets/cicids2017_processed.csv
    """
    parser = argparse.ArgumentParser(description="PreVisor: обучение классификатора (RF/XGB)")
    parser.add_argument("--model", choices=["rf", "xgb"], default="rf", help="Тип модели (по умолчанию rf).")
    parser.add_argument(
        "--inputs",
        nargs="*",
        default=None,
        help="Пути к CSV (можно несколько). Если не указано — берём data/runtime/datasets/*_processed.csv.",
    )
    args = parser.parse_args(argv)

    root = PROJECT_ROOT
    models_dir = _models_runtime_dir(root)

    # 1) Данные
    if args.inputs:
        paths = [Path(p).expanduser().resolve() for p in args.inputs]
    else:
        paths = _default_inputs(root)

    if not paths:
        raise RuntimeError(
            "Не найдено ни одного processed датасета. "
            "Сначала сформируй data/runtime/datasets/*_processed.csv через utils/process_data.py "
            "или передай --inputs явно."
        )

    df = _load_and_concat(paths)

    # 2) Предобработка (train)
    result = preprocess_data(df, purpose="train", save_csv=False)

    X_train = result.get("X_train")
    X_test = result.get("X_test")
    y_train = result.get("y_train")
    y_test = result.get("y_test")

    if X_train is None or y_train is None:
        raise RuntimeError(
            "Предобработка не вернула X_train/y_train. "
            "Проверь, что в данных есть колонка метки (Attack Type / classification / Label)."
        )

    # 3) Обучение
    analyzer = Analyzer(model_type=args.model)

    if args.model == "rf":
        model_path = models_dir / "previsor_model.pkl"
        report_path = models_dir / "last_report.txt"
    else:
        model_path = models_dir / "previsor_model_xgb.pkl"
        report_path = models_dir / "last_report_xgb.txt"

    # Если Analyzer поддерживает атрибуты путей — принудительно направим их в models/runtime
    if hasattr(analyzer, "model_path"):
        analyzer.model_path = str(model_path)
    if hasattr(analyzer, "report_path"):
        analyzer.report_path = str(report_path)

    analyzer.train_model(X_train, y_train)
    metrics = analyzer.evaluate(X_test, y_test) if X_test is not None and y_test is not None else {"f1_score": None}

    f1 = metrics.get("f1_score")
    if f1 is None:
        print(f"{args.model.upper()} обучен (без test-оценки)")
    else:
        print(f"{args.model.upper()} F1-score: {float(f1):.4f}")


if __name__ == "__main__":
    main()
