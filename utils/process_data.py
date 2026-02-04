from __future__ import annotations

import logging
import os
from datetime import datetime
from typing import Optional

import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)
if not logging.getLogger().handlers:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


def _project_root() -> str:
    """Возвращает абсолютный путь к корню проекта (папка previsor)."""
    return os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))


def _samples_dir() -> str:
    """Путь к data/samples."""
    return os.path.join(_project_root(), "data", "samples")


def _datasets_dir() -> str:
    """Путь к data/runtime/datasets."""
    return os.path.join(_project_root(), "data", "runtime", "datasets")


def _ensure_dir(path: str) -> None:
    """Создаёт директорию, если её нет."""
    os.makedirs(path, exist_ok=True)


def _add_common_columns(df: pd.DataFrame, *, seed: int = 42) -> pd.DataFrame:
    """Добавляет общие колонки, необходимые для демонстрации.

    Добавляем (если отсутствуют):
    - timestamp: псевдо-временная шкала
    - source_ip: адреса из приватного диапазона
    - dest_port: случайный порт назначения

    Args:
        df: DataFrame.
        seed: Seed для воспроизводимости.

    Returns:
        Обновлённый DataFrame.
    """
    df = df.copy()
    rng = np.random.default_rng(seed)

    if "timestamp" not in df.columns:
        # ровная шкала по секундам
        start = pd.Timestamp("2025-10-12 00:00:00")
        df["timestamp"] = pd.date_range(start=start, periods=len(df), freq="s")

    if "source_ip" not in df.columns:
        # 192.168.1.1 .. 192.168.1.254 по кругу
        df["source_ip"] = [f"192.168.1.{(i % 254) + 1}" for i in range(len(df))]

    if "dest_port" not in df.columns:
        df["dest_port"] = rng.integers(1, 65535, size=len(df)).astype(int)

    return df


def process_mscad(
    input_path: Optional[str] = None,
    output_path: Optional[str] = None,
) -> pd.DataFrame:
    """Обрабатывает MSCAD sample → processed.

    Особенности:
    - в исходнике часто есть "Flow Duration" и "Label";
    - добавляем общие поля для демонстрации (timestamp/source_ip/dest_port).

    Args:
        input_path: путь к sample CSV (по умолчанию data/samples/mscad_sample.csv)
        output_path: путь к processed CSV (по умолчанию data/runtime/datasets/mscad_processed.csv)

    Returns:
        processed DataFrame.
    """
    input_path = input_path or os.path.join(_samples_dir(), "mscad_sample.csv")
    output_path = output_path or os.path.join(_datasets_dir(), "mscad_processed.csv")

    df = pd.read_csv(input_path, low_memory=False)

    # иногда встречаются странные кавычки в заголовках
    df.columns = [str(col).strip("'").strip() for col in df.columns]

    df = _add_common_columns(df)

    _ensure_dir(os.path.dirname(output_path))
    df.to_csv(output_path, index=False)

    if "Label" in df.columns:
        logger.info("MSCAD: баланс Label: %s", df["Label"].value_counts().to_dict())

    logger.info("MSCAD processed сохранён: %s (строк=%s)", output_path, len(df))
    return df


def process_cicids2017(
    input_path: Optional[str] = None,
    output_path: Optional[str] = None,
) -> pd.DataFrame:
    """Обрабатывает CICIDS2017 sample → processed.

    В CICIDS обычно есть "Flow Duration" (в мс). Если она есть — используем её для timestamp.

    Args:
        input_path: путь к sample CSV (по умолчанию data/samples/cicids2017_sample.csv)
        output_path: путь к processed CSV (по умолчанию data/runtime/datasets/cicids2017_processed.csv)

    Returns:
        processed DataFrame.
    """
    input_path = input_path or os.path.join(_samples_dir(), "cicids2017_sample.csv")
    output_path = output_path or os.path.join(_datasets_dir(), "cicids2017_processed.csv")

    df = pd.read_csv(input_path, low_memory=False)

    if "timestamp" not in df.columns:
        base = pd.Timestamp("2025-10-12 00:00:00")
        if "Flow Duration" in df.columns:
            # Flow Duration часто в мс (но встречаются большие значения — ок, это демо)
            df["timestamp"] = base + pd.to_timedelta(df["Flow Duration"], unit="ms", errors="coerce")
        else:
            df["timestamp"] = pd.date_range(start=base, periods=len(df), freq="s")

    df = _add_common_columns(df)

    _ensure_dir(os.path.dirname(output_path))
    df.to_csv(output_path, index=False)

    if "Attack Type" in df.columns:
        logger.info("CICIDS2017: баланс Attack Type: %s", df["Attack Type"].value_counts().to_dict())

    logger.info("CICIDS2017 processed сохранён: %s (строк=%s)", output_path, len(df))
    return df


def process_csic2010(
    input_path: Optional[str] = None,
    output_path: Optional[str] = None,
) -> pd.DataFrame:
    """Обрабатывает CSIC2010 sample → processed.

    Особенности:
    - в некоторых выгрузках есть мусорные колонки 'Unnamed: 0' и подобные;
    - для web-трафика dest_port логично фиксировать на 80 (если колонки нет).

    Args:
        input_path: путь к sample CSV (по умолчанию data/samples/csic2010_sample.csv)
        output_path: путь к processed CSV (по умолчанию data/runtime/datasets/csic2010_processed.csv)

    Returns:
        processed DataFrame.
    """
    input_path = input_path or os.path.join(_samples_dir(), "csic2010_sample.csv")
    output_path = output_path or os.path.join(_datasets_dir(), "csic2010_processed.csv")

    df = pd.read_csv(input_path, low_memory=False)

    # чистим “Unnamed:*”
    unnamed = [c for c in df.columns if str(c).lower().startswith("unnamed")]
    if unnamed:
        df = df.drop(columns=unnamed, errors="ignore")

    df = _add_common_columns(df)

    # dest_port для web: 80, если столбца ещё не было (или его добавили рандомом)
    if "dest_port" in df.columns:
        df["dest_port"] = 80

    _ensure_dir(os.path.dirname(output_path))
    df.to_csv(output_path, index=False)

    if "classification" in df.columns:
        logger.info("CSIC2010: баланс classification: %s", df["classification"].value_counts().to_dict())

    logger.info("CSIC2010 processed сохранён: %s (строк=%s)", output_path, len(df))
    return df


def main() -> None:
    """Запуск обработки всех датасетов."""
    _ensure_dir(_datasets_dir())
    try:
        process_mscad()
        process_cicids2017()
        process_csic2010()
    except Exception as exc:
        logger.error("Ошибка при обработке данных: %s", exc)


if __name__ == "__main__":
    main()
