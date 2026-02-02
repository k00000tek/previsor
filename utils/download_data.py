from __future__ import annotations

import argparse
import logging
import os
import subprocess
import zipfile
from dataclasses import dataclass
from typing import List, Optional, Tuple

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


def _tmp_kaggle_dir() -> str:
    """Путь к utils/tmp_kaggle."""
    return os.path.join(_project_root(), "utils", "tmp_kaggle")


@dataclass(frozen=True)
class DatasetConfig:
    """Конфигурация скачивания и выборки датасета."""
    kaggle_id: str
    target_rows: int
    label_col: Optional[str]
    hint_name: str


def download_file_with_kaggle(dataset_name: str, dest_dir: str) -> str:
    """Скачивает датасет Kaggle CLI в виде zip-архива.

    Требования:
    - установлен kaggle CLI;
    - настроен ~/.kaggle/kaggle.json.

    Args:
        dataset_name: Идентификатор Kaggle (например "user/dataset").
        dest_dir: Куда скачать архив.

    Returns:
        Путь к скачанному zip.
    """
    os.makedirs(dest_dir, exist_ok=True)

    zip_name = dataset_name.split("/")[-1] + ".zip"
    zip_path = os.path.join(dest_dir, zip_name)

    if os.path.exists(zip_path):
        logger.info("Архив уже существует: %s", zip_path)
        return zip_path

    cmd = ["kaggle", "datasets", "download", "-d", dataset_name, "-p", dest_dir]
    logger.info("Запуск: %s", " ".join(cmd))
    res = subprocess.run(cmd, capture_output=True, text=True)

    if res.returncode != 0:
        logger.error("Ошибка скачивания: %s", res.stderr)
        raise RuntimeError(f"Не удалось скачать {dataset_name}")

    logger.info("Скачано: %s", zip_path)
    return zip_path


def extract_zip(zip_path: str, extract_to: str) -> None:
    """Распаковывает zip-архив.

    Args:
        zip_path: Путь к архиву.
        extract_to: Папка распаковки.
    """
    os.makedirs(extract_to, exist_ok=True)
    logger.info("Распаковка %s → %s", zip_path, extract_to)
    with zipfile.ZipFile(zip_path, "r") as z:
        z.extractall(extract_to)


def find_csv_files(root_dir: str) -> List[str]:
    """Рекурсивно ищет все CSV файлы в папке.

    Args:
        root_dir: Корневая папка поиска.

    Returns:
        Список путей к CSV.
    """
    csv_paths: List[str] = []
    for root, _, files in os.walk(root_dir):
        for f in files:
            if f.lower().endswith(".csv"):
                csv_paths.append(os.path.join(root, f))
    return csv_paths


def choose_csv(csv_paths: List[str]) -> str:
    """Выбирает “лучший” CSV (по умолчанию — самый большой по размеру).

    Args:
        csv_paths: Список CSV.

    Returns:
        Путь к выбранному CSV.

    Raises:
        FileNotFoundError: если список пуст.
    """
    if not csv_paths:
        raise FileNotFoundError("CSV файлы не найдены")
    csv_paths.sort(key=lambda p: os.path.getsize(p), reverse=True)
    return csv_paths[0]


def stratified_sample(df: pd.DataFrame, n: int, label_col: Optional[str], random_state: int = 42) -> pd.DataFrame:
    """Делает подвыборку n строк (стратифицированно по метке, если возможно).

    Args:
        df: Исходный DataFrame.
        n: Размер выборки.
        label_col: Имя колонки метки (если есть).
        random_state: Seed.

    Returns:
        Подвыборка DataFrame.
    """
    if n <= 0 or len(df) <= n:
        return df.copy()

    if label_col and label_col in df.columns:
        # Стратификация: по чуть-чуть из каждого класса
        classes = df[label_col].dropna().unique().tolist()
        if not classes:
            return df.sample(n, random_state=random_state)

        per_class = max(1, n // len(classes))
        parts = []

        for c in classes:
            df_c = df[df[label_col] == c]
            if len(df_c) <= per_class:
                parts.append(df_c)
            else:
                parts.append(df_c.sample(per_class, random_state=random_state))

        out = pd.concat(parts, ignore_index=True)

        # добираем до n случайными строками
        if len(out) < n:
            remaining = df.drop(out.index, errors="ignore")
            need = n - len(out)
            if len(remaining) > 0:
                extra = remaining.sample(min(need, len(remaining)), random_state=random_state)
                out = pd.concat([out, extra], ignore_index=True)

        return out

    return df.sample(n, random_state=random_state)


def process_dataset(cfg: DatasetConfig, *, cleanup_extracted: bool = True) -> str:
    """Скачивает датасет, извлекает, выбирает CSV и сохраняет sample в data/samples.

    Args:
        cfg: DatasetConfig.
        cleanup_extracted: Удалять ли извлечённые CSV (оставляем только zip + sample).

    Returns:
        Путь к сохранённому sample CSV.
    """
    tmp_dir = _tmp_kaggle_dir()
    samples_dir = _samples_dir()
    os.makedirs(samples_dir, exist_ok=True)

    zip_path = download_file_with_kaggle(cfg.kaggle_id, dest_dir=tmp_dir)
    extract_zip(zip_path, tmp_dir)

    csv_paths = find_csv_files(tmp_dir)
    csv_path = choose_csv(csv_paths)
    logger.info("Выбран CSV: %s", csv_path)

    df = pd.read_csv(csv_path, low_memory=False)
    df_sample = stratified_sample(df, cfg.target_rows, cfg.label_col)

    out_path = os.path.join(samples_dir, f"{cfg.hint_name}_sample.csv")
    df_sample.to_csv(out_path, index=False)
    logger.info("Сохранено: %s (строк=%s)", out_path, len(df_sample))

    if cleanup_extracted:
        for p in csv_paths:
            try:
                os.remove(p)
            except Exception:
                pass

    return out_path


def main() -> None:
    """CLI-точка входа."""
    parser = argparse.ArgumentParser(description="Скачивание датасетов Kaggle и формирование data/samples/*_sample.csv")
    parser.add_argument("--all", action="store_true", help="Скачать и подготовить все датасеты (по конфигу внутри файла)")
    args = parser.parse_args()

    configs = [
        DatasetConfig("ericanacletoribeiro/cicids2017-cleaned-and-preprocessed", 12000, "Attack Type", "cicids2017"),
        DatasetConfig("ispangler/csic-2010-web-application-attacks", 5000, "classification", "csic2010"),
        DatasetConfig("drjamailalsawwa/mscad", 10000, "Label", "mscad"),
    ]

    if args.all:
        for c in configs:
            try:
                process_dataset(c)
            except Exception as exc:
                logger.error("Ошибка обработки %s: %s", c.kaggle_id, exc)
    else:
        logger.info("Ничего не сделано. Запусти с --all")


if __name__ == "__main__":
    main()
