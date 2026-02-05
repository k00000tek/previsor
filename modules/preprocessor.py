from __future__ import annotations

import logging
import os
import warnings
from dataclasses import dataclass
from typing import Any, Dict, Optional, Union, Literal, List

import joblib
import pandas as pd
from pandas.errors import PerformanceWarning
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import MinMaxScaler, StandardScaler, LabelEncoder, OneHotEncoder

import config as cfg
from config import DATA_RUNTIME_DIR, MODELS_RUNTIME_DIR

Purpose = Literal["train", "inference"]

logger = logging.getLogger(__name__)
if not logging.getLogger().handlers:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

warnings.filterwarnings("ignore", category=PerformanceWarning)


@dataclass
class PreprocessorArtifacts:
    """Артефакты предобработки, общие для train и inference.

    Attributes:
        scaler: Объект масштабирования (MinMaxScaler/StandardScaler).
        scaler_columns: Список колонок, на которых обучался scaler (порядок важен).
        http_ohe: OneHotEncoder для http_method.
        label_encoder: LabelEncoder для меток атак.
    """

    scaler: Optional[Union[MinMaxScaler, StandardScaler]] = None
    scaler_columns: Optional[List[str]] = None
    http_ohe: Optional[OneHotEncoder] = None
    label_encoder: Optional[LabelEncoder] = None


def _ensure_dir(path: str) -> None:
    """Создаёт директорию, если её нет."""
    os.makedirs(path, exist_ok=True)


def _artifact_paths(artifacts_dir: str) -> Dict[str, str]:
    """Возвращает пути ко всем артефактам предобработки.

    Args:
        artifacts_dir: Директория, где хранятся артефакты (обычно models/runtime).

    Returns:
        Словарь путей к файлам артефактов.
    """
    return {
        "scaler": os.path.join(artifacts_dir, "scaler.pkl"),
        "scaler_cols": os.path.join(artifacts_dir, "scaler_columns.pkl"),
        "http_ohe": os.path.join(artifacts_dir, "http_ohe.pkl"),
        "label_encoder": os.path.join(artifacts_dir, "label_encoder.pkl"),
    }


def _load_artifact(runtime_path: str, fallback_path: Optional[str] = None) -> Optional[Any]:
    """Загружает артефакт из runtime или fallback (pretrained), если доступен."""
    if runtime_path and os.path.exists(runtime_path):
        return joblib.load(runtime_path)
    if fallback_path and os.path.exists(fallback_path):
        return joblib.load(fallback_path)
    return None


def _detect_label_column(df: pd.DataFrame) -> Optional[str]:
    """Пытается найти колонку метки атак в разных названиях.

    Args:
        df: DataFrame с данными.

    Returns:
        Имя колонки метки или None.
    """
    for col in ["label", "Label", "Attack Type", "classification"]:
        if col in df.columns:
            return col
    return None


def _make_ohe() -> OneHotEncoder:
    """Создаёт OneHotEncoder, совместимый с разными версиями sklearn."""
    try:
        return OneHotEncoder(sparse_output=False, handle_unknown="ignore")
    except TypeError:  # старые sklearn
        return OneHotEncoder(sparse=False, handle_unknown="ignore")


def preprocess_data(
    input_data: Union[str, pd.DataFrame],
    *,
    purpose: Purpose = "inference",
    output_dir: str = DATA_RUNTIME_DIR,
    artifacts_dir: str = MODELS_RUNTIME_DIR,
    scaler_type: str = "minmax",
    test_size: float = 0.2,
    save_csv: bool = True,
    random_state: int = 42,
) -> Dict[str, Any]:
    """Предобработка данных для PreVisor (train/inference).

    Ключевая идея:
    - В `train` мы делаем fit преобразований и сохраняем артефакты (scaler/ohe/label_encoder).
    - В `inference` мы ТОЛЬКО применяем сохранённые артефакты и НИЧЕГО не дообучаем.

    Это критично для стабильности:
    - исключаем переобучение scaler на каждом прогоне пайплайна,
    - исключаем перезапись label_encoder, чтобы Analyzer корректно декодировал классы.

    Args:
        input_data: Путь к CSV или DataFrame с сырыми данными.
        purpose: "train" или "inference".
        output_dir: Куда сохранять обработанный CSV (data/runtime).
        artifacts_dir: Где хранятся артефакты предобработки (models/runtime).
        scaler_type: "minmax" или "standard".
        test_size: Доля тестовой выборки (только для train при наличии y).
        save_csv: Сохранять ли processed CSV в output_dir.
        random_state: Seed для воспроизводимости split.

    Returns:
        dict со следующими ключами:
            - processed_df: DataFrame после предобработки (включая source_ip/timestamp если были).
            - X: Матрица признаков (числовые столбцы без label_encoded).
            - y: Вектор меток (Series) или None.
            - X_train, X_test, y_train, y_test: только для purpose="train" и если y доступен.
    """
    _ensure_dir(output_dir)
    _ensure_dir(artifacts_dir)
    paths = _artifact_paths(artifacts_dir)
    pretrained_paths = _artifact_paths(cfg.MODELS_PRETRAINED_DIR)

    # --- 0) Загрузка данных ---
    if isinstance(input_data, pd.DataFrame):
        df = input_data.copy()
    else:
        input_file = input_data
        if not os.path.exists(input_file):
            raise FileNotFoundError(f"Файл {input_file} не найден")
        df = pd.read_csv(input_file)
        logger.info("Загружен файл %s: %s строк", input_file, len(df))

    # --- 1) Унификация названий колонок (минимально) ---
    rename_map = {
        "Flow Duration": "flow_duration",
        "Flow_Duration": "flow_duration",
    }
    df = df.rename(columns=rename_map)

    # --- 2) Очистка ---
    preferred_keys = ["source_ip", "dest_port", "packet_count", "flow_duration"]
    key_cols = [c for c in preferred_keys if c in df.columns]
    if key_cols:
        if purpose == "train":
            df = df.dropna(subset=key_cols)
        else:
            df[key_cols] = df[key_cols].fillna(0)

    df = df.drop_duplicates()

    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

    if "source_ip" in df.columns:
        df["source_ip"] = df["source_ip"].astype(str)

    numeric_candidates = [
        "protocol",
        "src_port",
        "dest_port",
        "packet_len",
        "ttl",
        "tcp_flags",
        "packet_count",
        "flow_duration",
    ]
    for col in numeric_candidates:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce")
            if purpose != "train":
                df[col] = df[col].fillna(0)

    logger.info("После очистки: %s строк", len(df))
    if df.empty:
        logger.warning("После очистки нет данных для обработки (0 строк)")
        X_empty = df.select_dtypes(include=["number"]).copy()
        return {
            "processed_df": df,
            "X": X_empty,
            "y": None,
            "X_train": None,
            "X_test": None,
            "y_train": None,
            "y_test": None,
        }

    # --- 3) Загрузка артефактов (ТОЛЬКО load в inference) ---
    artifacts = PreprocessorArtifacts()

    artifacts.scaler = _load_artifact(paths["scaler"], pretrained_paths.get("scaler"))
    artifacts.scaler_columns = _load_artifact(paths["scaler_cols"], pretrained_paths.get("scaler_cols"))
    artifacts.http_ohe = _load_artifact(paths["http_ohe"], pretrained_paths.get("http_ohe"))
    artifacts.label_encoder = _load_artifact(paths["label_encoder"], pretrained_paths.get("label_encoder"))

    # --- 4) Feature engineering (безопасно, если колонок нет) ---
    if "flow_duration" in df.columns and "packet_count" in df.columns:
        df["error_rate"] = df["packet_count"] / df["flow_duration"].clip(lower=1)
        logger.info("Добавлен признак error_rate")

    # --- 5) OneHot для http_method ---
    if "http_method" in df.columns:
        series = df["http_method"].fillna("unknown").astype(str)

        if purpose == "train":
            artifacts.http_ohe = _make_ohe()
            http_arr = artifacts.http_ohe.fit_transform(series.to_frame())
            joblib.dump(artifacts.http_ohe, paths["http_ohe"])
            logger.info("Сохранён http_ohe: %s", paths["http_ohe"])
        else:
            if artifacts.http_ohe is None:
                logger.warning("http_ohe отсутствует — OneHotEncoding пропущен (inference)")
                http_arr = None
            else:
                http_arr = artifacts.http_ohe.transform(series.to_frame())

        if http_arr is not None:
            http_cols = artifacts.http_ohe.get_feature_names_out(["http_method"])
            http_df = pd.DataFrame(http_arr, columns=http_cols, index=df.index)
            df = pd.concat([df.drop(columns=["http_method"]), http_df], axis=1)
            logger.info("OneHotEncoding для http_method завершён (%s колонок)", len(http_cols))

    else:
        # Если http_method нет, но encoder был на обучении — добавим нулевые колонки (стабильность)
        if artifacts.http_ohe is not None:
            http_cols = artifacts.http_ohe.get_feature_names_out(["http_method"])
            for c in http_cols:
                if c not in df.columns:
                    df[c] = 0.0
            logger.info("http_method отсутствует — добавлены нулевые OHE-колонки (%s)", len(http_cols))

    # --- 6) Label encoding (только если метка есть) ---
    label_col = _detect_label_column(df)
    y: Optional[pd.Series] = None

    if label_col:
        labels = df[label_col].fillna("unknown").astype(str)

        if purpose == "train":
            artifacts.label_encoder = LabelEncoder()
            y_encoded = artifacts.label_encoder.fit_transform(labels)
            df["label_encoded"] = y_encoded
            joblib.dump(artifacts.label_encoder, paths["label_encoder"])
            logger.info("Сохранён label_encoder: %s", paths["label_encoder"])
        else:
            # В inference НИКОГДА не fit. Если encoder нет — просто не кодируем.
            if artifacts.label_encoder is None:
                logger.warning("label_encoder отсутствует — label encoding пропущен (inference)")
            else:
                try:
                    df["label_encoded"] = artifacts.label_encoder.transform(labels)
                except ValueError:
                    # неизвестные метки → -1
                    mapping = {cls: i for i, cls in enumerate(artifacts.label_encoder.classes_)}
                    encoded = labels.map(mapping).fillna(-1).astype(int)
                    unknown_cnt = int((encoded == -1).sum())
                    logger.warning("Найдены неизвестные метки: %s шт. (закодированы как -1)", unknown_cnt)
                    df["label_encoded"] = encoded

        # Оригинальную колонку метки удаляем, чтобы дальше она не мешала моделям
        df = df.drop(columns=[label_col], errors="ignore")
        if "label_encoded" in df.columns:
            y = df["label_encoded"]
            logger.info("LabelEncoding завершён для '%s'", label_col)
    else:
        logger.info("Колонка с меткой не найдена — режим без y")

    # --- 7) Удаление нечисловых (кроме source_ip/timestamp) ---
    non_numeric_cols = df.select_dtypes(exclude=["number"]).columns.tolist()
    for keep in ["source_ip", "timestamp"]:
        if keep in non_numeric_cols:
            non_numeric_cols.remove(keep)

    if non_numeric_cols:
        df = df.drop(columns=non_numeric_cols, errors="ignore")

    logger.info("Удалены нечисловые колонки: %s", non_numeric_cols)

    # --- 8) Масштабирование числовых ---
    numeric_cols = df.select_dtypes(include=["number"]).columns.tolist()
    if "label_encoded" in numeric_cols:
        numeric_cols.remove("label_encoded")

    if purpose == "train":
        if not numeric_cols:
            logger.warning("Нет числовых колонок для масштабирования (train)")
        else:
            scaler_obj: Union[MinMaxScaler, StandardScaler]
            if scaler_type == "standard":
                scaler_obj = StandardScaler()
            else:
                scaler_obj = MinMaxScaler()

            artifacts.scaler = scaler_obj
            artifacts.scaler_columns = list(numeric_cols)

            df[artifacts.scaler_columns] = artifacts.scaler.fit_transform(df[artifacts.scaler_columns])

            joblib.dump(artifacts.scaler, paths["scaler"])
            joblib.dump(artifacts.scaler_columns, paths["scaler_cols"])
            logger.info("Сохранён scaler: %s", paths["scaler"])
            logger.info("Сохранены scaler_columns (%s): %s", len(artifacts.scaler_columns), paths["scaler_cols"])
            logger.info("Масштабирование (%s) выполнено для %s колонок", scaler_type, len(artifacts.scaler_columns))
    else:
        # inference: строго transform по сохранённым колонкам
        if artifacts.scaler is None or artifacts.scaler_columns is None:
            logger.warning("Артефакты scaler отсутствуют — масштабирование пропущено (inference)")
        else:
            # добавим отсутствующие колонки из обучения нулями
            for col in artifacts.scaler_columns:
                if col not in df.columns:
                    df[col] = 0.0

            # уберём лишние колонки (которые scaler не видел), чтобы transform был корректным
            df[artifacts.scaler_columns] = artifacts.scaler.transform(df[artifacts.scaler_columns])
            logger.info("Масштабирование (inference) выполнено для %s колонок", len(artifacts.scaler_columns))

    # --- 9) Сохранение processed CSV ---
    if save_csv:
        if isinstance(input_data, pd.DataFrame):
            base_name = "inmemory_processed.csv"
        else:
            base_name = os.path.basename(str(input_data)).replace(".csv", "_processed.csv")

        output_path = os.path.join(output_dir, base_name)
        df.to_csv(output_path, index=False)
        logger.info("Обработанные данные сохранены в %s", output_path)

    # --- 10) Формирование X/y ---
    X = df.select_dtypes(include=["number"]).copy()
    if "label_encoded" in X.columns:
        X = X.drop(columns=["label_encoded"], errors="ignore")

    # split только в train и только если есть y
    X_train = X_test = y_train = y_test = None
    if purpose == "train" and y is not None and len(X) > 0:
        try:
            X_train, X_test, y_train, y_test = train_test_split(
                X,
                y,
                test_size=test_size,
                random_state=random_state,
                stratify=y if y.nunique() > 1 else None,
            )
            logger.info("Train/test split: %s / %s строк", len(X_train), len(X_test))
        except Exception as exc:
            logger.warning("Train/test split пропущен: %s", exc)

    return {
        "processed_df": df,
        "X": X,
        "y": y,
        "X_train": X_train,
        "X_test": X_test,
        "y_train": y_train,
        "y_test": y_test,
    }


if __name__ == "__main__":
    # Мини-тест (ручной запуск): попробуем inference на последнем собранном runtime CSV
    test_path = os.path.join(DATA_RUNTIME_DIR, "collected_traffic.csv")
    if os.path.exists(test_path):
        res = preprocess_data(test_path, purpose="inference")
        print(res["processed_df"].head())
    else:
        print(f"Файл не найден: {test_path}")
