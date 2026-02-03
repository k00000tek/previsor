"""
Конфигурация PreVisor.

Основные принципы:
1) Репозиторий хранит только исходники и небольшие sample-данные.
2) Артефакты выполнения (БД, модели, обработанные датасеты, временные CSV) живут в runtime-папках
   и не должны коммититься в Git.
3) Пользовательский режим по умолчанию — real (сбор реального трафика и периодический анализ).
   Другие режимы (demo/test/dataset) используются как внутренние.
"""

from __future__ import annotations

import os
from typing import Literal


def _env_bool(name: str, default: bool) -> bool:
    """Читает булеву переменную окружения.

    Поддерживаемые значения: 1/0, true/false, yes/no, on/off (без учета регистра).

    Args:
        name: Имя переменной окружения.
        default: Значение по умолчанию, если переменная не задана.

    Returns:
        Булево значение.
    """
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "y", "on"}


# -----------------------------
# Базовые пути (соответствуют текущей структуре репозитория)
# -----------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DATA_ROOT_DIR = os.getenv("PREVISOR_DATA_ROOT_DIR", os.path.join(BASE_DIR, "data"))
SAMPLES_DIR = os.getenv("PREVISOR_SAMPLES_DIR", os.path.join(DATA_ROOT_DIR, "samples"))

DATA_RUNTIME_DIR = os.getenv("PREVISOR_DATA_RUNTIME_DIR", os.path.join(DATA_ROOT_DIR, "runtime"))
DATASETS_DIR = os.getenv("PREVISOR_DATASETS_DIR", os.path.join(DATA_RUNTIME_DIR, "datasets"))

MODELS_ROOT_DIR = os.getenv("PREVISOR_MODELS_ROOT_DIR", os.path.join(BASE_DIR, "models"))
MODELS_RUNTIME_DIR = os.getenv("PREVISOR_MODELS_RUNTIME_DIR", os.path.join(MODELS_ROOT_DIR, "runtime"))

DB_ROOT_DIR = os.getenv("PREVISOR_DB_ROOT_DIR", os.path.join(BASE_DIR, "db"))
DB_RUNTIME_DIR = os.getenv("PREVISOR_DB_RUNTIME_DIR", os.path.join(DB_ROOT_DIR, "runtime"))
DB_PATH = os.getenv("PREVISOR_DB_PATH", os.path.join(DB_RUNTIME_DIR, "previsor.db"))

for _p in (DATA_ROOT_DIR, SAMPLES_DIR, DATA_RUNTIME_DIR, DATASETS_DIR, MODELS_ROOT_DIR, MODELS_RUNTIME_DIR, DB_ROOT_DIR, DB_RUNTIME_DIR):
    os.makedirs(_p, exist_ok=True)

# -----------------------------
# Режимы работы
# -----------------------------
# Пользовательский режим: real (по умолчанию)
# Внутренние режимы: demo/test/dataset (для наших тестов и экспериментов)
MODE: Literal["real", "demo", "test", "dataset"] = os.getenv("PREVISOR_MODE", "real")  # по умолчанию real

# demo-источник (для внутренних прогонов)
DEMO_SOURCE: Literal["mixed", "cicids2017", "csic2010", "mscad", "simulated"] = os.getenv(
    "PREVISOR_DEMO_SOURCE",
    "mixed",
)
DEMO_ROWS = int(os.getenv("PREVISOR_DEMO_ROWS", "1200"))
DEMO_SEED = os.getenv("PREVISOR_DEMO_SEED")  # если задано, демо станет воспроизводимым

# dataset-источник (для внутренних прогонов по подготовленным датасетам)
DATASET_NAME = os.getenv("PREVISOR_DATASET_NAME", "cicids2017_processed.csv")  # файл в DATASETS_DIR

# -----------------------------
# Реальный сбор трафика (MODE="real")
# -----------------------------

NETWORK_INTERFACE = os.getenv("PREVISOR_NET_IFACE", "Ethernet 4")
PACKET_COUNT_PER_COLLECTION = int(os.getenv("PREVISOR_PACKET_COUNT", "200"))
PACKET_SNIFF_TIMEOUT_SEC = int(os.getenv("PREVISOR_PACKET_TIMEOUT", "30"))
BPF_FILTER = os.getenv("PREVISOR_BPF_FILTER", "")  # например: "tcp or udp"

# -----------------------------
# Пути к runtime CSV
# -----------------------------

# Сырые данные (обычная коллекция)
COLLECTED_TRAFFIC_CSV = os.getenv(
    "PREVISOR_COLLECTED_TRAFFIC_CSV",
    os.path.join(DATA_RUNTIME_DIR, "collected_traffic.csv"),
)

# Baseline-накопление для обучения детектора аномалий
BASELINE_TRAFFIC_CSV = os.getenv(
    "PREVISOR_BASELINE_TRAFFIC_CSV",
    os.path.join(DATA_RUNTIME_DIR, "baseline_traffic.csv"),
)

# -----------------------------
# Пути к артефактам моделей (runtime)
# -----------------------------

# Классификаторы
RF_MODEL_PATH = os.getenv("PREVISOR_RF_MODEL_PATH", os.path.join(MODELS_RUNTIME_DIR, "previsor_model.pkl"))
XGB_MODEL_PATH = os.getenv("PREVISOR_XGB_MODEL_PATH", os.path.join(MODELS_RUNTIME_DIR, "previsor_model_xgb.pkl"))

# Общие артефакты признаков/препроцессинга
FEATURE_SCHEMA_PATH = os.getenv("PREVISOR_FEATURE_SCHEMA_PATH", os.path.join(MODELS_RUNTIME_DIR, "feature_columns.pkl"))
SCALER_PATH = os.getenv("PREVISOR_SCALER_PATH", os.path.join(MODELS_RUNTIME_DIR, "scaler.pkl"))
SCALER_COLUMNS_PATH = os.getenv("PREVISOR_SCALER_COLUMNS_PATH", os.path.join(MODELS_RUNTIME_DIR, "scaler_columns.pkl"))
LABEL_ENCODER_PATH = os.getenv("PREVISOR_LABEL_ENCODER_PATH", os.path.join(MODELS_RUNTIME_DIR, "label_encoder.pkl"))

# Аномалии
IFOREST_MODEL_PATH = os.getenv("PREVISOR_IFOREST_MODEL_PATH", os.path.join(MODELS_RUNTIME_DIR, "isolation_forest.pkl"))

# Включение детектора аномалий.
# Требование для рабочего сценария: anomaly_detector используется ТОЛЬКО если:
#   1) ANOMALY_ENABLED=1 (или PREVISOR_ANOMALY_ENABLED=1)
#   2) baseline-модель IsolationForest существует (см. IFOREST_MODEL_PATH)
ANOMALY_ENABLED = _env_bool("ANOMALY_ENABLED", False) or _env_bool("PREVISOR_ANOMALY_ENABLED", False)

# Отчёты (внутреннее)
LAST_REPORT_PATH = os.getenv("PREVISOR_LAST_REPORT_PATH", os.path.join(MODELS_RUNTIME_DIR, "last_report.txt"))
LAST_REPORT_XGB_PATH = os.getenv("PREVISOR_LAST_REPORT_XGB_PATH", os.path.join(MODELS_RUNTIME_DIR, "last_report_xgb.txt"))

# -----------------------------
# Параметры алертинга/уведомлений
# -----------------------------

MAX_TELEGRAM_ALERTS_PER_RUN = int(os.getenv("MAX_TELEGRAM_ALERTS_PER_RUN", "5"))

# В real по умолчанию НЕ урезаем функциональность: алерты по классификатору разрешены
ENABLE_CLASSIFIER_ALERTS_IN_REAL = _env_bool("PREVISOR_CLASSIFIER_ALERTS_IN_REAL", True)

# -----------------------------
# Celery / Redis
# -----------------------------

CELERY_BROKER_URL = os.getenv("CELERY_BROKER_URL", "redis://localhost:6379/0")

# Интервал автоматического запуска анализа (Celery beat), секунды.
# Для разработки можно 300, для демонстрации 600.
COLLECTION_INTERVAL = int(os.getenv("PREVISOR_COLLECTION_INTERVAL", "300"))
