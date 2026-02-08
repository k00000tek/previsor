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

from dotenv import load_dotenv

load_dotenv()


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
MODELS_PRETRAINED_DIR = os.getenv("PREVISOR_MODELS_PRETRAINED_DIR", os.path.join(MODELS_ROOT_DIR, "pretrained"))

DB_ROOT_DIR = os.getenv("PREVISOR_DB_ROOT_DIR", os.path.join(BASE_DIR, "db"))
DB_RUNTIME_DIR = os.getenv("PREVISOR_DB_RUNTIME_DIR", os.path.join(DB_ROOT_DIR, "runtime"))
DB_PATH = os.getenv("PREVISOR_DB_PATH", os.path.join(DB_RUNTIME_DIR, "previsor.db"))

for _p in (
    DATA_ROOT_DIR,
    SAMPLES_DIR,
    DATA_RUNTIME_DIR,
    DATASETS_DIR,
    MODELS_ROOT_DIR,
    MODELS_RUNTIME_DIR,
    MODELS_PRETRAINED_DIR,
    DB_ROOT_DIR,
    DB_RUNTIME_DIR,
):
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

NETWORK_INTERFACE = os.getenv("PREVISOR_NET_IFACE", "Беспроводная сеть")
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
IFOREST_STATS_PATH = os.getenv(
    "PREVISOR_IFOREST_STATS_PATH",
    os.path.join(MODELS_RUNTIME_DIR, "isolation_forest_stats.json"),
)

# Предобученные артефакты (fallback, если runtime отсутствует)
RF_PRETRAINED_MODEL_PATH = os.getenv(
    "PREVISOR_RF_PRETRAINED_MODEL_PATH",
    os.path.join(MODELS_PRETRAINED_DIR, "previsor_model.pkl"),
)
XGB_PRETRAINED_MODEL_PATH = os.getenv(
    "PREVISOR_XGB_PRETRAINED_MODEL_PATH",
    os.path.join(MODELS_PRETRAINED_DIR, "previsor_model_xgb.pkl"),
)
FEATURE_SCHEMA_PRETRAINED_PATH = os.getenv(
    "PREVISOR_FEATURE_SCHEMA_PRETRAINED_PATH",
    os.path.join(MODELS_PRETRAINED_DIR, "feature_columns.pkl"),
)
SCALER_PRETRAINED_PATH = os.getenv(
    "PREVISOR_SCALER_PRETRAINED_PATH",
    os.path.join(MODELS_PRETRAINED_DIR, "scaler.pkl"),
)
SCALER_COLUMNS_PRETRAINED_PATH = os.getenv(
    "PREVISOR_SCALER_COLUMNS_PRETRAINED_PATH",
    os.path.join(MODELS_PRETRAINED_DIR, "scaler_columns.pkl"),
)
LABEL_ENCODER_PRETRAINED_PATH = os.getenv(
    "PREVISOR_LABEL_ENCODER_PRETRAINED_PATH",
    os.path.join(MODELS_PRETRAINED_DIR, "label_encoder.pkl"),
)
IFOREST_PRETRAINED_PATH = os.getenv(
    "PREVISOR_IFOREST_PRETRAINED_PATH",
    os.path.join(MODELS_PRETRAINED_DIR, "isolation_forest.pkl"),
)
IFOREST_STATS_PRETRAINED_PATH = os.getenv(
    "PREVISOR_IFOREST_STATS_PRETRAINED_PATH",
    os.path.join(MODELS_PRETRAINED_DIR, "isolation_forest_stats.json"),
)

# Включение детектора аномалий.
# Требование для рабочего сценария: anomaly_detector используется ТОЛЬКО если:
#   1) ANOMALY_ENABLED=1 (или PREVISOR_ANOMALY_ENABLED=1)
#   2) baseline-модель IsolationForest существует (см. IFOREST_MODEL_PATH)
ANOMALY_ENABLED = _env_bool("ANOMALY_ENABLED", True) or _env_bool("PREVISOR_ANOMALY_ENABLED", False)

# Логирование сырых строк трафика в БД (traffic_logs).
LOG_TRAFFIC = _env_bool("PREVISOR_LOG_TRAFFIC", True)

# Включение эвристических детекторов (DDoS/port-scan/HTTP).
HEURISTICS_ENABLED = _env_bool("PREVISOR_HEURISTICS_ENABLED", True)

# Отчёты (внутреннее)
LAST_REPORT_PATH = os.getenv("PREVISOR_LAST_REPORT_PATH", os.path.join(MODELS_RUNTIME_DIR, "last_report.txt"))
LAST_REPORT_XGB_PATH = os.getenv("PREVISOR_LAST_REPORT_XGB_PATH", os.path.join(MODELS_RUNTIME_DIR, "last_report_xgb.txt"))


def resolve_artifact_path(runtime_path: str, pretrained_path: str) -> str:
    """Возвращает runtime путь, если он существует, иначе fallback на pretrained."""
    if runtime_path and os.path.exists(runtime_path):
        return runtime_path
    if pretrained_path and os.path.exists(pretrained_path):
        return pretrained_path
    return runtime_path

# -----------------------------
# Параметры алертинга/уведомлений
# -----------------------------

MAX_TELEGRAM_ALERTS_PER_RUN = int(os.getenv("MAX_TELEGRAM_ALERTS_PER_RUN", "5"))

# -----------------------------
# Внешние сервисы и каналы уведомлений
# -----------------------------

# Threat Intel (например, AbuseIPDB)
ABUSEIPDB_KEY = os.getenv(
    "ABUSEIPDB_KEY",
    "f6654debe874c838ab6271680260e642ab2178c88dc35f4e0d8c11d7e184b43e361f24d1e05b5118",
)

# Telegram уведомления
TELEGRAM_BOT_TOKEN = os.getenv(
    "TELEGRAM_BOT_TOKEN",
    "8478758709:AAHeApTfPirUh7dcjzxxa2fxqOW5CwKxexo",
)
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "-5026845212")
TELEGRAM_API_BASE = os.getenv("TELEGRAM_API_BASE", "https://api.telegram.org")
TELEGRAM_TIMEOUT_SEC = int(os.getenv("TELEGRAM_TIMEOUT_SEC", "10"))
PREVISOR_TELEGRAM_ENABLED = _env_bool("PREVISOR_TELEGRAM_ENABLED", True)
PREVISOR_TELEGRAM_COMMANDS = _env_bool("PREVISOR_TELEGRAM_COMMANDS", True)

# -----------------------------
# Настройки непрерывного мониторинга
# -----------------------------

PREVISOR_CONTINUOUS_MONITOR = _env_bool("PREVISOR_CONTINUOUS_MONITOR", True)
PREVISOR_CONTINUOUS_BATCH_SIZE = int(os.getenv("PREVISOR_CONTINUOUS_BATCH_SIZE", "500"))
PREVISOR_CONTINUOUS_FLUSH_SEC = float(os.getenv("PREVISOR_CONTINUOUS_FLUSH_SEC", "3"))
PREVISOR_CONTINUOUS_QUEUE_MAX = int(os.getenv("PREVISOR_CONTINUOUS_QUEUE_MAX", "10000"))

# -----------------------------
# Настройки аномалий (IsolationForest)
# -----------------------------

PREVISOR_ANOMALY_STRATEGY = os.getenv("PREVISOR_ANOMALY_STRATEGY", "baseline")
PREVISOR_ANOMALY_DECISION_THRESHOLD = float(os.getenv("PREVISOR_ANOMALY_DECISION_THRESHOLD", "0.0"))
PREVISOR_ANOMALY_BASELINE_QUANTILE = float(os.getenv("PREVISOR_ANOMALY_BASELINE_QUANTILE", "0.999"))
PREVISOR_ANOMALY_BASELINE_QUANTILES = os.getenv("PREVISOR_ANOMALY_BASELINE_QUANTILES", "0.95,0.99,0.995,0.999")
PREVISOR_ANOMALY_RETRAIN_ROWS = int(os.getenv("PREVISOR_ANOMALY_RETRAIN_ROWS", "5000"))
