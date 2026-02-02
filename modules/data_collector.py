from __future__ import annotations

import logging
import os
import time
from typing import Optional, Literal

import numpy as np
import pandas as pd
from faker import Faker

from config import (
    MODE,
    SAMPLES_DIR,
    DATA_RUNTIME_DIR,
    DATASETS_DIR,
    DATASET_NAME,
    DEMO_SOURCE,
    DEMO_ROWS,
    DEMO_SEED,
    NETWORK_INTERFACE,
    PACKET_COUNT_PER_COLLECTION,
    PACKET_SNIFF_TIMEOUT_SEC,
    BPF_FILTER,
)

# Scapy может быть недоступен в некоторых окружениях; импортируем безопасно.
try:
    from scapy.all import sniff  # type: ignore
    from scapy.layers.inet import IP, TCP, UDP  # type: ignore
    from scapy.layers.http import HTTPRequest  # type: ignore
except Exception:  # pragma: no cover
    sniff = None  # type: ignore
    IP = TCP = UDP = HTTPRequest = None  # type: ignore

logger = logging.getLogger(__name__)
if not logging.getLogger().handlers:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

fake = Faker()

DemoSource = Literal["mixed", "cicids2017", "csic2010", "mscad", "simulated"]
CollectorMode = Literal["real", "demo", "test", "dataset"]


def _maybe_seed() -> None:
    """Устанавливает seed для numpy/faker, если PREVISOR_DEMO_SEED задан.

    По умолчанию (если seed не задан) результаты демо будут различаться между запусками.
    """
    if DEMO_SEED is None or not str(DEMO_SEED).strip():
        return
    try:
        seed = int(str(DEMO_SEED).strip())
        np.random.seed(seed)
        Faker.seed(seed)
    except Exception:
        # Если seed не число — просто игнорируем.
        return


def _safe_read_csv(path: str) -> Optional[pd.DataFrame]:
    """Безопасно читает CSV, возвращает None при ошибке.

    Args:
        path: Путь к CSV.

    Returns:
        DataFrame или None.
    """
    try:
        if not os.path.exists(path):
            return None
        return pd.read_csv(path)
    except Exception as exc:
        logger.warning("Не удалось прочитать CSV %s: %s", path, exc)
        return None


def _default_output_csv() -> str:
    """Возвращает дефолтный путь сохранения собранного трафика в runtime."""
    os.makedirs(DATA_RUNTIME_DIR, exist_ok=True)
    return os.path.join(DATA_RUNTIME_DIR, "collected_traffic.csv")


def collect_real_traffic(
    *,
    iface: str = NETWORK_INTERFACE,
    num_packets: int = PACKET_COUNT_PER_COLLECTION,
    timeout_sec: int = PACKET_SNIFF_TIMEOUT_SEC,
    bpf_filter: str = BPF_FILTER,
) -> pd.DataFrame:
    """Захват реального трафика с помощью Scapy.

    Требования:
    - Scapy установлен (requirements.txt).
    - Запуск с правами, достаточными для sniff (обычно админ/root).
    - Корректное имя сетевого интерфейса (PREVISOR_NET_IFACE).

    Args:
        iface: Имя сетевого интерфейса.
        num_packets: Максимальное число пакетов за один сбор.
        timeout_sec: Таймаут захвата (сек).
        bpf_filter: BPF-фильтр (например: "tcp or udp").

    Returns:
        DataFrame с "сырыми" признаками на уровне пакетов.
        Важно: колонка Attack Type ставится в "Normal Traffic", чтобы инференс не ломался
        на LabelEncoder (у нас в real нет истинной метки).
    """
    if sniff is None:
        raise RuntimeError(
            "Scapy недоступен в окружении. Проверьте, что он установлен и импортируется корректно."
        )

    rows: list[dict] = []

    def packet_handler(pkt) -> None:
        if IP is None or IP not in pkt:
            return

        ts = pd.to_datetime(time.time(), unit="s")
        src_ip = pkt[IP].src

        proto = 0
        src_port = None
        dst_port = None
        tcp_flags = None

        if TCP is not None and TCP in pkt:
            proto = 6
            src_port = int(pkt[TCP].sport)
            dst_port = int(pkt[TCP].dport)
            try:
                tcp_flags = int(pkt[TCP].flags)
            except Exception:
                tcp_flags = None
        elif UDP is not None and UDP in pkt:
            proto = 17
            src_port = int(pkt[UDP].sport)
            dst_port = int(pkt[UDP].dport)
        else:
            proto = int(getattr(pkt[IP], "proto", 0))

        http_method = None
        if HTTPRequest is not None and HTTPRequest in pkt and getattr(pkt[HTTPRequest], "Method", None):
            try:
                http_method = pkt[HTTPRequest].Method.decode(errors="ignore")
            except Exception:
                http_method = None

        pkt_len = None
        try:
            pkt_len = int(len(pkt))
        except Exception:
            pkt_len = None

        ttl = None
        try:
            ttl = int(getattr(pkt[IP], "ttl", 0))
        except Exception:
            ttl = None

        rows.append(
            {
                "timestamp": ts,
                "source_ip": src_ip,
                "protocol": proto,          # 6=TCP, 17=UDP, прочее=другое
                "src_port": src_port,
                "dest_port": dst_port,
                "packet_len": pkt_len,
                "ttl": ttl,
                "tcp_flags": tcp_flags,
                "packet_count": 1,
                "http_method": http_method,
                # В real метки нет → ставим "Normal Traffic", чтобы не падал LabelEncoder в inference
                "Attack Type": "Normal Traffic",
            }
        )

    logger.info(
        "Захват реального трафика: iface=%s packets=%s timeout=%ss filter=%r",
        iface, num_packets, timeout_sec, bpf_filter
    )

    sniff_kwargs = {
        "iface": iface,
        "prn": packet_handler,
        "count": int(num_packets),
        "timeout": int(timeout_sec),
        "store": False,
    }
    if bpf_filter:
        sniff_kwargs["filter"] = bpf_filter

    sniff(**sniff_kwargs)  # type: ignore

    if not rows:
        return pd.DataFrame(
            columns=[
                "timestamp",
                "source_ip",
                "protocol",
                "src_port",
                "dest_port",
                "packet_len",
                "ttl",
                "tcp_flags",
                "packet_count",
                "http_method",
                "Attack Type",
            ]
        )

    return pd.DataFrame(rows)


def collect_simulated_traffic(*, num_rows: int) -> pd.DataFrame:
    """Генерация симулированных строк трафика для внутренних режимов.

    Args:
        num_rows: Сколько строк сгенерировать.

    Returns:
        DataFrame с колонками, совместимыми с базовой предобработкой.
    """
    attack_types = ["Normal Traffic", "DDoS", "Port Scanning", "Brute Force", "Web Attacks", "Anomaly"]
    http_methods = [None, "GET", "POST", "HEAD"]

    rows = []
    for _ in range(int(num_rows)):
        ts = fake.date_time_this_year()
        src_ip = fake.ipv4()

        proto = int(np.random.choice([6, 17], p=[0.75, 0.25]))
        src_port = int(np.random.randint(1024, 65536))
        dst_port = int(np.random.randint(1, 65536))

        http_method = np.random.choice(http_methods, p=[0.7, 0.1, 0.15, 0.05])
        attack = np.random.choice(attack_types, p=[0.85, 0.03, 0.04, 0.03, 0.03, 0.02])

        rows.append(
            {
                "timestamp": ts,
                "source_ip": src_ip,
                "protocol": proto,
                "src_port": src_port,
                "dest_port": dst_port,
                "packet_len": int(np.random.randint(60, 1500)),
                "ttl": int(np.random.randint(32, 129)),
                "tcp_flags": int(np.random.randint(0, 64)) if proto == 6 else None,
                "packet_count": 1,
                "http_method": http_method,
                "Attack Type": attack,
            }
        )

    return pd.DataFrame(rows)


def _collect_from_samples(source: DemoSource, *, num_rows: int) -> Optional[pd.DataFrame]:
    """Берет данные из sample CSV (data/samples/*_sample.csv) и делает случайную выборку.

    Args:
        source: Источник demo-данных.
        num_rows: Размер выборки.

    Returns:
        DataFrame или None, если сэмплы не найдены/не читаются.
    """
    mapping = {
        "cicids2017": os.path.join(SAMPLES_DIR, "cicids2017_sample.csv"),
        "csic2010": os.path.join(SAMPLES_DIR, "csic2010_sample.csv"),
        "mscad": os.path.join(SAMPLES_DIR, "mscad_sample.csv"),
    }

    if source == "simulated":
        return None

    if source == "mixed":
        frames = []
        for s in ("cicids2017", "csic2010", "mscad"):
            df = _safe_read_csv(mapping[s])
            if df is not None and len(df) > 0:
                frames.append(df)
        if not frames:
            return None
        df_all = pd.concat(frames, ignore_index=True)
        return df_all.sample(n=min(num_rows, len(df_all)), replace=len(df_all) < num_rows)

    path = mapping.get(source)
    if not path:
        return None

    df = _safe_read_csv(path)
    if df is None or len(df) == 0:
        return None

    return df.sample(n=min(num_rows, len(df)), replace=len(df) < num_rows)


def collect_from_dataset(
    *,
    dataset_name: str = DATASET_NAME,
    num_rows: Optional[int] = None,
) -> pd.DataFrame:
    """Читает подготовленный датасет из data/runtime/datasets.

    Args:
        dataset_name: Имя файла датасета (например cicids2017_processed.csv).
        num_rows: Если задано — возвращает случайную подвыборку указанного размера.

    Returns:
        DataFrame.
    """
    path = os.path.join(DATASETS_DIR, dataset_name)
    df = _safe_read_csv(path)
    if df is None:
        raise FileNotFoundError(f"Prepared dataset не найден: {path}")

    if num_rows is not None and num_rows > 0:
        df = df.sample(n=min(int(num_rows), len(df)), replace=len(df) < int(num_rows))

    return df


def collect_traffic(
    *,
    mode: CollectorMode = MODE,  # type: ignore[assignment]
    save_csv: bool = True,
    output_csv: Optional[str] = None,
    demo_source: DemoSource = DEMO_SOURCE,  # type: ignore[assignment]
    demo_rows: int = DEMO_ROWS,
    dataset_name: str = DATASET_NAME,
) -> pd.DataFrame:
    """Единая точка получения "сырых" данных для пайплайна.

    Режимы:
        - real: sniff реального трафика через scapy
        - demo/test: sample-датасеты (data/samples) или simulated, если sample нет
        - dataset: подготовленный processed датасет из data/runtime/datasets

    Args:
        mode: "real" | "demo" | "test" | "dataset".
        save_csv: Сохранять ли собранные данные в CSV.
        output_csv: Явный путь для сохранения (если не задан — сохранение в data/runtime/collected_traffic.csv).
        demo_source: Источник для demo/test ("mixed"/"cicids2017"/"csic2010"/"mscad"/"simulated").
        demo_rows: Размер demo/test-выборки.
        dataset_name: Имя processed датасета для режима dataset.

    Returns:
        DataFrame с сырыми данными трафика.
    """
    _maybe_seed()

    if mode == "real":
        df = collect_real_traffic()
    elif mode == "dataset":
        df = collect_from_dataset(dataset_name=dataset_name, num_rows=demo_rows)
    else:
        # demo/test
        df = _collect_from_samples(demo_source, num_rows=int(demo_rows))
        if df is None:
            logger.info("Сэмплы не найдены или не подходят — использую simulated-генерацию")
            df = collect_simulated_traffic(num_rows=int(demo_rows))

    if save_csv:
        if output_csv is None:
            output_csv = _default_output_csv()
        os.makedirs(os.path.dirname(output_csv), exist_ok=True)
        df.to_csv(output_csv, index=False)
        logger.info("Данные сохранены: %s", output_csv)

    return df
