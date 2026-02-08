from __future__ import annotations

import logging
import os
import time
from typing import Optional, Literal, List

import numpy as np
import pandas as pd
from faker import Faker

from config import (
    MODE,
    SAMPLES_DIR,
    DATA_RUNTIME_DIR,
    COLLECTED_TRAFFIC_CSV,
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
    from scapy.all import sniff, get_if_list, conf  # type: ignore
    try:  # Windows-only helper
        from scapy.arch.windows import get_windows_if_list  # type: ignore
    except Exception:  # pragma: no cover
        get_windows_if_list = None  # type: ignore
    from scapy.layers.inet import IP, TCP, UDP  # type: ignore
    try:
        from scapy.layers.inet6 import IPv6  # type: ignore
    except Exception:  # pragma: no cover
        IPv6 = None  # type: ignore
    from scapy.layers.http import HTTPRequest  # type: ignore
except Exception:  # pragma: no cover
    sniff = None  # type: ignore
    get_if_list = None  # type: ignore
    conf = None  # type: ignore
    get_windows_if_list = None  # type: ignore
    IP = TCP = UDP = HTTPRequest = None  # type: ignore
    IPv6 = None  # type: ignore

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
    return COLLECTED_TRAFFIC_CSV


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

    iface_list = _resolve_iface_names(iface)
    iface = iface_list if len(iface_list) > 1 else iface_list[0]

    rows: list[dict] = []

    def packet_handler(pkt) -> None:
        """Обрабатывает один пакет и добавляет строку в rows."""
        if (IP is None or IP not in pkt) and (IPv6 is None or IPv6 not in pkt):
            return

        ts = pd.to_datetime(time.time(), unit="s")
        if IP is not None and IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            proto = int(getattr(pkt[IP], "proto", 0))
        else:
            src_ip = pkt[IPv6].src  # type: ignore[index]
            dst_ip = pkt[IPv6].dst  # type: ignore[index]
            proto = int(getattr(pkt[IPv6], "nh", 0))  # type: ignore[index]

        src_port = 0
        dst_port = 0
        tcp_flags = 0

        if TCP is not None and TCP in pkt:
            proto = 6
            src_port = int(pkt[TCP].sport)
            dst_port = int(pkt[TCP].dport)
            try:
                tcp_flags = int(pkt[TCP].flags)
            except Exception:
                tcp_flags = 0
        elif UDP is not None and UDP in pkt:
            proto = 17
            src_port = int(pkt[UDP].sport)
            dst_port = int(pkt[UDP].dport)
        else:
            proto = proto

        http_method = None
        http_host = None
        http_path = None
        http_url = None
        if HTTPRequest is not None and HTTPRequest in pkt and getattr(pkt[HTTPRequest], "Method", None):
            try:
                http_method = pkt[HTTPRequest].Method.decode(errors="ignore")
            except Exception:
                http_method = None
            try:
                raw_host = getattr(pkt[HTTPRequest], "Host", None)
                http_host = raw_host.decode(errors="ignore") if raw_host else None
            except Exception:
                http_host = None
            try:
                raw_path = getattr(pkt[HTTPRequest], "Path", None)
                http_path = raw_path.decode(errors="ignore") if raw_path else None
            except Exception:
                http_path = None
            if http_host and http_path:
                http_url = f"http://{http_host}{http_path}"

        pkt_len = 0
        try:
            pkt_len = int(len(pkt))
        except Exception:
            pkt_len = 0

        ttl = 0
        try:
            if IP is not None and IP in pkt:
                ttl = int(getattr(pkt[IP], "ttl", 0))
            elif IPv6 is not None and IPv6 in pkt:
                ttl = int(getattr(pkt[IPv6], "hlim", 0))
            else:
                ttl = 0
        except Exception:
            ttl = 0

        rows.append(
            {
                "timestamp": ts,
                "source_ip": src_ip,
                "dest_ip": dst_ip,
                "protocol": proto,          # 6=TCP, 17=UDP, прочее=другое
                "src_port": src_port,
                "dest_port": dst_port,
                "packet_len": pkt_len,
                "ttl": ttl,
                "tcp_flags": tcp_flags,
                "packet_count": 1,
                "http_method": http_method,
                "host": http_host,
                "url": http_url,
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
        "promisc": True,
    }
    if bpf_filter:
        sniff_kwargs["filter"] = bpf_filter

    try:
        sniff(**sniff_kwargs)  # type: ignore
    except Exception as exc:
        if isinstance(iface, list) and len(iface) > 1:
            logger.warning("Multi-iface sniff failed (%s) - fallback to %s", exc, iface[0])
            sniff_kwargs["iface"] = iface[0]
            sniff(**sniff_kwargs)  # type: ignore
        else:
            raise

    if not rows:
        logger.warning("Не удалось захватить пакеты на интерфейсе: %s", iface)

    if not rows:
        return pd.DataFrame(
            columns=[
                "timestamp",
                "source_ip",
                "dest_ip",
                "protocol",
                "src_port",
                "dest_port",
                "packet_len",
                "ttl",
                "tcp_flags",
                "packet_count",
                "http_method",
                "host",
                "url",
                "Attack Type",
            ]
        )

    return pd.DataFrame(rows)


def collect_simulated_traffic(*, num_rows: int) -> pd.DataFrame:
    """Генерация симулированных строк трафика для внутренних режимов.

    Важно: для демонстрации эвристик (Port Scanning/DDoS/HTTP Anomaly)
    создаются «паттерн-строки», которые гарантированно триггерят детекторы,
    если num_rows достаточно велик.

    Args:
        num_rows: Сколько строк сгенерировать.

    Returns:
        DataFrame с колонками, совместимыми с базовой предобработкой.
    """
    from modules.heuristics import HeuristicPolicy

    attack_types = ["Normal Traffic", "DDoS", "Port Scanning", "Brute Force", "Web Attacks", "Anomaly"]
    http_methods = [None, "GET", "POST", "HEAD"]

    policy = HeuristicPolicy()

    def _rand_row(
        *,
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
        src_port: Optional[int] = None,
        dst_port: Optional[int] = None,
        http_method: Optional[str] = None,
        url: Optional[str] = None,
        host: Optional[str] = None,
    ) -> dict:
        """Формирует одну строку «сырого» трафика для симуляции.

        Args:
            src_ip: IP источника (если None — будет сгенерирован).
            dst_ip: IP назначения (если None — будет сгенерирован).
            src_port: Порт источника (если None — будет сгенерирован).
            dst_port: Порт назначения (если None — будет сгенерирован).
            http_method: HTTP метод (если None — будет выбран случайно).
            url: URL (опционально).
            host: Host (опционально).

        Returns:
            Словарь с полями строки трафика.
        """
        ts = fake.date_time_this_year()
        src_ip = src_ip or fake.ipv4()
        dst_ip = dst_ip or fake.ipv4()

        proto = int(np.random.choice([6, 17], p=[0.75, 0.25]))
        src_port = int(src_port if src_port is not None else np.random.randint(1024, 65536))
        dst_port = int(dst_port if dst_port is not None else np.random.randint(1, 65536))

        http_method = http_method if http_method is not None else np.random.choice(http_methods, p=[0.7, 0.1, 0.15, 0.05])
        attack = np.random.choice(attack_types, p=[0.85, 0.03, 0.04, 0.03, 0.03, 0.02])

        return {
            "timestamp": ts,
            "source_ip": src_ip,
            "dest_ip": dst_ip,
            "protocol": proto,
            "src_port": src_port,
            "dest_port": dst_port,
            "packet_len": int(np.random.randint(60, 1500)),
            "ttl": int(np.random.randint(32, 129)),
            "tcp_flags": int(np.random.randint(0, 64)) if proto == 6 else None,
            "packet_count": 1,
            "http_method": http_method,
            "host": host,
            "url": url,
            "Attack Type": attack,
        }

    rows: List[dict] = []

    # Паттерны для эвристик (если хватает места)
    portscan_unique = max(1, int(policy.portscan_min_unique_ports))
    portscan_total = max(portscan_unique, int(policy.portscan_min_total_packets))
    ddos_unique = max(1, int(policy.ddos_min_unique_sources))
    ddos_total = max(ddos_unique, int(policy.ddos_min_total_packets))
    susp_hits = max(1, int(policy.suspicious_port_min_hits))
    http_hits = 1

    required = portscan_total + ddos_total + susp_hits + http_hits
    if int(num_rows) >= required:
        # Suspicious Port
        susp_port = policy.suspicious_ports[0] if policy.suspicious_ports else 22
        susp_src = fake.ipv4_private()
        susp_dst = fake.ipv4_private()
        for _ in range(susp_hits):
            rows.append(_rand_row(src_ip=susp_src, dst_ip=susp_dst, dst_port=susp_port))

        # Port Scanning
        scan_src = fake.ipv4_private()
        scan_dst = fake.ipv4_private()
        scan_ports = np.random.choice(range(1, 65536), size=portscan_unique, replace=False)
        for port in scan_ports:
            rows.append(_rand_row(src_ip=scan_src, dst_ip=scan_dst, dst_port=int(port)))
        for _ in range(portscan_total - portscan_unique):
            port = int(np.random.choice(scan_ports))
            rows.append(_rand_row(src_ip=scan_src, dst_ip=scan_dst, dst_port=port))

        # DDoS
        ddos_target = fake.ipv4_private()
        ddos_sources = [fake.ipv4_private() for _ in range(ddos_unique)]
        for i in range(ddos_total):
            src = ddos_sources[i % ddos_unique]
            rows.append(_rand_row(src_ip=src, dst_ip=ddos_target, dst_port=int(np.random.randint(1, 65536))))

        # HTTP Anomaly
        rows.append(
            _rand_row(
                src_ip=fake.ipv4_private(),
                dst_ip=fake.ipv4_private(),
                dst_port=80,
                http_method="GET",
                host="example.local",
                url="http://example.local/?q=../etc/passwd",
            )
        )
    else:
        logger.warning(
            "num_rows=%s слишком мал для полной эмуляции эвристик (нужно >= %s); генерирую только базовые строки.",
            num_rows,
            required,
        )

    # Остальные строки — случайные
    remaining = max(0, int(num_rows) - len(rows))
    for _ in range(remaining):
        rows.append(_rand_row())

    return pd.DataFrame(rows)


def list_network_interfaces(details: bool = False) -> List[dict] | List[str]:
    """Возвращает список доступных интерфейсов (если Scapy доступен).

    Args:
        details: Если True, вернуть список словарей с name/description/guid.
    """
    if get_if_list is None:
        return []
    try:
        if details and get_windows_if_list is not None:
            return list(get_windows_if_list())
        return list(get_if_list())
    except Exception:
        return []


def _is_link_local(ip: str) -> bool:
    """Проверяет, является ли IP link-local или loopback."""
    ip = (ip or "").lower()
    return ip.startswith("169.254.") or ip.startswith("fe80:") or ip in {"127.0.0.1", "::1"}


def _is_virtual_name(name: str) -> bool:
    """Проверяет, является ли интерфейс виртуальным по имени."""
    lower = (name or "").lower()
    bad = ["loopback", "virtual", "hyper-v", "vbox", "teredo", "miniport", "wsl", "npcap"]
    return any(b in lower for b in bad)


def _auto_iface_from_details(details: List[dict]) -> Optional[str]:
    """Выбирает интерфейс с реальным IP из подробного списка."""
    if not details:
        return None
    preferred = []
    fallback = []
    for item in details:
        name = str(item.get("name") or "")
        if not name or _is_virtual_name(name):
            continue
        ips = item.get("ips") or []
        ips = [str(ip) for ip in ips if ip]
        if any(not _is_link_local(ip) for ip in ips):
            preferred.append(name)
        elif ips:
            fallback.append(name)
    if preferred:
        return preferred[0]
    if fallback:
        return fallback[0]
    return None


def _auto_iface(interfaces: List[str]) -> Optional[str]:
    """Выбирает первый не-loopback интерфейс."""
    if not interfaces:
        return None
    for name in interfaces:
        lower = name.lower()
        if "loopback" in lower or lower == "lo" or "npcap loopback" in lower:
            continue
        return name
    return interfaces[0] if interfaces else None


def _find_loopback_iface() -> Optional[str]:
    """Ищет loopback-интерфейс (Npcap Loopback Adapter на Windows или lo на Linux)."""
    details = list_network_interfaces(details=True)
    if details:
        for item in details:
            name = str(item.get("name") or "")
            desc = str(item.get("description") or "")
            guid = str(item.get("guid") or "")
            blob = " ".join([name, desc, guid]).lower()
            if "loopback" in blob:
                return name

    interfaces = list_network_interfaces()
    for name in interfaces:
        lower = name.lower()
        if lower in {"lo"} or "loopback" in lower:
            return name
    return None


def _resolve_iface_names(requested: str) -> List[str]:
    """Возвращает список интерфейсов для sniff (основной + loopback при наличии)."""
    primary = _resolve_iface_name(requested)
    if os.getenv("PREVISOR_INCLUDE_LOOPBACK", "true").strip().lower() in {"1", "true", "yes", "y", "on"}:
        loopback = _find_loopback_iface()
        if loopback and loopback != primary:
            return [primary, loopback]
    return [primary]


def _resolve_iface_name(requested: str) -> str:
    """Возвращает имя интерфейса для Scapy с учетом aliases.

    Args:
        requested: Запрошенное имя (или "auto").

    Returns:
        Имя интерфейса, понятное Scapy.
    """
    requested = (requested or "").strip()
    if requested.lower() == "auto" or not requested:
        details = list_network_interfaces(details=True)
        auto = _auto_iface_from_details(details) if details else None
        if auto:
            return auto
        interfaces = list_network_interfaces()
        auto = _auto_iface(interfaces)
        if auto:
            return auto
        raise ValueError("Не удалось автоматически определить интерфейс. Укажи PREVISOR_NET_IFACE вручную.")

    interfaces = list_network_interfaces()
    if requested in interfaces:
        return requested

    # Try Windows friendly names/descriptions
    details = list_network_interfaces(details=True)
    if details:
        for item in details:
            name = str(item.get("name") or "")
            desc = str(item.get("description") or "")
            guid = str(item.get("guid") or "")
            if requested.lower() in {name.lower(), desc.lower(), guid.lower()}:
                return name

    auto = _auto_iface(interfaces)
    if auto:
        logger.warning("Интерфейс '%s' не найден, использую '%s'", requested, auto)
        return auto

    raise ValueError(
        "Interface '%s' not found. Доступные интерфейсы: %s" % (requested, ", ".join(interfaces) or "-")
    )


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
    # Параметры захвата для режима real
    iface: str = NETWORK_INTERFACE,
    num_packets: int = PACKET_COUNT_PER_COLLECTION,
    timeout_sec: int = PACKET_SNIFF_TIMEOUT_SEC,
    bpf_filter: str = BPF_FILTER,
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
        iface: Имя интерфейса (только для mode="real").
        num_packets: Количество пакетов за один сбор (только для mode="real").
        timeout_sec: Таймаут захвата (сек), только для mode="real".
        bpf_filter: BPF фильтр (только для mode="real").
        demo_source: Источник для demo/test ("mixed"/"cicids2017"/"csic2010"/"mscad"/"simulated").
        demo_rows: Размер demo/test-выборки.
        dataset_name: Имя processed датасета для режима dataset.

    Returns:
        DataFrame с сырыми данными трафика.
    """
    _maybe_seed()

    if mode == "real":
        df = collect_real_traffic(
            iface=iface,
            num_packets=num_packets,
            timeout_sec=timeout_sec,
            bpf_filter=bpf_filter,
        )
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
