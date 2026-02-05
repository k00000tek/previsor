from __future__ import annotations

import logging
import os
import re
import ipaddress
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

import pandas as pd
from datetime import datetime

logger = logging.getLogger(__name__)
if not logging.getLogger().handlers:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


def _env_int(name: str, default: int) -> int:
    """Читает int из переменной окружения.

    Args:
        name: Имя переменной.
        default: Значение по умолчанию.

    Returns:
        int.
    """
    raw = os.getenv(name)
    if raw is None:
        return int(default)
    try:
        return int(raw)
    except Exception:
        return int(default)


def _env_bool(name: str, default: bool) -> bool:
    """Читает bool из переменной окружения.

    Args:
        name: Имя переменной.
        default: Значение по умолчанию.

    Returns:
        bool.
    """
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "y", "on"}


def _env_csv_ints(name: str, default: Iterable[int]) -> List[int]:
    """Читает список int из CSV строки окружения.

    Args:
        name: Имя переменной.
        default: Значение по умолчанию.

    Returns:
        Список int.
    """
    raw = os.getenv(name)
    if not raw:
        return list(default)
    out: List[int] = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            out.append(int(part))
        except Exception:
            continue
    return out or list(default)


def _env_regex(name: str, default: str) -> re.Pattern:
    """Возвращает регулярное выражение из окружения.

    Args:
        name: Имя переменной.
        default: Регулярное выражение по умолчанию.

    Returns:
        Скомпилированный regex.
    """
    raw = os.getenv(name) or default
    try:
        return re.compile(raw, re.IGNORECASE)
    except re.error:
        return re.compile(default, re.IGNORECASE)


@dataclass
class HeuristicPolicy:
    """Параметры эвристик (DDoS, port-scan, HTTP)."""
    enabled: bool = _env_bool("PREVISOR_HEURISTICS_ENABLED", True)

    # Port scanning
    portscan_min_unique_ports: int = _env_int("PREVISOR_PORTSCAN_UNIQUE_PORTS", 20)
    portscan_min_total_packets: int = _env_int("PREVISOR_PORTSCAN_MIN_PACKETS", 30)

    # DDoS-like burst
    ddos_min_unique_sources: int = _env_int("PREVISOR_DDOS_MIN_SOURCES", 10)
    ddos_min_total_packets: int = _env_int("PREVISOR_DDOS_MIN_PACKETS", 200)

    # Suspicious ports
    suspicious_ports: List[int] = None  # type: ignore[assignment]
    suspicious_port_min_hits: int = _env_int("PREVISOR_SUSPICIOUS_PORT_MIN_HITS", 3)

    # HTTP anomalies
    http_regex: re.Pattern = _env_regex(
        "PREVISOR_HTTP_SUSPICIOUS_REGEX",
        r"(?:\.\./|%2e%2e/|union\s+select|or\s+1=1|<script|%3cscript|/etc/passwd|cmd=|powershell|wget\s+http)",
    )

    def __post_init__(self) -> None:
        """Заполняет список подозрительных портов по умолчанию."""
        if self.suspicious_ports is None:
            self.suspicious_ports = _env_csv_ints(
                "PREVISOR_SUSPICIOUS_PORTS",
                default=[21, 22, 23, 25, 445, 3389, 1433, 3306, 5432, 6379, 27017, 5900],
            )


def _is_private_ip(value: Optional[str]) -> bool:
    """Проверяет, что IP относится к private/loopback/link-local сети."""
    if not value:
        return False
    try:
        ip = ipaddress.ip_address(str(value))
    except ValueError:
        return False
    return bool(ip.is_private or ip.is_loopback or ip.is_link_local)


def _col(df: pd.DataFrame, *names: str) -> Optional[str]:
    """Ищет первую существующую колонку среди списка имен.

    Args:
        df: DataFrame.
        *names: Список возможных названий.

    Returns:
        Имя колонки или None.
    """
    for name in names:
        if name in df.columns:
            return name
    return None


def _safe_iter_text(row: pd.Series, cols: Iterable[str]) -> str:
    """Склеивает текстовые поля строки в одну строку.

    Args:
        row: Строка DataFrame.
        cols: Колонки для объединения.

    Returns:
        Объединенная строка.
    """
    parts: List[str] = []
    for c in cols:
        val = row.get(c)
        if val is None:
            continue
        try:
            parts.append(str(val))
        except Exception:
            continue
    return " ".join(parts)


def detect_heuristic_alerts(
    df: pd.DataFrame,
    *,
    require_private_target: bool = False,
    require_private_source: bool = False,
) -> List[Dict[str, Any]]:
    """Heuristic detections for DDoS/port scanning/suspicious ports/HTTP anomalies.

    This works on raw traffic rows (pre-preprocessing), so it is resilient to dataset variety.
    """
    policy = HeuristicPolicy()
    if not policy.enabled:
        return []

    if df is None or df.empty:
        return []

    alerts: List[Dict[str, Any]] = []
    now = datetime.now().isoformat()

    source_col = _col(df, "source_ip", "src_ip", "Source IP")
    dest_ip_col = _col(df, "dest_ip", "dst_ip", "Destination IP")
    dest_port_col = _col(df, "dest_port", "dst_port", "Destination Port")

    if require_private_target:
        if not dest_ip_col:
            logger.debug("Heuristics skipped: dest_ip missing for private-target mode")
            return []
        mask = df[dest_ip_col].astype(str).map(_is_private_ip)
        df = df[mask]
        if df.empty:
            return []

    if require_private_source:
        if not source_col:
            logger.debug("Heuristics skipped: source_ip missing for private-source mode")
            return []
        mask = df[source_col].astype(str).map(_is_private_ip)
        df = df[mask]
        if df.empty:
            return []

    # Port scanning: many unique dest ports from one source in a batch.
    if source_col and dest_port_col:
        grouped = df.groupby(source_col)[dest_port_col].agg(["nunique", "count"])
        offenders = grouped[
            (grouped["nunique"] >= policy.portscan_min_unique_ports)
            & (grouped["count"] >= policy.portscan_min_total_packets)
        ]
        for src_ip, row in offenders.iterrows():
            alerts.append(
                {
                    "alert": 1,
                    "alert_type": "Port Scanning",
                    "probability": min(1.0, float(row["nunique"]) / max(policy.portscan_min_unique_ports, 1)),
                    "source_ip": str(src_ip),
                    "details": {
                        "unique_ports": int(row["nunique"]),
                        "total_packets": int(row["count"]),
                    },
                    "timestamp": now,
                    "detection_source": "heuristics",
                }
            )

    # DDoS-like burst: many sources hitting same target (dest_ip or dest_port).
    target_col = dest_ip_col or dest_port_col
    if target_col and source_col:
        grouped = df.groupby(target_col)[source_col].agg(["nunique", "count"])
        offenders = grouped[
            (grouped["nunique"] >= policy.ddos_min_unique_sources)
            & (grouped["count"] >= policy.ddos_min_total_packets)
        ]
        for target, row in offenders.iterrows():
            alerts.append(
                {
                    "alert": 1,
                    "alert_type": "DDoS",
                    "probability": min(1.0, float(row["count"]) / max(policy.ddos_min_total_packets, 1)),
                    "source_ip": None,
                    "details": {
                        "target": str(target),
                        "unique_sources": int(row["nunique"]),
                        "total_packets": int(row["count"]),
                    },
                    "timestamp": now,
                    "detection_source": "heuristics",
                }
            )

    # Suspicious port access: repeated hits on risky ports.
    if dest_port_col:
        port_hits = df[df[dest_port_col].isin(policy.suspicious_ports)]
        if not port_hits.empty:
            if source_col:
                grouped = port_hits.groupby([source_col, dest_port_col]).size()
                for (src_ip, port), count in grouped.items():
                    if int(count) >= policy.suspicious_port_min_hits:
                        alerts.append(
                            {
                                "alert": 1,
                                "alert_type": "Suspicious Port",
                                "probability": min(1.0, float(count) / max(policy.suspicious_port_min_hits, 1)),
                                "source_ip": str(src_ip),
                                "details": {"dest_port": int(port), "hits": int(count)},
                                "timestamp": now,
                                "detection_source": "heuristics",
                            }
                        )
            else:
                grouped = port_hits.groupby(dest_port_col).size()
                for port, count in grouped.items():
                    if int(count) >= policy.suspicious_port_min_hits:
                        alerts.append(
                            {
                                "alert": 1,
                                "alert_type": "Suspicious Port",
                                "probability": min(1.0, float(count) / max(policy.suspicious_port_min_hits, 1)),
                                "source_ip": None,
                                "details": {"dest_port": int(port), "hits": int(count)},
                                "timestamp": now,
                                "detection_source": "heuristics",
                            }
                        )

    # HTTP anomalies: regex scan on URL/content-like fields.
    http_cols = [
        c
        for c in df.columns
        if c.lower() in {"url", "content", "host", "user-agent", "user_agent", "useragent"}
    ]
    if http_cols:
        for _, row in df.iterrows():
            payload = _safe_iter_text(row, http_cols)
            if not payload:
                continue
            if policy.http_regex.search(payload):
                alerts.append(
                    {
                        "alert": 1,
                        "alert_type": "HTTP Anomaly",
                        "probability": 0.9,
                        "source_ip": str(row.get(source_col)) if source_col else None,
                        "details": {"columns": http_cols},
                        "timestamp": now,
                        "detection_source": "heuristics",
                    }
                )

    return alerts
