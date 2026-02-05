from __future__ import annotations

import logging
import os
import time
from datetime import datetime, timedelta
from typing import Optional

import requests
from dotenv import load_dotenv

from modules.database import get_ip_reputation, upsert_ip_reputation

load_dotenv()

logger = logging.getLogger(__name__)
if not logging.getLogger().handlers:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


# -----------------------------
# Конфиг
# -----------------------------

ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY", "").strip()
CACHE_DAYS = int(os.getenv("PREVISOR_TI_CACHE_DAYS", "7"))

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
ABUSEIPDB_TIMEOUT_SEC = int(os.getenv("PREVISOR_TI_TIMEOUT_SEC", "10"))
ABUSEIPDB_MAX_RETRIES = int(os.getenv("PREVISOR_TI_MAX_RETRIES", "3"))
ABUSEIPDB_BACKOFF_BASE_SEC = float(os.getenv("PREVISOR_TI_BACKOFF_BASE_SEC", "0.8"))


def _has_real_key(key: str) -> bool:
    """Проверяет, задан ли ключ не-плейсхолдер.

    Args:
        key: Строка ключа.

    Returns:
        True, если ключ выглядит рабочим, иначе False.
    """
    if not key:
        return False
    bad = {"your_key", "YOUR_KEY", "changeme", "change_me", "none"}
    return key.strip() not in bad


def _is_cache_fresh(last_check: datetime, cache_days: int) -> bool:
    """Проверяет “свежесть” кэша репутации IP.

    Args:
        last_check: Время последней проверки.
        cache_days: TTL кэша в днях.

    Returns:
        True, если кэш можно использовать.
    """
    return (datetime.utcnow() - last_check) < timedelta(days=int(cache_days))


def get_abuseipdb_score(ip: str) -> Optional[float]:
    """Получает abuseConfidenceScore (0..100) из AbuseIPDB.

    Использует кэш в БД (ip_cache). Если кэш “свежий”, сетевой запрос не делается.

    Args:
        ip: IP-адрес.

    Returns:
        float 0..100 или None, если запрос невозможен/ошибка.
    """
    ip = (ip or "").strip()
    if not ip:
        return None

    if not _has_real_key(ABUSEIPDB_KEY):
        logger.info("AbuseIPDB: ключ не задан — TI-обогащение пропущено")
        return None

    # 1) Проверяем кэш
    cached = get_ip_reputation(ip)
    if cached is not None:
        rep, last_check, source = cached
        if source == "abuseipdb" and last_check and _is_cache_fresh(last_check, CACHE_DAYS):
            return float(rep)

    # 2) Запрос к API с retry/backoff
    headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}

    for attempt in range(1, ABUSEIPDB_MAX_RETRIES + 1):
        try:
            resp = requests.get(
                ABUSEIPDB_URL,
                headers=headers,
                params=params,
                timeout=ABUSEIPDB_TIMEOUT_SEC,
            )

            if resp.status_code == 200:
                score = float(resp.json()["data"]["abuseConfidenceScore"])
                upsert_ip_reputation(ip, score, source="abuseipdb", checked_at=datetime.utcnow())
                return score

            # 429/5xx — пробуем повторить
            if resp.status_code in {429, 500, 502, 503, 504}:
                logger.warning("AbuseIPDB временная ошибка %s: %s", resp.status_code, resp.text)
            else:
                logger.warning("AbuseIPDB ошибка %s: %s", resp.status_code, resp.text)
                return None

        except Exception as exc:
            logger.warning("AbuseIPDB исключение: %s", exc)

        # backoff перед повтором
        if attempt < ABUSEIPDB_MAX_RETRIES:
            sleep_s = ABUSEIPDB_BACKOFF_BASE_SEC * (2 ** (attempt - 1))
            time.sleep(sleep_s)

    return None


def enrich_alert_with_reputation(alert_type: str, probability: float, source_ip: Optional[str] = None) -> float:
    """Корректирует риск алерта с учётом репутации источника IP.

    Используем простую комбинацию:
        adjusted = min(probability + score/200, 1.0)
    где score = abuseConfidenceScore (0..100).

    Args:
        alert_type: Тип угрозы (не используется в формуле, но оставлен для расширения логики).
        probability: Базовая вероятность модели (0..1).
        source_ip: Исходный IP.

    Returns:
        Итоговый риск (0..1).
    """
    if not source_ip:
        return float(probability)

    score = get_abuseipdb_score(source_ip)
    if score is None:
        return float(probability)

    adjusted = min(float(probability) + float(score) / 200.0, 1.0)
    logger.debug("IP %s репутация %.1f%% -> вероятность %.2f -> %.2f", source_ip, score, probability, adjusted)
    return float(adjusted)
