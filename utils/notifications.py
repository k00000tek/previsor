from __future__ import annotations

import html
import logging
import os
import textwrap
import time
from dataclasses import dataclass
from email.mime.text import MIMEText
from typing import Iterable, List, Optional, Tuple

import requests
import smtplib
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)
if not logging.getLogger().handlers:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


def _env_bool(name: str, default: bool) -> bool:
    """Читает булеву переменную окружения.

    Поддерживаемые значения: 1/0, true/false, yes/no, on/off (без учета регистра).

    Args:
        name: Имя переменной окружения.
        default: Значение по умолчанию.

    Returns:
        Булево значение.
    """
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "y", "on"}


def _split_csv(value: str) -> List[str]:
    """Разбирает строку вида "a,b,c" в список значений."""
    return [v.strip() for v in (value or "").split(",") if v.strip()]


def _chunks(text: str, limit: int) -> Iterable[str]:
    """Бьёт длинное сообщение на части до лимита Telegram (4096)."""
    if not text:
        return []
    if len(text) <= limit:
        return [text]

    parts: List[str] = []
    buf = ""
    for line in text.splitlines(keepends=True):
        if len(buf) + len(line) <= limit:
            buf += line
            continue

        if buf:
            parts.append(buf)
            buf = ""

        if len(line) <= limit:
            buf = line
            continue

        for w in line.split(" "):
            add = w + " "
            if len(buf) + len(add) <= limit:
                buf += add
            else:
                if buf:
                    parts.append(buf)
                buf = add

    if buf:
        parts.append(buf)
    return parts


@dataclass(frozen=True)
class TelegramConfig:
    """Конфигурация Telegram-уведомлений.

    Attributes:
        token: Токен бота.
        chat_ids: Один или несколько chat_id (через запятую), куда слать уведомления.
        enabled: Включён ли канал Telegram.
        api_base: Базовый URL Bot API (на случай прокси).
        timeout_sec: Таймаут HTTP запросов.
    """

    token: str
    chat_ids: List[str]
    enabled: bool
    api_base: str
    timeout_sec: int


def _telegram_config() -> TelegramConfig:
    """Собирает конфигурацию Telegram из окружения.

    Returns:
        TelegramConfig.
    """
    token = (os.getenv("TELEGRAM_BOT_TOKEN") or "").strip()
    chat_ids = _split_csv(os.getenv("TELEGRAM_CHAT_ID") or "")
    enabled = _env_bool("PREVISOR_TELEGRAM_ENABLED", True)
    api_base = (os.getenv("TELEGRAM_API_BASE") or "https://api.telegram.org").rstrip("/")
    timeout_sec = int(os.getenv("TELEGRAM_TIMEOUT_SEC", "10"))
    return TelegramConfig(
        token=token,
        chat_ids=chat_ids,
        enabled=enabled,
        api_base=api_base,
        timeout_sec=timeout_sec,
    )


def _telegram_ready(cfg: TelegramConfig) -> bool:
    """Проверяет, готова ли конфигурация Telegram для отправки.

    Args:
        cfg: Конфигурация Telegram.

    Returns:
        True, если можно отправлять сообщения.
    """
    return bool(cfg.enabled and cfg.token and cfg.chat_ids)


def send_telegram(message: str) -> bool:
    """Отправляет сообщение в Telegram через Bot API.

    Поддерживает несколько chat_id (через запятую в TELEGRAM_CHAT_ID).

    Важно:
    - Для личного чата пользователь должен сначала написать боту (/start),
      иначе Telegram часто возвращает 400 "chat not found".
    - Для группового чата необходимо добавить бота в группу.

    Args:
        message: Текст сообщения (HTML-разметка разрешена).

    Returns:
        True, если сообщение успешно доставлено хотя бы в один чат.
    """
    cfg = _telegram_config()
    if not _telegram_ready(cfg):
        logger.warning(
            "Telegram: канал выключен или не настроен (enabled=%s token=%s chat_ids=%s)",
            cfg.enabled,
            bool(cfg.token),
            bool(cfg.chat_ids),
        )
        return False

    url = f"{cfg.api_base}/bot{cfg.token}/sendMessage"

    parts = list(_chunks(message, limit=4096))
    delivered_any = False
    max_retries = max(1, int(os.getenv("PREVISOR_TELEGRAM_MAX_RETRIES", "3")))
    backoff_base = float(os.getenv("PREVISOR_TELEGRAM_RETRY_BASE_SEC", "1.0"))

    for chat_id in cfg.chat_ids:
        for part in parts:
            payload = {"chat_id": chat_id, "text": part, "parse_mode": "HTML"}
            for attempt in range(1, max_retries + 1):
                try:
                    resp = requests.post(url, data=payload, timeout=cfg.timeout_sec)
                    ok = (resp.status_code == 200) and (resp.json().get("ok") is True)
                    if ok:
                        delivered_any = True
                        break

                    if resp.status_code == 429:
                        retry_after = None
                        try:
                            retry_after = resp.json().get("parameters", {}).get("retry_after")
                        except Exception:
                            retry_after = None
                        sleep_s = float(retry_after or (backoff_base * (2 ** (attempt - 1))))
                        logger.warning("Telegram rate limited (429), retry in %.1fs", sleep_s)
                        time.sleep(sleep_s)
                        continue

                    if resp.status_code in {500, 502, 503, 504} and attempt < max_retries:
                        sleep_s = backoff_base * (2 ** (attempt - 1))
                        logger.warning("Telegram temporary error %s, retry in %.1fs", resp.status_code, sleep_s)
                        time.sleep(sleep_s)
                        continue

                    if resp.status_code == 400 and "chat not found" in resp.text.lower():
                        logger.error(
                            "Telegram error 400: chat not found. "
                            "Проверь: (1) пользователь написал боту /start, "
                            "(2) TELEGRAM_CHAT_ID верный, "
                            "(3) бот добавлен в группу/канал и имеет права. "
                            "chat_id=%s",
                            chat_id,
                        )
                        break

                    logger.error("Telegram error %s: %s", resp.status_code, resp.text)
                    break
                except Exception as exc:
                    if attempt < max_retries:
                        sleep_s = backoff_base * (2 ** (attempt - 1))
                        logger.warning("Telegram exception: %s (retry in %.1fs)", exc, sleep_s)
                        time.sleep(sleep_s)
                        continue
                    logger.error("Telegram exception: %s", exc)
                    break
    return delivered_any


def fetch_telegram_updates(*, limit: int = 50, offset: Optional[int] = None) -> dict:
    """Получает updates у Telegram-бота.

    Это утилита для сценария "пользователь нашёл бота → написал /start → мы узнаём chat_id".
    На Windows локально webhook обычно не используется, поэтому pairing делается через getUpdates.

    Args:
        limit: Сколько updates запросить.
        offset: Offset для getUpdates.

    Returns:
        JSON-ответ Telegram Bot API.
    """
    cfg = _telegram_config()
    if not cfg.token:
        raise RuntimeError("TELEGRAM_BOT_TOKEN не задан")

    url = f"{cfg.api_base}/bot{cfg.token}/getUpdates"
    payload = {"limit": int(limit)}
    if offset is not None:
        payload["offset"] = int(offset)

    resp = requests.get(url, params=payload, timeout=cfg.timeout_sec)
    resp.raise_for_status()
    return resp.json()


def extract_chat_candidates(updates_json: dict) -> List[Tuple[str, str]]:
    """Извлекает кандидатов chat_id из getUpdates.

    Returns:
        Список пар (chat_id, title_or_username).
    """
    results = updates_json.get("result") or []
    out: List[Tuple[str, str]] = []

    for item in results:
        msg = item.get("message") or item.get("channel_post") or item.get("edited_message")
        if not isinstance(msg, dict):
            continue

        chat = msg.get("chat") or {}
        chat_id = chat.get("id")
        if chat_id is None:
            continue

        title = chat.get("title")
        username = chat.get("username")
        first = chat.get("first_name")
        last = chat.get("last_name")

        name = title or username or " ".join([p for p in [first, last] if p]) or "unknown"
        out.append((str(chat_id), str(name)))

    seen = set()
    uniq: List[Tuple[str, str]] = []
    for cid, name in reversed(out):
        if cid in seen:
            continue
        seen.add(cid)
        uniq.append((cid, name))

    return list(reversed(uniq))


def send_email(subject: str, body: str) -> bool:
    """Отправляет email-уведомление через SMTP.

    Канал email сейчас не используется по умолчанию (в PreVisor основной канал — Telegram),
    но оставлен как опциональное расширение.

    Переменные окружения:
        SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, EMAIL_TO

    Args:
        subject: Тема письма.
        body: Тело письма в формате HTML.

    Returns:
        True, если письмо отправлено, иначе False.
    """
    smtp_host = os.getenv("SMTP_HOST", "smtp.gmail.com")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = os.getenv("SMTP_USER")
    smtp_pass = os.getenv("SMTP_PASS")
    email_to = os.getenv("EMAIL_TO")

    if not all([smtp_host, smtp_user, smtp_pass, email_to]):
        logger.warning("Email: SMTP настройки не заданы (пропуск отправки)")
        return False

    msg = MIMEText(body, "html")
    msg["Subject"] = subject
    msg["From"] = smtp_user
    msg["To"] = email_to

    try:
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.send_message(msg)
        logger.info("Email: отправлено")
        return True
    except Exception as exc:
        logger.error("Email error: %s", exc)
        return False


def notify_new_alert(alert_type: str, probability: float, source_ip: Optional[str] = None) -> bool:
    """Отправляет уведомление об одном новом алерте.

    Важное улучшение: все пользовательские/модельные поля HTML-экранируются,
    чтобы случайные символы не ломали разметку Telegram.

    Args:
        alert_type: Тип угрозы/аномалии.
        probability: Риск/вероятность (0..1).
        source_ip: Исходный IP (опционально).

    Returns:
        True, если хотя бы один канал принял сообщение.
    """
    alert_type_safe = html.escape(str(alert_type))
    ip_safe = html.escape(str(source_ip)) if source_ip else ""
    ip_part = f" (IP: {ip_safe})" if ip_safe else ""

    msg = textwrap.dedent(
        f"""\
        <b>УГРОЗА!</b>
        Тип: <code>{alert_type_safe}</code>
        Вероятность: <b>{probability:.1%}</b>{ip_part}
        """
    ).strip()

    ok = send_telegram(msg)
    # ok = ok or send_email("PreVisor: Новая угроза", msg)
    return ok


def notify_pipeline_summary(
    *,
    model_type: str,
    total_alerts: int,
    new_alerts: int,
    telegram_sent: int,
    top_types: List[Tuple[str, int]],
    max_probability: Optional[float] = None,
) -> bool:
    """Отправляет компактную сводку по одному запуску пайплайна.

    Args:
        model_type: Идентификатор модели ("rf"/"xgb"/...).
        total_alerts: Общее число записей в result.alerts.
        new_alerts: Число сохранённых алертов (где alert == 1).
        telegram_sent: Сколько индивидуальных уведомлений ушло в Telegram.
        top_types: Топ типов алертов (тип, количество).
        max_probability: Максимальная вероятность среди алертов (если есть).

    Returns:
        True, если сводка отправлена, иначе False.
    """
    top_str = ", ".join([f"{html.escape(str(t))}: {int(c)}" for t, c in top_types]) if top_types else "—"
    max_str = f"{float(max_probability):.1%}" if max_probability is not None else "—"
    model_safe = html.escape(str(model_type))

    msg = textwrap.dedent(
        f"""\
        <b>PreVisor: сводка запуска</b>
        Модель: <code>{model_safe}</code>
        Всего записей: <b>{int(total_alerts)}</b>
        Новых алертов: <b>{int(new_alerts)}</b>
        Отправлено в Telegram: <b>{int(telegram_sent)}</b>
        Макс. вероятность: <b>{max_str}</b>
        Топ типов: <code>{top_str}</code>
        """
    ).strip()

    return send_telegram(msg)
