from __future__ import annotations

import logging
import os
from typing import List, Optional, Tuple

import requests
import smtplib
from email.mime.text import MIMEText
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)
if not logging.getLogger().handlers:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


# -----------------------------
# Конфиг
# -----------------------------

TELEGRAM_BOT_TOKEN = (os.getenv("TELEGRAM_BOT_TOKEN") or "").strip()
TELEGRAM_CHAT_ID = (os.getenv("TELEGRAM_CHAT_ID") or "").strip()

SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASS = os.getenv("SMTP_PASS")
EMAIL_TO = os.getenv("EMAIL_TO")


def _telegram_configured() -> bool:
    """Проверяет наличие минимальной конфигурации Telegram."""
    return bool(TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID)


def send_telegram(message: str) -> bool:
    """Отправляет сообщение в Telegram через Bot API.

    Важно:
    - TELEGRAM_CHAT_ID должен соответствовать чату/пользователю/каналу, где бот имеет доступ.
    - Для личного чата пользователь должен сначала написать боту (/start),
      иначе Telegram часто возвращает 400 "chat not found".

    Args:
        message: Текст сообщения (HTML-разметка разрешена).

    Returns:
        True, если сообщение успешно отправлено, иначе False.
    """
    if not _telegram_configured():
        logger.warning("Telegram: token/chat_id не настроены (пропуск отправки)")
        return False

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {"chat_id": TELEGRAM_CHAT_ID, "text": message, "parse_mode": "HTML"}

    try:
        resp = requests.post(url, data=payload, timeout=10)
        ok = (resp.status_code == 200) and (resp.json().get("ok") is True)
        if ok:
            logger.info("Telegram: сообщение отправлено")
            return True

        # Частая причина: бот не добавлен в чат / пользователь не писал боту
        if resp.status_code == 400 and "chat not found" in resp.text.lower():
            logger.error(
                "Telegram error 400: chat not found. "
                "Проверь: (1) пользователь написал боту /start, "
                "(2) TELEGRAM_CHAT_ID верный, "
                "(3) бот добавлен в группу/канал и имеет права."
            )
        else:
            logger.error("Telegram error %s: %s", resp.status_code, resp.text)

        return False

    except Exception as exc:
        logger.error("Telegram exception: %s", exc)
        return False


def send_email(subject: str, body: str) -> bool:
    """Отправляет email-уведомление через SMTP.

    Args:
        subject: Тема письма.
        body: Тело письма в формате HTML.

    Returns:
        True, если письмо отправлено, иначе False.
    """
    if not all([SMTP_HOST, SMTP_USER, SMTP_PASS, EMAIL_TO]):
        logger.warning("Email: SMTP настройки не заданы (пропуск отправки)")
        return False

    msg = MIMEText(body, "html")
    msg["Subject"] = subject
    msg["From"] = SMTP_USER
    msg["To"] = EMAIL_TO

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)
        logger.info("Email: отправлено")
        return True
    except Exception as exc:
        logger.error("Email error: %s", exc)
        return False


def notify_new_alert(alert_type: str, probability: float, source_ip: Optional[str] = None) -> bool:
    """Отправляет уведомление об одном новом алерте.

    Args:
        alert_type: Тип угрозы/аномалии.
        probability: Риск/вероятность (0..1).
        source_ip: Исходный IP (опционально).

    Returns:
        True, если хотя бы один канал принял сообщение.
    """
    ip = f" (IP: {source_ip})" if source_ip else ""
    msg = (
        f"<b>УГРОЗА!</b>\n"
        f"Тип: <code>{alert_type}</code>\n"
        f"Вероятность: <b>{probability:.1%}</b>{ip}"
    )

    ok = send_telegram(msg)
    # При желании можно включить email:
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
        total_alerts: Общее число обработанных записей (длина списка alerts).
        new_alerts: Число новых/сохранённых алертов (где alert == 1).
        telegram_sent: Сколько индивидуальных уведомлений ушло в Telegram.
        top_types: Топ типов алертов (тип, количество).
        max_probability: Максимальная вероятность среди алертов (если есть).

    Returns:
        True, если сводка отправлена, иначе False.
    """
    top_str = ", ".join([f"{t}: {c}" for t, c in top_types]) if top_types else "—"
    max_str = f"{max_probability:.1%}" if max_probability is not None else "—"

    msg = (
        f"<b>PreVisor: сводка запуска</b>\n"
        f"Модель: <code>{model_type}</code>\n"
        f"Всего записей: <b>{total_alerts}</b>\n"
        f"Новых алертов: <b>{new_alerts}</b>\n"
        f"Отправлено в Telegram: <b>{telegram_sent}</b>\n"
        f"Макс. вероятность: <b>{max_str}</b>\n"
        f"Топ типов: <code>{top_str}</code>"
    )

    return send_telegram(msg)
