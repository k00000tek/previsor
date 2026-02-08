from __future__ import annotations

import os

import pytest


def _env_bool(name: str, default: bool = False) -> bool:
    """Читает bool из переменной окружения (1/0, true/false, yes/no, on/off)."""
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "y", "on"}


# ВНИМАНИЕ: это интеграционный тест (нужна сеть + валидный TELEGRAM_BOT_TOKEN).
# По умолчанию он не запускается, чтобы не было неожиданных запросов к Telegram.
if not _env_bool("PREVISOR_RUN_TELEGRAM_DEBUG", False):
    pytest.skip("Telegram debug test disabled (set PREVISOR_RUN_TELEGRAM_DEBUG=true)", allow_module_level=True)


def test_telegram_webhook_info_and_updates():
    """Диагностика: проверяет webhook и работоспособность getUpdates."""
    token = (os.getenv("TELEGRAM_BOT_TOKEN") or "").strip()
    if not token:
        pytest.skip("TELEGRAM_BOT_TOKEN is not set")

    from utils.notifications import get_telegram_webhook_info, fetch_telegram_updates, extract_chat_candidates

    info = get_telegram_webhook_info()
    assert info.get("ok") is True, info

    result = info.get("result") or {}
    url = str(result.get("url") or "")
    pending = result.get("pending_update_count")
    last_error = result.get("last_error_message")

    print(f"Webhook URL: {url or '<empty>'}")
    print(f"Pending updates: {pending}")
    if last_error:
        print(f"Last error: {last_error}")

    if url:
        raise AssertionError(
            "У бота активирован webhook. В таком режиме polling (getUpdates) не работает, "
            "поэтому команды (/start) не будут обрабатываться нашим polling-потоком. "
            "Отключите webhook (deleteWebhook) или используйте /telegram/webhook."
        )

    updates = fetch_telegram_updates(limit=10, offset=None)
    assert updates.get("ok") is True, updates

    candidates = extract_chat_candidates(updates)
    print(f"Chat candidates (from updates): {candidates}")

