from __future__ import annotations

from typing import Any, Dict, List, Tuple


def _update(chat_id: int, text: str) -> Dict[str, Any]:
    """Строит минимальный update-объект Telegram для unit-тестов."""
    return {"update_id": 1, "message": {"chat": {"id": chat_id}, "text": text}}


def test_telegram_start_sends_help(monkeypatch):
    """Проверяет, что /start и /help вызывают отправку меню."""
    from app import _handle_telegram_update
    import app as app_module

    sent: List[Tuple[str, str]] = []

    def _fake_send(chat_id: str, message: str) -> bool:
        sent.append((str(chat_id), str(message)))
        return True

    monkeypatch.setattr(app_module, "send_telegram_to", _fake_send, raising=True)

    _handle_telegram_update(_update(123, "/start"))
    _handle_telegram_update(_update(123, "/help"))

    assert sent, "Ожидалась хотя бы одна отправка сообщения"
    assert any("PreVisor" in msg for _, msg in sent)


def test_telegram_selectchat_updates_env(monkeypatch):
    """Проверяет, что /selectchat обновляет TELEGRAM_CHAT_ID (без записи в .env)."""
    from app import _handle_telegram_update
    import app as app_module

    def _fake_send(chat_id: str, message: str) -> bool:
        return True

    monkeypatch.setattr(app_module, "send_telegram_to", _fake_send, raising=True)
    monkeypatch.setattr(app_module, "_write_env_value", lambda *a, **k: None, raising=True)

    _handle_telegram_update(_update(-999, "/selectchat@previsor_bot"))

    assert str(app_module.os.environ.get("TELEGRAM_CHAT_ID")) == "-999"


def test_telegram_status_and_monitor_commands(monkeypatch):
    """Проверяет, что /status, /startmonitor и /stopmonitor не падают и отвечают."""
    from app import _handle_telegram_update
    import app as app_module

    sent: List[str] = []

    def _fake_send(chat_id: str, message: str) -> bool:
        sent.append(str(message))
        return True

    monkeypatch.setattr(app_module, "send_telegram_to", _fake_send, raising=True)
    monkeypatch.setattr(app_module, "_is_monitor_running", lambda: True, raising=True)
    monkeypatch.setattr(app_module, "_start_continuous_monitor", lambda: True, raising=True)
    monkeypatch.setattr(app_module, "_stop_continuous_monitor", lambda: True, raising=True)

    _handle_telegram_update(_update(321, "/status"))
    _handle_telegram_update(_update(321, "/startmonitor"))
    _handle_telegram_update(_update(321, "/stopmonitor"))

    assert sent
    assert any("Мониторинг" in s for s in sent)
