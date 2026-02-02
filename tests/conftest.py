from __future__ import annotations

import os
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def test_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Глобальная фикстура для тестов.

    Цели:
    - направить runtime-артефакты (DB, модели, данные) в tmp_path;
    - выключить внешние интеграции (AbuseIPDB/Telegram), чтобы не было сетевых вызовов;
    - поставить безопасный режим demo, чтобы тесты не пытались sniff-ить интерфейсы.
    """
    data_dir = tmp_path / "data_runtime"
    db_dir = tmp_path / "db_runtime"
    models_dir = tmp_path / "models_runtime"

    data_dir.mkdir(parents=True, exist_ok=True)
    db_dir.mkdir(parents=True, exist_ok=True)
    models_dir.mkdir(parents=True, exist_ok=True)

    monkeypatch.setenv("PREVISOR_MODE", "demo")
    monkeypatch.setenv("PREVISOR_DATA_DIR", str(data_dir))
    monkeypatch.setenv("PREVISOR_DB_PATH", str(db_dir / "previsor.db"))
    monkeypatch.setenv("PREVISOR_MODELS_DIR", str(models_dir))

    # Внешние интеграции отключаем
    monkeypatch.setenv("ABUSEIPDB_KEY", "")
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "")

    # dev-only (если в app есть dev эндпоинты)
    monkeypatch.setenv("PREVISOR_ENABLE_DEV_ENDPOINTS", "true")

    # На всякий случай — “старые” имена переменных, если где-то остались:
    monkeypatch.setenv("DATA_DIR", str(data_dir))
    monkeypatch.setenv("DB_PATH", str(db_dir / "previsor.db"))
    monkeypatch.setenv("MODELS_DIR", str(models_dir))

    yield
