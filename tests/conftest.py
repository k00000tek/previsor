from __future__ import annotations

import os
import shutil
import uuid
from pathlib import Path

import pytest


@pytest.fixture
def tmp_path() -> Path:
    """Локальный аналог pytest tmp_path без tmpdir-плагина.

    В этом окружении стандартный tmpdir/tmp_path может создавать директории,
    которые становятся недоступны по ACL (WinError 5). Здесь мы делаем временную
    директорию внутри репозитория без выставления специфичных прав.
    """
    base = Path.cwd() / ".tests_tmp"
    base.mkdir(parents=True, exist_ok=True)
    path = base / uuid.uuid4().hex
    path.mkdir(parents=True, exist_ok=False)
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


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

    # Упрощаем параллельность sklearn/joblib для стабильных тестов в Windows-среде.
    monkeypatch.setenv("PREVISOR_SKLEARN_N_JOBS", "1")

    # Обратная совместимость: старые имена переменных окружения.
    monkeypatch.setenv("DATA_DIR", str(data_dir))
    monkeypatch.setenv("DB_PATH", str(db_dir / "previsor.db"))
    monkeypatch.setenv("MODELS_DIR", str(models_dir))

    yield
