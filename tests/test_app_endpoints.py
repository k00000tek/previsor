from __future__ import annotations


def test_health_endpoint():
    """Проверяем, что сервис жив и возвращает ожидаемый JSON."""
    # ВАЖНО: импорт app делаем внутри теста (чтобы conftest успел выставить env)
    from app import app

    client = app.test_client()
    resp = client.get("/health")

    assert resp.status_code == 200
    data = resp.get_json()
    assert isinstance(data, dict)
    assert data.get("status") == "OK"


def test_alerts_endpoint_returns_list():
    """Проверяем, что /alerts отвечает 200 и возвращает список (даже если пустой)."""
    from app import app

    client = app.test_client()
    resp = client.get("/alerts?limit=5&offset=0")

    assert resp.status_code == 200
    data = resp.get_json()
    assert isinstance(data, list)
