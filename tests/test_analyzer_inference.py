from __future__ import annotations

import inspect
from pathlib import Path

import pandas as pd


def _make_synthetic_df(n: int = 200) -> pd.DataFrame:
    """Синтетика для обучения/инференса классификатора."""
    rows = []
    for i in range(n):
        rows.append(
            {
                "timestamp": "2026-01-01T00:00:00",
                "source_ip": f"192.168.1.{(i % 254) + 1}",
                "dest_port": 80,
                "flow_duration": float(10 + (i % 50)),
                "packet_count": int(1 + (i % 20)),
                "Attack Type": "BENIGN" if i % 2 == 0 else "DDoS",
            }
        )
    return pd.DataFrame(rows)


def test_analyzer_inference_smoke(tmp_path: Path, monkeypatch):
    """Smoke-тест: Analyzer обучается и возвращает алерты на инференсе."""
    # 1) отключаем TI/сеть, если модуль существует
    try:
        import utils.api_integration as api_integration

        monkeypatch.setattr(api_integration, "get_abuseipdb", lambda ip: 0.0, raising=False)
    except Exception:
        pass

    from modules.preprocessor import preprocess_data
    from modules.analyzer import Analyzer

    df = _make_synthetic_df(200)

    # 2) предобработка под train
    sig = inspect.signature(preprocess_data)
    kwargs = {}
    if "purpose" in sig.parameters:
        kwargs["purpose"] = "train"
    if "save_csv" in sig.parameters:
        kwargs["save_csv"] = False

    result = preprocess_data(df, **kwargs)
    X_train = result.get("X_train")
    y_train = result.get("y_train")
    X_test = result.get("X_test")

    assert X_train is not None and y_train is not None and X_test is not None

    # 3) обучаем и сохраняем модель во временный путь
    analyzer = Analyzer(model_type="rf")

    model_path = tmp_path / "previsor_model.pkl"
    report_path = tmp_path / "last_report.txt"

    if hasattr(analyzer, "model_path"):
        analyzer.model_path = str(model_path)
    if hasattr(analyzer, "report_path"):
        analyzer.report_path = str(report_path)

    analyzer.train_model(X_train, y_train)

    # 4) инференс
    # В analyze обычно можно подать DataFrame напрямую
    alerts = analyzer.analyze(X_test, source_ips=None)

    assert isinstance(alerts, list)
    assert len(alerts) == len(X_test)

    # минимальная проверка структуры алерта
    sample = alerts[0]
    assert "alert" in sample
    assert "probability" in sample
