from __future__ import annotations

import inspect
from datetime import datetime, timedelta

import pandas as pd


def _make_synthetic_df(n: int = 200) -> pd.DataFrame:
    """Генерирует небольшой синтетический датасет для unit-тестов."""
    rows = []
    base = datetime(2026, 1, 1, 0, 0, 0)

    for i in range(n):
        rows.append(
            {
                "timestamp": (base + timedelta(seconds=i)).isoformat(),
                "source_ip": f"192.168.1.{(i % 254) + 1}",
                "dest_port": 80 if i % 2 == 0 else 443,
                "flow_duration": float(10 + (i % 50)),
                "packet_count": int(1 + (i % 20)),
                # метка: 2 класса (важно для stratify)
                "Attack Type": "BENIGN" if i % 2 == 0 else "DDoS",
            }
        )

    return pd.DataFrame(rows)


def test_preprocess_returns_numeric_X_train_y_train():
    """Проверяем базовый контракт preprocess_data: X_train/y_train и только числовые признаки."""
    from modules.preprocessor import preprocess_data

    df = _make_synthetic_df(200)

    sig = inspect.signature(preprocess_data)
    kwargs = {}

    # Если новая версия поддерживает purpose — используем её.
    if "purpose" in sig.parameters:
        kwargs["purpose"] = "train"
    # Если поддерживает save_csv — выключаем
    if "save_csv" in sig.parameters:
        kwargs["save_csv"] = False

    result = preprocess_data(df, **kwargs)

    # Старый контракт
    X_train = result.get("X_train")
    y_train = result.get("y_train")

    assert X_train is not None, "preprocess_data должен вернуть X_train"
    assert y_train is not None, "preprocess_data должен вернуть y_train"
    assert len(X_train) == len(y_train)

    # Только числовые типы в X_train
    assert all(
        str(dt).startswith("float") or str(dt).startswith("int")
        for dt in X_train.dtypes
    ), "X_train должен содержать только числовые признаки"
