# tests/test_preprocessor.py
from modules.preprocessor import preprocess_data
import os

def test_preprocess_returns_numeric_X(tmp_path):
    # Используем твой collected_traffic.csv
    result = preprocess_data('data/collected_traffic.csv', output_dir='data')
    X_train = result['X_train']
    y_train = result['y_train']

    assert X_train is not None
    assert y_train is not None
    # Только числовые типы
    assert all(str(dt).startswith('float') or str(dt).startswith('int') for dt in X_train.dtypes)
