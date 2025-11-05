import pandas as pd
from sklearn.preprocessing import MinMaxScaler, StandardScaler, LabelEncoder, OneHotEncoder
from sklearn.model_selection import train_test_split
import logging
import os
import joblib

# Настройка логирования
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def preprocess_data(input_file: str, output_dir: str = 'data', scaler_type: str = 'minmax', test_size: float = 0.2) -> dict:
    """Предобработка данных из CSV: очистка, кодирование, масштабирование, split. Возвращает dict с train/test DF."""
    # Чтение файла
    if not os.path.exists(input_file):
        raise FileNotFoundError(f"Файл {input_file} не найден")
    df = pd.read_csv(input_file)
    logging.info(f"Загружен файл {input_file}: {len(df)} строк")

    # Очистка: dropna на ключевых, удаление дубликатов
    key_cols = ['source_ip', 'dest_port', 'packet_count'] if 'packet_count' in df else ['Flow Duration', 'source_ip']  # Унификация для источников
    df = df.dropna(subset=key_cols)
    df = df.drop_duplicates()
    df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
    logging.info(f"После очистки: {len(df)} строк")

    # Кодирование категориальных
    if 'http_method' in df:
        ohe = OneHotEncoder(sparse_output=False, handle_unknown='ignore')
        http_encoded = ohe.fit_transform(df[['http_method']])
        http_cols = ohe.get_feature_names_out(['http_method'])
        df = pd.concat([df.drop('http_method', axis=1), pd.DataFrame(http_encoded, columns=http_cols, index=df.index)], axis=1)
        logging.info("OneHotEncoding для http_method завершено")

    # Автоопределение колонки с меткой
    label_col = None
    for col in ['label', 'Label', 'Attack Type', 'classification']:
        if col in df.columns:
            label_col = col
            break

    if label_col:
        le = LabelEncoder()
        df['label_encoded'] = le.fit_transform(df[label_col])
        # Сохраняем encoder для analyzer
        joblib.dump(le, 'models/label_encoder.pkl')
        logging.info(f"LabelEncoding для '{label_col}' завершено")
    else:
        logging.warning("Колонка с меткой не найдена. Анализ без label.")


    # === УДАЛЯЕМ исходную колонку с меткой ===
    df = df.drop(columns=[label_col], errors='ignore')

    # === МАСШТАБИРОВАНИЕ ТОЛЬКО ЧИСЛОВЫХ ПРИЗНАКОВ (БЕЗ label_encoded!) ===
    # Масштабирование числовых признаков
    # numeric_cols = df.select_dtypes(include=['int64', 'float64']).columns
    # numeric_cols = numeric_cols.drop('label_encoded', errors='ignore')  # Исключаем label_encoded

    # === УДАЛЕНИЕ НЕЧИСЛОВЫХ КОЛОНОК ===
    non_numeric_cols = df.select_dtypes(exclude=['int64', 'float64']).columns
    df = df.drop(columns=non_numeric_cols, errors='ignore')
    logging.info(f"Удалены нечисловые колонки: {list(non_numeric_cols)}")

    # === МАСШТАБИРОВАНИЕ ТОЛЬКО ЧИСЛОВЫХ ===
    numeric_cols = df.select_dtypes(include=['int64', 'float64']).columns
    numeric_cols = numeric_cols.drop('label_encoded', errors='ignore')

    if scaler_type == 'minmax':
        scaler = MinMaxScaler()
    else:
        scaler = StandardScaler()

    if len(numeric_cols) > 0:
        df[numeric_cols] = scaler.fit_transform(df[numeric_cols])
        logging.info(f"Масштабирование (minmax) для {len(numeric_cols)} числовых колонок")
    else:
        logging.warning("Нет числовых колонок для масштабирования")


    # Feature engineering (как было + унификация)
    if 'flow_duration' in df and 'packet_count' in df:
        df['error_rate'] = df['packet_count'] / df['flow_duration'].clip(lower=1)
        logging.info("Добавлен feature: error_rate")

    # Сохранение обработанных данных
    base_name = os.path.basename(input_file).replace('.csv', '_processed.csv')
    output_path = os.path.join(output_dir, base_name)
    df.to_csv(output_path, index=False)
    logging.info(f"Обработанные данные сохранены в {output_path}")

    # Формирование features/label и split
    if 'label_encoded' in df:
        X = df.drop(['label', 'label_encoded'], axis=1, errors='ignore')  # Features
        y = df['label_encoded']  # Label
    else:
        X = df.copy()
        y = None
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=test_size, random_state=42, stratify=y) if y is not None else (None, None, None, None)
    logging.info(f"Train/test split: {len(X_train) if X_train is not None else 0} / {len(X_test) if X_test is not None else 0} строк")

    return {'X_train': X_train, 'X_test': X_test, 'y_train': y_train, 'y_test': y_test, 'processed_df': df}

if __name__ == "__main__":
    # Тест: укажи свой файл
    input_file = 'data/collected_traffic.csv'  # Или simulated_traffic.csv
    result = preprocess_data(input_file)
    print("Первые строки processed:", result['processed_df'].head())