import pandas as pd
import numpy as np
import os

def process_mscad(input_path: str = "../data/mscad_sample.csv", output_path: str = "../data/mscad_processed.csv") -> pd.DataFrame:
    """Обрабатывает MSCAD датасет: добавляет timestamp, IP, порт и проверяет баланс."""
    df = pd.read_csv(input_path, low_memory=False)
    df.columns = [col.strip("'") for col in df.columns]
    df['timestamp'] = pd.to_datetime('2025-10-12') + pd.to_timedelta(df["Flow Duration"], unit='ms')
    df['source_ip'] = [f"192.168.1.{i}" for i in range(len(df))]
    df['dest_port'] = np.random.randint(1, 65535, len(df))

    print("Информация (info):")
    print(df.info())
    print(f"\nБаланс Label: {df['Label'].value_counts()}")

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    df.to_csv(output_path, index=False)
    print(f"Сохранено обработанное: {output_path}")
    return df

def process_cicids2017(input_path: str = "../data/cicids2017_sample.csv", output_path: str = "../data/cicids2017_processed.csv") -> pd.DataFrame:
    """Обрабатывает CICIDS2017 датасет: добавляет timestamp и IP."""
    df = pd.read_csv(input_path, low_memory=False)
    df['timestamp'] = pd.to_datetime('2025-10-12') + pd.to_timedelta(df['Flow Duration'], unit='ms')
    df['source_ip'] = [f"192.168.1.{i % 256}" for i in range(len(df))]

    print("Информация (info):")
    print(df.info())
    print(f"\nБаланс Attack Type: {df['Attack Type'].value_counts()}")

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    df.to_csv(output_path, index=False)
    print(f"Сохранено обработанное: {output_path}")
    return df

def process_csic2010(input_path: str = "../data/csic2010_sample.csv", output_path: str = "../data/csic2010_processed.csv") -> pd.DataFrame:
    """Обрабатывает CSIC2010 датасет: добавляет timestamp, IP, порт и удаляет лишний столбец."""
    df = pd.read_csv(input_path, low_memory=False)
    df['timestamp'] = pd.date_range(start='2025-10-12', periods=len(df), freq='T')
    df = df.drop(columns=['Unnamed: 0'])
    df['source_ip'] = [f"192.168.1.{i % 256}" for i in range(len(df))]
    df['dest_port'] = 80

    print("Информация (info):")
    print(df.info())
    print(f"\nБаланс classification: {df['classification'].value_counts()}")

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    df.to_csv(output_path, index=False)
    print(f"Сохранено обработанное: {output_path}")
    return df

def main():
    """Запуск обработки всех датасетов."""
    try:
        process_mscad()
        process_cicids2017()
        process_csic2010()
    except Exception as e:
        print("Ошибка при обработке данных:", e)

if __name__ == "__main__":
    main()