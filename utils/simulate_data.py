import pandas as pd
import numpy as np
import os
from faker import Faker

def generate_simulated_data(num_rows: int = 5000, output_path: str = "../data/simulated_traffic.csv") -> pd.DataFrame:
    """Генерирует синтетические данные трафика для тестирования."""
    fake = Faker()
    data = []

    for _ in range(num_rows):
        timestamp = fake.date_time_this_year()
        source_ip = fake.ipv4()
        dest_port = np.random.randint(1, 65535)
        packet_count = np.random.randint(1, 1000)
        http_method = np.random.choice(['GET', 'POST', 'HEAD', None], p=[0.3, 0.3, 0.2, 0.2])
        label = np.random.choice(['Normal Traffic', 'DDoS', 'PortScan', 'Brute_Force'], p=[0.6, 0.2, 0.1, 0.1])

        flow_duration = np.random.randint(100, 2000000)
        tot_fwd_pkts = np.random.randint(1, 50)
        tot_len_fwd_pkts = np.random.randint(100, 5000)

        data.append({
            'timestamp': timestamp,
            'source_ip': source_ip,
            'dest_port': dest_port,
            'packet_count': packet_count,
            'http_method': http_method,
            'label': label,
            'flow_duration': flow_duration,
            'tot_fwd_pkts': tot_fwd_pkts,
            'tot_len_fwd_pkts': tot_len_fwd_pkts
        })

    df = pd.DataFrame(data)
    df['timestamp'] = pd.to_datetime(df['timestamp'])

    # Сохранение
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    df.to_csv(output_path, index=False)
    print(f"Симулированные данные сохранены в {output_path}")
    print("Информация (info):")
    print(df.info())
    print("\nПервые 5 строк:")
    print(df.head())

    return df

def main():
    """Запуск генерации симулированных данных."""
    try:
        generate_simulated_data()
    except Exception as e:
        print("Ошибка при генерации данных:", e)

if __name__ == "__main__":
    main()