import pandas as pd
import numpy as np
import os
from scapy.all import Packet, RandIP, RandShort, sniff
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.http import HTTPRequest
import time
from config import MODE, NETWORK_INTERFACE, PACKET_COUNT_PER_COLLECTION, COLLECTION_INTERVAL, DATA_DIR
from faker import Faker
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

fake = Faker()


def collect_real_traffic(num_packets=PACKET_COUNT_PER_COLLECTION) -> pd.DataFrame:
    """Захват реального трафика с сети с помощью Scapy (существующая функция)."""
    data = []

    def packet_handler(pkt):
        if IP in pkt:
            timestamp = time.time()
            source_ip = pkt[IP].src
            if TCP in pkt:
                dest_port = pkt[TCP].dport
            elif UDP in pkt:
                dest_port = pkt[UDP].dport
            else:
                dest_port = None
            packet_count = 1
            http_method = None
            if HTTPRequest in pkt:
                http_method = pkt[HTTPRequest].Method.decode() if pkt[HTTPRequest].Method else None
            data.append({
                'timestamp': pd.to_datetime(timestamp, unit='s'),
                'source_ip': source_ip,
                'dest_port': dest_port,
                'packet_count': packet_count,
                'http_method': http_method,
                'label': 'Unknown'
            })
            logging.info(f"Захвачен пакет: {source_ip}:{dest_port} ({http_method})")

    logging.info(f"Захват реального трафика с {NETWORK_INTERFACE} ({num_packets} пакетов)...")
    sniff(iface=NETWORK_INTERFACE, prn=packet_handler, count=num_packets, timeout=30)
    df = pd.DataFrame(data)
    return df


def collect_simulated_traffic(num_packets=100, port_range=(1, 65535), ip_range='192.168.1.') -> pd.DataFrame:
    """Генерация симулированных сетевых пакетов с Scapy и Faker."""
    data = []
    for _ in range(num_packets):
        # Генерация IP вручную
        src_ip = fake.ipv4()
        dst_ip = f"{ip_range}{np.random.randint(1, 255)}"

        # Протокол
        proto = np.random.choice([TCP, UDP])
        src_port = np.random.randint(1024, 65535)
        dst_port = np.random.randint(port_range[0], port_range[1])

        # Создаём пакет
        pkt = IP(src=src_ip, dst=dst_ip) / proto(sport=src_port, dport=dst_port)

        # Добавляем HTTP для части пакетов
        http_method = None
        if np.random.random() < 0.3:  # 30% шанс на HTTP
            http_method = np.random.choice(['GET', 'POST', 'HEAD'])
            pkt = pkt / HTTPRequest(Method=http_method)

        timestamp = fake.date_time_this_year()
        source_ip = pkt[IP].src
        dest_port = pkt[proto].dport
        packet_count = 1  # Симулируем по одному
        label = np.random.choice(['Normal Traffic', 'DDoS', 'PortScan', 'Brute_Force'], p=[0.6, 0.2, 0.1, 0.1])

        data.append({
            'timestamp': timestamp,
            'source_ip': source_ip,
            'dest_port': dest_port,
            'packet_count': packet_count,
            'http_method': http_method,
            'label': label
        })
        logging.info(f"Симулирован пакет: {source_ip}:{dest_port} ({http_method}, label={label})")

    df = pd.DataFrame(data)
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    return df


def collect_traffic(
        mode='simulated',
        num_packets=100,
        port_range=(1, 65535),
        ip_range='192.168.1.',
        include_labels=False,
        save_csv=True
) -> pd.DataFrame:
    """
    Универсальная функция сбора данных.

    mode: 'real', 'simulated', 'test'
    include_labels: Только для 'simulated' и 'test' — для оценки
    """
    if mode == 'real':
        df = collect_real_traffic(num_packets)
        # В реальном режиме — МЕТОК НЕТ
        if 'label' in df.columns:
            df = df.drop(columns=['label'])

    elif mode == 'simulated':
        df = collect_simulated_traffic(num_packets, port_range, ip_range)
        # Метки — только если нужно
        if not include_labels and 'label' in df.columns:
            df = df.drop(columns=['label'])

    elif mode == 'test':
        df = load_test_data()  # из cicids2017_processed.csv
        if not include_labels and 'label' in df.columns:
            df = df.drop(columns=['label'])

    else:
        raise ValueError("mode: 'real', 'simulated' или 'test'")

    # Сохранение
    if save_csv:
        filename = {
            'real': 'collected_traffic.csv',
            'simulated': 'simulated_traffic.csv',
            'test': 'test_traffic.csv'
        }[mode]
        output_path = os.path.join(DATA_DIR, filename)
        df.to_csv(output_path, index=False)
        logging.info(f"Данные сохранены: {output_path}")

    return df

def load_test_data(dataset_type: str = 'cicids2017') -> pd.DataFrame:
    """Загрузка тестовых данных из CSV."""
    paths = {
        'cicids2017': os.path.join(DATA_DIR, 'cicids2017_processed.csv'),
        'mscad': os.path.join(DATA_DIR, 'mscad_processed.csv'),
        'csic2010': os.path.join(DATA_DIR, 'csic2010_processed.csv'),
        'simulated': os.path.join(DATA_DIR, 'simulated_traffic.csv')
    }
    path = paths.get(dataset_type, paths['simulated'])
    print(f"Загрузка тестовых данных из {path}...")
    df = pd.read_csv(path)
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    return df.sample(frac=0.1)  # Обрезаем для скорости тестов

def collect_data(mode: str = MODE) -> pd.DataFrame:
    """Основная функция сбора данных с переключателем режимов."""
    if mode == 'real':
        return collect_real_traffic()
    elif mode == 'test':
        return load_test_data('cicids2017')  # Или другой по умолчанию
    else:
        raise ValueError("Неверный режим: используй 'real' или 'test'")

def run_collector():
    """Запуск сбора по расписанию."""
    while True:
        df = collect_data()
        # Здесь вызов предобработки и сохранения в DB (добавим в Шаг 3)
        print("Данные собраны:", df.head())
        time.sleep(COLLECTION_INTERVAL)

if __name__ == "__main__":
    collect_traffic(mode='simulated', num_packets=50)