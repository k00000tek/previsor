import os

# Режим работы: 'real' для реального сбора, 'test' для датасетов/симуляции
MODE = 'test'  # Изменить на 'real' для продакшена
# MODE = 'real'
# Пути
DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), 'data'))
DB_PATH = os.path.join(os.path.dirname(__file__), 'db', 'previsor.db')  # SQLite DB

# Scapy настройки (для real mode)
NETWORK_INTERFACE = 'Ethernet 4'  # Проверь: from scapy.all import get_if_list; print(get_if_list())
PACKET_COUNT_PER_COLLECTION = 100  # Сколько пакетов захватывать за раз

# Другие параметры
COLLECTION_INTERVAL = 600  # Секунды между сборами (для scheduler)

CELERY_BROKER_URL = 'redis://localhost:6379/0'

PROCESSED_DATA_DIR = DATA_DIR  # 'data'
SCALER_TYPE = 'minmax'  # По умолчанию
