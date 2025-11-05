import sqlite3
import pandas as pd
from config import DB_PATH
import os

def init_db():
    """Инициализация БД."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS traffic_logs (
            id INTEGER PRIMARY KEY,
            timestamp DATETIME,
            source_ip TEXT,
            dest_port INTEGER,
            packet_count INTEGER,
            http_method TEXT,
            label TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY,
            timestamp DATETIME,
            alert_type TEXT,
            probability FLOAT,
            description TEXT
        )
    ''')
    conn.commit()
    conn.close()
    print("БД инициализирована:", DB_PATH)

def insert_logs(df: pd.DataFrame):
    """Вставка логов в БД."""
    conn = sqlite3.connect(DB_PATH)
    df.to_sql('traffic_logs', conn, if_exists='append', index=False)
    conn.close()
    print("Логи вставлены в БД.")

if __name__ == "__main__":
    init_db()