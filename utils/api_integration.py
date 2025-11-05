# utils/api_integration.py
import requests
import time
import logging
from modules.database import SessionLocal
from sqlalchemy import Column, Integer, String, Float, DateTime
from sqlalchemy.ext.declarative import declarative_base
import os
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.INFO)

Base = declarative_base()


class IPCache(Base):
    __tablename__ = 'ip_cache'
    ip = Column(String, primary_key=True)
    reputation = Column(Float)
    last_check = Column(DateTime)
    source = Column(String)


# Создаём таблицу
engine = SessionLocal().get_bind()
Base.metadata.create_all(engine)

# --- КОНФИГ (добавь в .env позже) ---
ABUSEIPDB_KEY = os.getenv('ABUSEIPDB_KEY', 'YOUR_KEY')
VT_KEY = os.getenv('VT_KEY', 'YOUR_KEY')
CACHE_DAYS = 7


# --- ФУНКЦИИ ---
def get_abuseipdb(ip):
    session = SessionLocal()
    try:
        # Кэш
        cached = session.query(IPCache).filter(IPCache.ip == ip).first()
        if cached and (datetime.utcnow() - cached.last_check).days < CACHE_DAYS:
            return cached.reputation

        url = f"https://api.abuseipdb.com/api/v2/check"
        headers = {'Key': ABUSEIPDB_KEY, 'Accept': 'application/json'}
        params = {'ipAddress': ip, 'maxAgeInDays': 90}

        response = requests.get(url, headers=headers, params=params, timeout=10)
        if response.status_code == 200:
            score = response.json()['data']['abuseConfidenceScore']
            # Сохраняем
            if cached:
                cached.reputation = score
                cached.last_check = datetime.utcnow()
                cached.source = 'abuseipdb'
            else:
                session.add(IPCache(ip=ip, reputation=score, last_check=datetime.utcnow(), source='abuseipdb'))
            session.commit()
            return score
        else:
            logging.warning(f"AbuseIPDB error {response.status_code}: {response.text}")
            return None
    except Exception as e:
        logging.error(f"AbuseIPDB error: {e}")
        return None
    finally:
        session.close()


def enrich_alert_with_reputation(alert_type, probability, source_ip=None):
    if not source_ip:
        return probability

    rep = get_abuseipdb(source_ip)
    if rep is not None:
        # Комбинируем: если IP плохой — повышаем приоритет
        adjusted = min(probability + rep / 200, 1.0)
        logging.info(f"IP {source_ip} репутация {rep}% → вероятность {probability:.2f} → {adjusted:.2f}")
        return adjusted
    return probability