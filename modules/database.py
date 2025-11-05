from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, '..', 'db', 'previsor.db')
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

engine = create_engine(f'sqlite:///{DB_PATH}', echo=False)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()


class Alert(Base):
    __tablename__ = 'alerts'

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    alert_type = Column(String, nullable=False)
    probability = Column(Float, nullable=False)
    source_ip = Column(String)
    status = Column(String, default='new')  # new, acknowledged, false_positive


Base.metadata.create_all(engine)


def save_alert(alert_type, probability, source_ip=None):
    session = SessionLocal()
    try:
        alert = Alert(
            alert_type=alert_type,
            probability=probability,
            source_ip=source_ip
        )
        session.add(alert)
        session.commit()
        return alert.id
    except Exception as e:
        session.rollback()
        raise e
    finally:
        session.close()


def get_alerts(alert_type=None, limit=50, offset=0):
    session = SessionLocal()
    try:
        query = session.query(Alert).order_by(Alert.timestamp.desc())
        if alert_type:
            query = query.filter(Alert.alert_type == alert_type)
        return query.offset(offset).limit(limit).all()
    finally:
        session.close()