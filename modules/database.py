from __future__ import annotations

import os
from contextlib import contextmanager
from datetime import datetime, timedelta
from typing import Any, Dict, Iterable, List, Optional, Tuple

import pandas as pd
from sqlalchemy import Column, DateTime, Float, Integer, String, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from config import DB_PATH

# -----------------------------
# Инициализация БД
# -----------------------------

os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

# Для SQLite + многопоточности (Flask/Celery) лучше отключать check_same_thread.
engine = create_engine(
    f"sqlite:///{DB_PATH}",
    echo=False,
    connect_args={"check_same_thread": False},
)

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

ALERT_STATUSES = {"new", "acknowledged", "false_positive", "ignored"}


# -----------------------------
# ORM-модели
# -----------------------------

class Alert(Base):
    """Таблица алертов (alerts).

    Хранит выявленные угрозы (классификатор + детектор аномалий) для API/дашборда.
    """

    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=True)
    alert_type = Column(String, nullable=False)
    probability = Column(Float, nullable=False)
    source_ip = Column(String, nullable=True)
    status = Column(String, default="new", nullable=True)  # new, acknowledged, false_positive


class IpCache(Base):
    """Кэш репутации IP (ip_cache).

    Используется модулями TI-интеграции (например, AbuseIPDB) для уменьшения количества запросов.
    """

    __tablename__ = "ip_cache"

    ip = Column(String, primary_key=True)
    reputation = Column(Float, nullable=True)  # например, abuseConfidenceScore (0..100)
    last_check = Column(DateTime, nullable=True)
    source = Column(String, nullable=True)  # "abuseipdb", "virustotal" и т.п.


class TrafficLog(Base):
    """Лог наблюдаемого трафика (traffic_logs).

    Таблица нужна для:
    - последующего анализа/визуализации на дашборде,
    - расширения ВКР до “журнала событий”,
    - возможного обучения baseline на исторических данных.

    Важно: это упрощённая схема, достаточная для демонстрации и развития проекта.
    """

    __tablename__ = "traffic_logs"

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=True)

    source_ip = Column(String, nullable=True)
    dest_ip = Column(String, nullable=True)

    protocol = Column(Integer, nullable=True)   # 6=TCP, 17=UDP и т.д.
    src_port = Column(Integer, nullable=True)
    dest_port = Column(Integer, nullable=True)

    packet_len = Column(Integer, nullable=True)
    ttl = Column(Integer, nullable=True)
    tcp_flags = Column(Integer, nullable=True)

    http_method = Column(String, nullable=True)
    mode = Column(String, nullable=True)  # real/demo/test/dataset


def init_db() -> None:
    """Создаёт таблицы (если их ещё нет)."""
    Base.metadata.create_all(engine)


init_db()


# -----------------------------
# Утилиты работы с сессией
# -----------------------------

@contextmanager
def session_scope():
    """Контекстный менеджер для транзакции.

    Пример:
        with session_scope() as s:
            s.add(...)
    """
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


# -----------------------------
# Alerts API
# -----------------------------

def save_alert(alert_type: str, probability: float, source_ip: Optional[str] = None, status: str = "new") -> int:
    """Сохраняет один алерт в базе данных.

    Args:
        alert_type: Категория алерта (например, "Brute Force", "Anomaly").
        probability: Риск/вероятность (0..1).
        source_ip: Исходный IP (опционально).
        status: Статус алерта (new/acknowledged/false_positive).

    Returns:
        ID созданного алерта.
    """
    if status == "ignored":
        status = "false_positive"
    if status not in ALERT_STATUSES:
        status = "new"

    with session_scope() as session:
        alert = Alert(alert_type=alert_type, probability=float(probability), source_ip=source_ip, status=status)
        session.add(alert)
        session.flush()  # получаем id без session.refresh
        return int(alert.id)


def get_alerts(
    alert_type: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    status: Optional[str] = None,
) -> List[Alert]:
    """Возвращает список алертов для API/дашборда.

    Args:
        alert_type: Если задано — фильтрация по точному типу.
        limit: Максимальное число записей.
        offset: Смещение для пагинации.
        status: Если задано — фильтрация по статусу.

    Returns:
        Список алертов, отсортированный по времени (сначала новые).
    """
    session = SessionLocal()
    try:
        q = session.query(Alert).order_by(Alert.timestamp.desc())
        if alert_type:
            q = q.filter(Alert.alert_type == alert_type)
        if status:
            q = q.filter(Alert.status == status)
        return q.offset(int(offset)).limit(int(limit)).all()
    finally:
        session.close()


def update_alert_status(alert_id: int, status: str) -> bool:
    """Обновляет статус алерта.

    Args:
        alert_id: ID алерта.
        status: Один из статусов: new, acknowledged, false_positive.

    Returns:
        True, если алерт найден и статус обновлён, иначе False.

    Raises:
        ValueError: Если передан статус вне допустимого набора.
    """
    if status == "ignored":
        status = "false_positive"
    if status not in ALERT_STATUSES:
        raise ValueError(f"Некорректный статус '{status}'. Допустимо: {sorted(ALERT_STATUSES)}")

    with session_scope() as session:
        alert = session.query(Alert).filter(Alert.id == int(alert_id)).one_or_none()
        if alert is None:
            return False
        alert.status = status
        return True


def purge_alerts(
    *,
    keep_last: Optional[int] = None,
    older_than_days: Optional[int] = None,
    status: Optional[str] = None,
) -> int:
    """Очищает алерты по правилам (для отладки/демонстрации).

    Варианты:
    - keep_last=N: оставить только N последних алертов, остальные удалить.
    - older_than_days=D: удалить алерты старше D дней.
    - status="new|acknowledged|false_positive": удалить только с указанным статусом.

    Args:
        keep_last: Сколько последних алертов оставить.
        older_than_days: Удалять всё старше указанного числа дней.
        status: Ограничение по статусу.

    Returns:
        Количество удалённых записей.
    """
    deleted = 0
    with session_scope() as session:
        q = session.query(Alert)

    if status:
        if status == "ignored":
            status = "false_positive"
        q = q.filter(Alert.status == status)

        if older_than_days is not None:
            border = datetime.utcnow() - timedelta(days=int(older_than_days))
            q = q.filter(Alert.timestamp < border)

        if keep_last is not None:
            keep_last = int(keep_last)
            # Получаем id последних N
            ids = (
                session.query(Alert.id)
                .order_by(Alert.timestamp.desc())
                .limit(keep_last)
                .all()
            )
            keep_ids = {i[0] for i in ids}
            if keep_ids:
                q = q.filter(~Alert.id.in_(keep_ids))

        deleted = q.delete(synchronize_session=False)

    return int(deleted)


# -----------------------------
# IP cache API
# -----------------------------

def get_ip_reputation(ip: str) -> Optional[Tuple[float, datetime, Optional[str]]]:
    """Возвращает кэш репутации IP, если он есть.

    Args:
        ip: IP-адрес.

    Returns:
        (reputation, last_check, source) или None.
    """
    session = SessionLocal()
    try:
        row = session.query(IpCache).filter(IpCache.ip == ip).one_or_none()
        if row is None or row.reputation is None or row.last_check is None:
            return None
        return float(row.reputation), row.last_check, row.source
    finally:
        session.close()


def upsert_ip_reputation(ip: str, reputation: float, *, source: str, checked_at: Optional[datetime] = None) -> None:
    """Создаёт/обновляет запись репутации IP в кэше.

    Args:
        ip: IP-адрес.
        reputation: Значение репутации (обычно 0..100).
        source: Источник ("abuseipdb", ...).
        checked_at: Время проверки (UTC). Если None — datetime.utcnow().
    """
    checked_at = checked_at or datetime.utcnow()
    with session_scope() as session:
        row = session.query(IpCache).filter(IpCache.ip == ip).one_or_none()
        if row is None:
            session.add(IpCache(ip=ip, reputation=float(reputation), last_check=checked_at, source=str(source)))
        else:
            row.reputation = float(reputation)
            row.last_check = checked_at
            row.source = str(source)


# -----------------------------
# Traffic logs API
# -----------------------------

def save_traffic_logs(df: pd.DataFrame, *, mode: Optional[str] = None) -> int:
    """Сохраняет пачку строк трафика в traffic_logs.

    Функция специально “мягкая”: если каких-то колонок нет — они будут сохранены как NULL.

    Args:
        df: DataFrame с колонками, похожими на output collect_traffic().
        mode: Режим (real/demo/test/dataset), будет записан в каждую строку.

    Returns:
        Количество сохранённых строк.
    """
    if df is None or df.empty:
        return 0

    cols = set(df.columns)

    def _get(row: Any, name: str) -> Any:
        """Безопасно получает значение из строки DataFrame."""
        return row[name] if name in cols else None

    count = 0
    with session_scope() as session:
        for _, row in df.iterrows():
            ts = _get(row, "timestamp")
            if isinstance(ts, str):
                try:
                    ts = datetime.fromisoformat(ts)
                except Exception:
                    ts = datetime.utcnow()

            item = TrafficLog(
                timestamp=ts if isinstance(ts, datetime) else datetime.utcnow(),
                source_ip=str(_get(row, "source_ip")) if _get(row, "source_ip") is not None else None,
                dest_ip=str(_get(row, "dest_ip")) if _get(row, "dest_ip") is not None else None,
                protocol=int(_get(row, "protocol")) if _get(row, "protocol") is not None else None,
                src_port=int(_get(row, "src_port")) if _get(row, "src_port") is not None else None,
                dest_port=int(_get(row, "dest_port")) if _get(row, "dest_port") is not None else None,
                packet_len=int(_get(row, "packet_len")) if _get(row, "packet_len") is not None else None,
                ttl=int(_get(row, "ttl")) if _get(row, "ttl") is not None else None,
                tcp_flags=int(_get(row, "tcp_flags")) if _get(row, "tcp_flags") is not None else None,
                http_method=str(_get(row, "http_method")) if _get(row, "http_method") is not None else None,
                mode=str(mode) if mode is not None else None,
            )
            session.add(item)
            count += 1

    return count


def get_traffic_logs(
    *,
    limit: int = 100,
    offset: int = 0,
    source_ip: Optional[str] = None,
) -> List[TrafficLog]:
    """Возвращает записи traffic_logs для будущего UI.

    Args:
        limit: Максимальное число строк.
        offset: Смещение для пагинации.
        source_ip: Фильтр по source_ip.

    Returns:
        Список TrafficLog, отсортированный по времени (сначала новые).
    """
    session = SessionLocal()
    try:
        q = session.query(TrafficLog).order_by(TrafficLog.timestamp.desc())
        if source_ip:
            q = q.filter(TrafficLog.source_ip == source_ip)
        return q.offset(int(offset)).limit(int(limit)).all()
    finally:
        session.close()
