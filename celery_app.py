from __future__ import annotations

import logging
import os
from collections import Counter
from typing import Any, Dict, List

from celery import Celery

import config as cfg
from modules.pipeline import PreVisorPipeline
from modules.database import save_alert
from utils.notifications import notify_new_alert, notify_pipeline_summary

logger = logging.getLogger(__name__)
if not logging.getLogger().handlers:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


def _broker_url() -> str:
    """Возвращает URL брокера Celery с приоритетом env."""
    return (
        os.getenv("CELERY_BROKER_URL")
        or getattr(cfg, "CELERY_BROKER_URL", None)
        or "redis://localhost:6379/0"
    )


celery = Celery(
    "previsor",
    broker=_broker_url(),
    include=["celery_app"],
)

celery.conf.broker_connection_retry_on_startup = True


def _get_alert_type(a: Dict[str, Any]) -> str:
    """Нормализует ключи типа алерта, чтобы не зависеть от формата пайплайна."""
    return str(a.get("alert_type") or a.get("type") or "Unknown")


@celery.task(name="previsor.full_pipeline")
def full_pipeline(model_type: str = "rf") -> Dict[str, Any]:
    """Запускает полный пайплайн PreVisor и сохраняет найденные алерты в БД."""
    mode = getattr(cfg, "MODE", os.getenv("PREVISOR_MODE", "demo"))
    pipeline = PreVisorPipeline(model_type=model_type)
    result = pipeline.run(mode=mode)

    alert_rows: List[Dict[str, Any]] = [a for a in (result.alerts or []) if int(a.get("alert", 0)) == 1]

    new_alerts = 0
    for a in alert_rows:
        alert_type = _get_alert_type(a)
        prob = float(a.get("probability", 0.0) or 0.0)
        ip = a.get("source_ip")
        save_alert(alert_type=alert_type, probability=prob, source_ip=ip)
        new_alerts += 1

    max_notifs = int(os.getenv("MAX_TELEGRAM_ALERTS_PER_RUN", "5"))
    top_alerts = sorted(alert_rows, key=lambda x: float(x.get("probability", 0.0) or 0.0), reverse=True)

    sent = 0
    for a in top_alerts[:max_notifs]:
        try:
            notify_new_alert(_get_alert_type(a), float(a.get("probability", 0.0) or 0.0), a.get("source_ip"))
            sent += 1
        except Exception:
            logger.exception("Notification error (notify_new_alert)")

    try:
        top_types = Counter(_get_alert_type(a) for a in alert_rows).most_common(5)
        max_prob = float(top_alerts[0].get("probability", 0.0) or 0.0) if top_alerts else None
        notify_pipeline_summary(
            model_type=model_type,
            total_alerts=len(result.alerts or []),
            new_alerts=new_alerts,
            telegram_sent=sent,
            top_types=top_types,
            max_probability=max_prob,
        )
    except Exception:
        logger.exception("Notification error (notify_pipeline_summary)")

    logger.info("Celery full_pipeline: mode=%s new_alerts=%s total=%s telegram_sent=%s", mode, new_alerts, len(result.alerts or []), sent)
    return {"new_alerts": new_alerts, "total_alerts": len(result.alerts or []), "telegram_sent": sent}


celery.conf.beat_schedule = {
    "full-pipeline-every-interval": {
        "task": "previsor.full_pipeline",
        "schedule": getattr(cfg, "COLLECTION_INTERVAL", 300),
    }
}
