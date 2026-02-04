from __future__ import annotations

import logging
import os
import threading
import time
from collections import Counter
from typing import Any, Dict, Optional, List

from flask import Flask, jsonify, render_template, request
from werkzeug.utils import secure_filename

import config as cfg
from modules.data_collector import collect_traffic, list_network_interfaces
from modules.database import get_alerts, save_alert, update_alert_status, purge_alerts
from modules.pipeline import PreVisorPipeline

# Telegram-уведомления (может быть отключено/отсутствовать в минимальном окружении).
try:  # pragma: no cover
    from utils.notifications import notify_new_alert, notify_pipeline_summary
except Exception:  # pragma: no cover
    notify_new_alert = None  # type: ignore
    notify_pipeline_summary = None  # type: ignore

logger = logging.getLogger(__name__)
if not logging.getLogger().handlers:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

app = Flask(__name__)

_monitor_thread: Optional[threading.Thread] = None
_monitor_stop = threading.Event()


def _start_auto_monitor() -> None:
    """Запускает фоновый мониторинг, если он еще не запущен."""
    global _monitor_thread
    if _monitor_thread and _monitor_thread.is_alive():
        return

    def _loop() -> None:
        model = os.getenv("PREVISOR_MODEL", "rf").strip().lower()
        mode = os.getenv("PREVISOR_MODE", getattr(cfg, "MODE", "real")).strip().lower()
        interval = int(os.getenv("PREVISOR_AUTO_MONITOR_INTERVAL", str(getattr(cfg, "COLLECTION_INTERVAL", 300))))
        pipeline = PreVisorPipeline(model_type=model)
        logger.info("Auto monitor started: mode=%s model=%s interval=%ss", mode, model, interval)
        while not _monitor_stop.is_set():
            try:
                pipeline.run(mode=mode, model_type=model)
            except Exception:
                logger.exception("Auto monitor run failed")
            _monitor_stop.wait(max(5, int(interval)))

    _monitor_thread = threading.Thread(target=_loop, name="previsor-auto-monitor", daemon=True)
    _monitor_thread.start()


def _env_bool(name: str, default: bool) -> bool:
    """Читает булеву переменную окружения.

    Args:
        name: Имя переменной окружения.
        default: Значение по умолчанию.

    Returns:
        Булево значение.
    """
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "y", "on"}


def _parse_bool(value: Optional[str]) -> bool:
    """Преобразует строку query-параметра в bool.

    Поддерживаемые значения: 1/0, true/false, yes/no, on/off.

    Args:
        value: Значение query-параметра.

    Returns:
        True, если значение интерпретируется как истина.
    """
    if value is None:
        return False
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}


def _project_root() -> str:
    """Возвращает путь к корню проекта (где лежит app.py)."""
    return os.path.dirname(os.path.abspath(__file__))


def _get_data_dir() -> str:
    """Возвращает runtime директорию данных.

    Приоритет:
      1) cfg.DATA_DIR
      2) env PREVISOR_DATA_DIR
      3) ./data/runtime (внутри репозитория)

    Returns:
        Путь к data/runtime.
    """
    data_dir = getattr(cfg, "DATA_DIR", None) or os.getenv("PREVISOR_DATA_DIR")
    if data_dir:
        return data_dir
    return os.path.join(_project_root(), "data", "runtime")


DEV_ENDPOINTS_ENABLED = _env_bool("PREVISOR_ENABLE_DEV_ENDPOINTS", True)
DEV_UI_ENABLED = _env_bool("PREVISOR_ENABLE_DEV_UI", False)
AUTO_MONITOR_ENABLED = _env_bool("PREVISOR_AUTO_MONITOR", True)


@app.route("/health")
def health():
    """Healthcheck для Docker/оркестрации."""
    return jsonify({"status": "OK"})


@app.route("/interfaces")
def interfaces():
    """Возвращает список сетевых интерфейсов (для настройки PREVISOR_NET_IFACE)."""
    details = list_network_interfaces(details=True)
    if details:
        return jsonify(details)
    return jsonify(list_network_interfaces())


@app.route("/monitor/status")
def monitor_status():
    """Возвращает статус фонового мониторинга."""
    running = bool(_monitor_thread and _monitor_thread.is_alive())
    interval = int(os.getenv("PREVISOR_AUTO_MONITOR_INTERVAL", str(getattr(cfg, "COLLECTION_INTERVAL", 300))))
    return jsonify(
        {
            "running": running,
            "interval_sec": int(interval),
        }
    )


@app.route("/")
def index():
    """Главная страница: рендерим дашборд."""
    return render_template("dashboard.html", enable_dev_ui=DEV_UI_ENABLED)


@app.route("/dashboard")
def dashboard():
    """Рендерит HTML-дашборд."""
    return render_template("dashboard.html", enable_dev_ui=DEV_UI_ENABLED)


@app.route("/collect", methods=["GET"])
def collect_endpoint():
    """Собирает порцию трафика и сохраняет её в runtime CSV (по умолчанию).

    Query параметры:
        mode: real|demo|test|dataset (по умолчанию берётся из PREVISOR_MODE)
        rows: размер порции для demo/test/dataset (по умолчанию PREVISOR_DEMO_ROWS)
        source: mixed|cicids2017|csic2010|mscad|simulated (для demo/test)
        dataset: имя processed датасета (для mode=dataset)

    Returns:
        JSON со статусом и количеством строк.
    """
    mode = (request.args.get("mode") or getattr(cfg, "MODE", "demo")).strip().lower()
    rows = int(request.args.get("rows") or getattr(cfg, "DEMO_ROWS", 1200))
    source = (request.args.get("source") or getattr(cfg, "DEMO_SOURCE", "mixed")).strip().lower()
    dataset_name = (request.args.get("dataset") or getattr(cfg, "DATASET_NAME", "cicids2017_processed.csv")).strip()

    baseline = _parse_bool(request.args.get("baseline"))

    if mode == "simulated":
        mode = "demo"
        source = "simulated"

    collect_kwargs: Dict[str, Any] = {
        "mode": mode,
        "save_csv": True,
        "baseline": baseline,
        "demo_source": source,
        "dataset_name": dataset_name,
    }

    # В real интерпретируем rows как число пакетов за сбор.
    if mode == "real":
        collect_kwargs["num_packets"] = int(rows)
    else:
        collect_kwargs["demo_rows"] = int(rows)

    try:
        df = collect_traffic(**collect_kwargs)  # type: ignore[arg-type]
    except ValueError as exc:
        logger.exception("Ошибка /collect (ValueError)")
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:
        logger.exception("Ошибка /collect")
        return jsonify({"error": str(exc)}), 500

    target_csv = None
    if baseline:
        target_csv = getattr(cfg, "BASELINE_TRAFFIC_CSV", None)
    else:
        target_csv = getattr(cfg, "COLLECTED_TRAFFIC_CSV", None)

    warning = None
    if int(len(df)) == 0 and mode == "real":
        warning = "no_packets_captured"
    return jsonify(
        {
            "status": "OK",
            "mode": mode,
            "baseline": bool(baseline),
            "rows": int(len(df)),
            "csv": target_csv,
            "warning": warning,
        }
    )


@app.route("/preprocess", methods=["GET"])
def preprocess_endpoint():
    """Запускает предобработку для CSV.

    Query параметры:
        file: путь к CSV (по умолчанию data/runtime/collected_traffic.csv)

    Returns:
        JSON со статусом и количеством строк после предобработки.
    """
    file_path = request.args.get("file")
    if not file_path:
        data_dir = _get_data_dir()
        os.makedirs(data_dir, exist_ok=True)
        file_path = os.path.join(data_dir, "collected_traffic.csv")

    try:
        from modules.preprocessor import preprocess_data

        result = preprocess_data(file_path, purpose="inference")
        return jsonify({"status": "OK", "rows": int(len(result["processed_df"]))})
    except Exception as exc:
        logger.exception("Ошибка /preprocess")
        return jsonify({"error": str(exc)}), 500


@app.route("/analyze", methods=["POST"])
def analyze_endpoint():
    """Запускает полный пайплайн в ручном режиме.

    Поддерживается:
      - загрузка файла (multipart/form-data: file=...)
      - путь к файлу (form/query: file=...)
      - без входа: авто-сценарий pipeline.run(mode=...)

    Параметры:
      - model: rf|xgb (по умолчанию rf)
      - mode: real|demo|test|dataset (по умолчанию PREVISOR_MODE)

    Returns:
        JSON-ответ с краткой сводкой и первыми алертами.
    """
    model_type = (request.form.get("model") or request.args.get("model") or "rf").strip().lower()
    mode = (request.form.get("mode") or request.args.get("mode") or getattr(cfg, "MODE", "demo")).strip().lower()

    pipeline = PreVisorPipeline(model_type=model_type)
    tmp_path: Optional[str] = None

    try:
        # 1) Пользователь загрузил файл
        if "file" in request.files and request.files["file"].filename:
            f = request.files["file"]

            data_dir = _get_data_dir()
            os.makedirs(data_dir, exist_ok=True)

            filename = secure_filename(f.filename)
            tmp_path = os.path.join(data_dir, f"uploaded_{filename}")
            f.save(tmp_path)
            result = pipeline.run(mode=mode, input_csv=tmp_path)

        # 2) Пользователь передал путь к файлу
        else:
            csv_path = request.form.get("file") or request.args.get("file")
            if csv_path:
                result = pipeline.run(mode=mode, input_csv=csv_path)
            else:
                # 3) Автозапуск: pipeline сам соберёт данные согласно mode
                result = pipeline.run(mode=mode)

        alert_rows: List[Dict[str, Any]] = [
            a for a in (result.alerts or []) if int(a.get("alert", 0)) == 1
        ]

        # Сохраняем в БД только alert == 1
        new_alerts = 0
        for a in alert_rows:
            alert_type = a.get("alert_type") or a.get("type") or "Unknown"
            prob = float(a.get("probability", 0.0) or 0.0)
            ip = a.get("source_ip")
            save_alert(alert_type=str(alert_type), probability=prob, source_ip=ip)
            new_alerts += 1

        # Отправляем Telegram-уведомления аналогично celery worker.
        max_notifs = int(os.getenv("MAX_TELEGRAM_ALERTS_PER_RUN", str(getattr(cfg, "MAX_TELEGRAM_ALERTS_PER_RUN", 5))))
        top_alerts = sorted(alert_rows, key=lambda x: float(x.get("probability", 0.0) or 0.0), reverse=True)

        telegram_sent = 0
        if notify_new_alert is not None:
            for a in top_alerts[:max_notifs]:
                try:
                    notify_new_alert(
                        str(a.get("alert_type") or a.get("type") or "Unknown"),
                        float(a.get("probability", 0.0) or 0.0),
                        a.get("source_ip"),
                    )
                    telegram_sent += 1
                except Exception:
                    logger.exception("Notification error (notify_new_alert)")

        if notify_pipeline_summary is not None:
            try:
                top_types = Counter(
                    str(a.get("alert_type") or a.get("type") or "Unknown") for a in alert_rows
                ).most_common(5)
                max_prob = float(top_alerts[0].get("probability", 0.0) or 0.0) if top_alerts else None
                notify_pipeline_summary(
                    model_type=model_type,
                    total_alerts=len(result.alerts or []),
                    new_alerts=new_alerts,
                    telegram_sent=telegram_sent,
                    top_types=top_types,
                    max_probability=max_prob,
                )
            except Exception:
                logger.exception("Notification error (notify_pipeline_summary)")

        warning = None
        if result.processed_df is not None and int(len(result.processed_df)) == 0 and mode == "real":
            warning = "no_packets_captured"
        return jsonify(
            {
                "status": "OK",
                "mode": mode,
                "model": model_type,
                "new_alerts": int(new_alerts),
                "total_alerts": int(len(result.alerts or [])),
                "telegram_sent": int(telegram_sent),
                "alerts": (result.alerts or [])[:10],
                "warning": warning,
            }
        )

    except ValueError as exc:
        logger.exception("Ошибка /analyze (ValueError)")
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:
        logger.exception("Ошибка /analyze")
        return jsonify({"error": str(exc)}), 500

    finally:
        if tmp_path and os.path.basename(tmp_path).startswith("uploaded_"):
            try:
                os.remove(tmp_path)
                logger.info("Удалён временный файл: %s", tmp_path)
            except Exception:
                pass


@app.route("/alerts")
def alerts_api():
    """Возвращает алерты для API/дашборда (с поддержкой limit/offset/status/type)."""
    alert_type = request.args.get("type")
    status = request.args.get("status")

    limit = int(request.args.get("limit", 50))
    offset = int(request.args.get("offset", 0))

    alerts = get_alerts(alert_type=alert_type, status=status, limit=limit, offset=offset)
    return jsonify(
        [
            {
                "id": a.id,
                "timestamp": a.timestamp.isoformat() if a.timestamp else None,
                "type": a.alert_type,
                "probability": a.probability,
                "source_ip": a.source_ip,
                "status": a.status,
            }
            for a in alerts
        ]
    )


@app.route("/alerts/<int:alert_id>/status", methods=["POST"])
def update_alert_status_api(alert_id: int):
    """Обновляет статус алерта.

    Ожидаемый payload:
      - JSON: {"status": "acknowledged"}
      - или form/query: status=...

    Returns:
        JSON с подтверждением обновления или ошибкой.
    """
    payload: Dict[str, Any] = request.get_json(silent=True) or {}
    status = payload.get("status") or request.form.get("status") or request.args.get("status")
    if not status:
        return jsonify({"error": "status is required"}), 400

    try:
        ok = update_alert_status(alert_id, str(status))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    if not ok:
        return jsonify({"error": f"alert id={alert_id} not found"}), 404

    return jsonify({"status": "OK", "id": alert_id, "new_status": status})


@app.route("/alerts/purge", methods=["POST"])
def purge_alerts_api():
    """Очищает таблицу alerts по правилам (удобно для отладки).

    Включено по умолчанию, отключается env:
        PREVISOR_ENABLE_DEV_ENDPOINTS=false
    """
    if not DEV_ENDPOINTS_ENABLED:
        return jsonify({"error": "dev endpoints disabled"}), 403

    payload: Dict[str, Any] = request.get_json(silent=True) or {}
    keep_last = payload.get("keep_last") or request.form.get("keep_last") or request.args.get("keep_last")
    older_than_days = payload.get("older_than_days") or request.form.get("older_than_days") or request.args.get("older_than_days")
    status = payload.get("status") or request.form.get("status") or request.args.get("status")

    deleted = purge_alerts(
        keep_last=int(keep_last) if keep_last not in (None, "") else None,
        older_than_days=int(older_than_days) if older_than_days not in (None, "") else None,
        status=str(status) if status not in (None, "") else None,
    )
    return jsonify({"status": "OK", "deleted": int(deleted)})


if __name__ == "__main__":
    if AUTO_MONITOR_ENABLED:
        _start_auto_monitor()
    app.run(host="0.0.0.0", port=5000)
