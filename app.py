from __future__ import annotations

import logging
import os
import queue
import threading
import time
import warnings
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, Optional, List

import pandas as pd
from flask import Flask, jsonify, render_template, request
from pandas.errors import PerformanceWarning
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
warnings.filterwarnings("ignore", category=PerformanceWarning)

app = Flask(__name__)

_monitor_lock = threading.Lock()
_monitor_stop = threading.Event()
_monitor_queue: Optional[queue.Queue] = None
_collector_thread: Optional[threading.Thread] = None
_processor_thread: Optional[threading.Thread] = None
_monitor_state: Dict[str, Any] = {
    "last_batch_at": None,
    "last_error": None,
    "last_error_at": None,
    "processed_batches": 0,
    "processed_rows": 0,
    "last_new_alerts": 0,
    "last_total_alerts": 0,
    "last_telegram_sent": 0,
}


def _get_monitor_state() -> Dict[str, Any]:
    with _monitor_lock:
        return dict(_monitor_state)


def _record_monitor_batch(batch_rows: int, summary: Dict[str, Any]) -> None:
    with _monitor_lock:
        _monitor_state["last_batch_at"] = datetime.now(timezone.utc).isoformat()
        _monitor_state["last_error"] = None
        _monitor_state["last_error_at"] = None
        _monitor_state["processed_batches"] += 1
        _monitor_state["processed_rows"] += int(batch_rows)
        _monitor_state["last_new_alerts"] = int(summary.get("new_alerts", 0))
        _monitor_state["last_total_alerts"] = int(summary.get("total_alerts", 0))
        _monitor_state["last_telegram_sent"] = int(summary.get("telegram_sent", 0))


def _record_monitor_error(exc: Exception) -> None:
    with _monitor_lock:
        _monitor_state["last_error"] = str(exc)
        _monitor_state["last_error_at"] = datetime.now(timezone.utc).isoformat()


def _is_monitor_running() -> bool:
    return bool(
        _collector_thread
        and _collector_thread.is_alive()
        and _processor_thread
        and _processor_thread.is_alive()
    )


def _monitor_config() -> Dict[str, Any]:
    model = os.getenv("PREVISOR_MODEL", "rf").strip().lower()
    mode = os.getenv("PREVISOR_MODE", getattr(cfg, "MODE", "real")).strip().lower()
    batch_size = max(1, int(os.getenv("PREVISOR_CONTINUOUS_BATCH_SIZE", "200")))
    flush_sec = max(1.0, float(os.getenv("PREVISOR_CONTINUOUS_FLUSH_SEC", "5")))
    queue_max = max(1, int(os.getenv("PREVISOR_CONTINUOUS_QUEUE_MAX", "200")))
    collect_sleep_sec = max(0.0, float(os.getenv("PREVISOR_CONTINUOUS_COLLECT_SLEEP_SEC", "0.25")))
    save_csv = _env_bool("PREVISOR_CONTINUOUS_SAVE_CSV", False)
    send_summary = _env_bool("PREVISOR_CONTINUOUS_NOTIFY_SUMMARY", False)

    collect_params = {
        "iface": os.getenv("PREVISOR_NET_IFACE", getattr(cfg, "NETWORK_INTERFACE", "auto")),
        "num_packets": int(
            os.getenv(
                "PREVISOR_CONTINUOUS_PACKET_COUNT",
                str(getattr(cfg, "PACKET_COUNT_PER_COLLECTION", 200)),
            )
        ),
        "timeout_sec": int(
            os.getenv(
                "PREVISOR_CONTINUOUS_PACKET_TIMEOUT",
                str(getattr(cfg, "PACKET_SNIFF_TIMEOUT_SEC", 30)),
            )
        ),
        "bpf_filter": os.getenv("PREVISOR_BPF_FILTER", getattr(cfg, "BPF_FILTER", "")),
        "demo_source": os.getenv("PREVISOR_CONTINUOUS_DEMO_SOURCE", getattr(cfg, "DEMO_SOURCE", "mixed")),
        "demo_rows": int(
            os.getenv("PREVISOR_CONTINUOUS_DEMO_ROWS", str(getattr(cfg, "DEMO_ROWS", 1200)))
        ),
        "dataset_name": os.getenv(
            "PREVISOR_CONTINUOUS_DATASET",
            getattr(cfg, "DATASET_NAME", ""),
        ),
    }

    return {
        "model": model,
        "mode": mode,
        "batch_size": batch_size,
        "flush_sec": flush_sec,
        "queue_max": queue_max,
        "collect_sleep_sec": collect_sleep_sec,
        "save_csv": save_csv,
        "send_summary": send_summary,
        "collect_params": collect_params,
    }


def _collector_loop(config: Dict[str, Any], out_queue: queue.Queue) -> None:
    mode = config["mode"]
    collect_params = config["collect_params"]
    save_csv = config["save_csv"]
    sleep_sec = float(config["collect_sleep_sec"])
    logger.info("Continuous collector started: mode=%s", mode)
    while not _monitor_stop.is_set():
        try:
            df = collect_traffic(mode=mode, save_csv=save_csv, **collect_params)
            if df is not None and len(df) > 0:
                try:
                    out_queue.put(df, timeout=1)
                except queue.Full:
                    logger.warning("Monitor queue is full, dropping batch")
            else:
                logger.debug("Collector batch empty")
        except Exception:
            logger.exception("Continuous collector failed")
        _monitor_stop.wait(sleep_sec)


def _processor_loop(config: Dict[str, Any], in_queue: queue.Queue) -> None:
    pipeline = PreVisorPipeline(model_type=config["model"])
    batch_size = int(config["batch_size"])
    flush_sec = float(config["flush_sec"])
    send_summary = bool(config.get("send_summary", False))
    buffer: List[pd.DataFrame] = []
    buffer_rows = 0
    last_flush = time.monotonic()

    logger.info("Continuous processor started: mode=%s model=%s", config["mode"], config["model"])
    while not _monitor_stop.is_set() or not in_queue.empty():
        try:
            df = in_queue.get(timeout=1)
            if df is not None and len(df) > 0:
                buffer.append(df)
                buffer_rows += int(len(df))
        except queue.Empty:
            df = None

        now = time.monotonic()
        should_flush = (
            buffer_rows >= batch_size
            or (buffer_rows > 0 and (now - last_flush) >= flush_sec)
            or (_monitor_stop.is_set() and buffer_rows > 0 and in_queue.empty())
        )
        if should_flush:
            try:
                batch_df = pd.concat(buffer, ignore_index=True)
            except ValueError:
                batch_df = pd.DataFrame()
            buffer = []
            buffer_rows = 0
            last_flush = now

            if batch_df is None or batch_df.empty:
                continue

            try:
                result = pipeline.run(mode=config["mode"], input_df=batch_df, model_type=config["model"])
                summary = _handle_pipeline_result(result, model_type=pipeline.model_type, send_summary=send_summary)
                _record_monitor_batch(len(batch_df), summary)
            except Exception as exc:
                logger.exception("Continuous processor failed")
                _record_monitor_error(exc)


def _start_continuous_monitor() -> bool:
    global _collector_thread, _processor_thread, _monitor_queue
    if _is_monitor_running():
        return False

    config = _monitor_config()
    _monitor_stop.clear()
    _monitor_queue = queue.Queue(maxsize=int(config["queue_max"]))
    with _monitor_lock:
        _monitor_state.update({
            "last_batch_at": None,
            "last_error": None,
            "last_error_at": None,
            "processed_batches": 0,
            "processed_rows": 0,
            "last_new_alerts": 0,
            "last_total_alerts": 0,
            "last_telegram_sent": 0,
        })

    _collector_thread = threading.Thread(
        target=_collector_loop,
        args=(config, _monitor_queue),
        name="previsor-collector",
        daemon=True,
    )
    _processor_thread = threading.Thread(
        target=_processor_loop,
        args=(config, _monitor_queue),
        name="previsor-processor",
        daemon=True,
    )
    _collector_thread.start()
    _processor_thread.start()
    logger.info(
        "Continuous monitor started: mode=%s model=%s batch=%s",
        config["mode"],
        config["model"],
        config["batch_size"],
    )
    return True


def _stop_continuous_monitor() -> bool:
    global _collector_thread, _processor_thread, _monitor_queue
    if not _collector_thread and not _processor_thread:
        return False
    _monitor_stop.set()
    if _collector_thread:
        _collector_thread.join(timeout=5)
    if _processor_thread:
        _processor_thread.join(timeout=5)
    return True

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


def _handle_pipeline_result(result, *, model_type: str, send_summary: bool = True) -> Dict[str, Any]:
    # Store alert rows, send notifications, and return summary counts.
    alert_rows: List[Dict[str, Any]] = [
        a for a in (result.alerts or []) if int(a.get("alert", 0)) == 1
    ]

    new_alerts = 0
    for a in alert_rows:
        alert_type = a.get("alert_type") or a.get("type") or "Unknown"
        prob = float(a.get("probability", 0.0) or 0.0)
        ip = a.get("source_ip")
        save_alert(alert_type=str(alert_type), probability=prob, source_ip=ip)
        new_alerts += 1

    max_notifs = int(
        os.getenv(
            "MAX_TELEGRAM_ALERTS_PER_RUN",
            str(getattr(cfg, "MAX_TELEGRAM_ALERTS_PER_RUN", 5)),
        )
    )
    top_alerts = sorted(
        alert_rows,
        key=lambda x: float(x.get("probability", 0.0) or 0.0),
        reverse=True,
    )

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

    if notify_pipeline_summary is not None and send_summary:
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

    return {
        "new_alerts": int(new_alerts),
        "total_alerts": int(len(result.alerts or [])),
        "telegram_sent": int(telegram_sent),
        "alerts": (result.alerts or []),
    }


DEV_ENDPOINTS_ENABLED = _env_bool("PREVISOR_ENABLE_DEV_ENDPOINTS", True)
DEV_UI_ENABLED = _env_bool("PREVISOR_ENABLE_DEV_UI", False)
CONTINUOUS_MONITOR_ENABLED = _env_bool("PREVISOR_CONTINUOUS_MONITOR", True)


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
    running = _is_monitor_running()
    config = _monitor_config()
    state = _get_monitor_state()
    queue_size = _monitor_queue.qsize() if _monitor_queue else 0
    return jsonify(
        {
            "running": running,
            "mode": config["mode"],
            "model": config["model"],
            "batch_size": int(config["batch_size"]),
            "flush_sec": float(config["flush_sec"]),
            "queue_size": int(queue_size),
            **state,
        }
    )


@app.route("/monitor/start", methods=["POST"])
def monitor_start():
    # Starts the continuous monitor if not running.
    started = _start_continuous_monitor()
    return jsonify({"status": "OK", "running": _is_monitor_running(), "started": bool(started)})


@app.route("/monitor/stop", methods=["POST"])
def monitor_stop():
    # Stops the continuous monitor.
    stopped = _stop_continuous_monitor()
    return jsonify({"status": "OK", "running": _is_monitor_running(), "stopped": bool(stopped)})

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

        summary = _handle_pipeline_result(result, model_type=model_type, send_summary=True)
        warning = None
        if result.processed_df is not None and int(len(result.processed_df)) == 0 and mode == "real":
            warning = "no_packets_captured"
        return jsonify(
            {
                "status": "OK",
                "mode": mode,
                "model": model_type,
                "new_alerts": int(summary["new_alerts"]),
                "total_alerts": int(summary["total_alerts"]),
                "telegram_sent": int(summary["telegram_sent"]),
                "alerts": (summary["alerts"] or [])[:10],
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
    if CONTINUOUS_MONITOR_ENABLED:
        _start_continuous_monitor()
    app.run(host="0.0.0.0", port=5000)
