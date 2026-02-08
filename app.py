"""Flask-приложение PreVisor.

Содержит:
- REST API и HTML-дашборд;
- непрерывный мониторинг трафика (collector/processor);
- интеграцию с Telegram: уведомления и команды.
"""

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
from modules.database import (
    get_alerts,
    save_alert,
    save_traffic_logs,
    update_alert_status,
    purge_alerts,
    get_alert_by_id,
    get_traffic_log_by_id,
)
from modules.baseline_manager import BaselinePolicy, count_baseline_rows, maybe_train_anomaly_model_from_db
from modules.pipeline import PreVisorPipeline

# Telegram-уведомления (может быть отключено/отсутствовать в минимальном окружении).
try:  # pragma: no cover
    from utils.notifications import (
        notify_new_alert,
        notify_pipeline_summary,
        telegram_status,
        send_telegram_to,
        fetch_telegram_updates,
        get_telegram_webhook_info,
        delete_telegram_webhook,
    )
except Exception:  # pragma: no cover
    notify_new_alert = None  # type: ignore
    notify_pipeline_summary = None  # type: ignore
    telegram_status = None  # type: ignore
    send_telegram_to = None  # type: ignore
    fetch_telegram_updates = None  # type: ignore
    get_telegram_webhook_info = None  # type: ignore
    delete_telegram_webhook = None  # type: ignore

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
_telegram_poll_thread: Optional[threading.Thread] = None
_telegram_poll_stop = threading.Event()
_telegram_last_update: Optional[int] = None
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
    """Возвращает текущее состояние непрерывного мониторинга."""
    with _monitor_lock:
        return dict(_monitor_state)


def _record_monitor_batch(batch_rows: int, summary: Dict[str, Any]) -> None:
    """Обновляет состояние мониторинга после успешной обработки батча.

    Args:
        batch_rows: Сколько строк обработано в батче.
        summary: Сводка пайплайна (new_alerts/total_alerts/telegram_sent и т.п.).
    """
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
    """Записывает ошибку мониторинга в состояние (thread-safe).

    Args:
        exc: Исключение.
    """
    with _monitor_lock:
        _monitor_state["last_error"] = str(exc)
        _monitor_state["last_error_at"] = datetime.now(timezone.utc).isoformat()


def _is_monitor_running() -> bool:
    """Проверяет, запущены ли потоки collector и processor."""
    return bool(
        _collector_thread
        and _collector_thread.is_alive()
        and _processor_thread
        and _processor_thread.is_alive()
    )


def _monitor_config() -> Dict[str, Any]:
    """Собирает конфигурацию непрерывного мониторинга из env и config.py."""
    model = os.getenv("PREVISOR_MODEL", "rf").strip().lower()
    mode = os.getenv("PREVISOR_MODE", getattr(cfg, "MODE", "real")).strip().lower()
    batch_size = max(
        1,
        int(
            os.getenv(
                "PREVISOR_CONTINUOUS_BATCH_SIZE",
                str(getattr(cfg, "PREVISOR_CONTINUOUS_BATCH_SIZE", 200)),
            )
        ),
    )
    flush_sec = max(
        1.0,
        float(
            os.getenv(
                "PREVISOR_CONTINUOUS_FLUSH_SEC",
                str(getattr(cfg, "PREVISOR_CONTINUOUS_FLUSH_SEC", 5)),
            )
        ),
    )
    queue_max = max(
        1,
        int(
            os.getenv(
                "PREVISOR_CONTINUOUS_QUEUE_MAX",
                str(getattr(cfg, "PREVISOR_CONTINUOUS_QUEUE_MAX", 200)),
            )
        ),
    )
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


def _set_telegram_chat_id(chat_id: str, *, persist: bool = True) -> None:
    """Обновляет TELEGRAM_CHAT_ID в окружении и .env (опционально)."""
    os.environ["TELEGRAM_CHAT_ID"] = str(chat_id)
    if persist:
        _write_env_value(os.path.join(_project_root(), ".env"), "TELEGRAM_CHAT_ID", str(chat_id))


def _telegram_help_message() -> str:
    """Формирует текст справки (меню) для команды /start."""
    configured = (os.getenv("TELEGRAM_CHAT_ID") or getattr(cfg, "TELEGRAM_CHAT_ID", "")).strip() or "не задан"
    return (
        "<b>PreVisor</b> — мониторинг сетевых угроз и аномалий.\n"
        "\n"
        "Я умею:\n"
        "• присылать уведомления о новых алертах\n"
        "• управлять непрерывным мониторингом\n"
        "• привязать текущий чат для уведомлений\n"
        "\n"
        f"Текущий TELEGRAM_CHAT_ID: <code>{configured}</code>\n"
        "\n"
        "<b>Команды</b>:\n"
        "• /start или /help — показать это меню\n"
        "• /selectchat — привязать этот чат для уведомлений\n"
        "• /status — статус мониторинга\n"
        "• /startmonitor — запустить непрерывный мониторинг\n"
        "• /stopmonitor — остановить мониторинг\n"
    )


def _handle_telegram_command(text: str, chat_id: str) -> None:
    """Обрабатывает команду Telegram, пришедшую из указанного чата.

    Args:
        text: Текст сообщения (обычно команда, например "/start").
        chat_id: Chat ID источника сообщения.
    """
    if send_telegram_to is None:
        return
    cmd = (text or "").strip().split()[0].lower()
    # В группах Telegram команды часто приходят как "/cmd@BotName".
    if "@" in cmd:
        cmd = cmd.split("@", 1)[0]
    if cmd in {"/start", "/help"}:
        send_telegram_to(chat_id, _telegram_help_message())
        return
    if cmd == "/selectchat":
        _set_telegram_chat_id(chat_id, persist=True)
        send_telegram_to(chat_id, f"Чат привязан: <code>{chat_id}</code>")
        return
    if cmd == "/startmonitor":
        started = _start_continuous_monitor()
        state = "запущен" if started else "уже запущен"
        send_telegram_to(chat_id, f"Мониторинг: {state}.")
        return
    if cmd == "/stopmonitor":
        stopped = _stop_continuous_monitor()
        state = "остановлен" if stopped else "уже остановлен"
        send_telegram_to(chat_id, f"Мониторинг: {state}.")
        return
    if cmd == "/status":
        running = _is_monitor_running()
        send_telegram_to(chat_id, f"Мониторинг: {'ON' if running else 'OFF'}.")
        return
    if cmd.startswith("/"):
        send_telegram_to(chat_id, _telegram_help_message())
        return


def _handle_telegram_update(update: Dict[str, Any]) -> None:
    """Обрабатывает один update Telegram (webhook или getUpdates).

    Args:
        update: Update-объект Telegram Bot API.
    """
    msg = update.get("message") or update.get("edited_message") or update.get("channel_post")
    if not isinstance(msg, dict):
        return
    chat = msg.get("chat") or {}
    chat_id = chat.get("id")
    text = msg.get("text") or ""
    if chat_id is None or not text:
        return
    _handle_telegram_command(str(text), str(chat_id))


def _telegram_poll_loop() -> None:
    """Цикл polling getUpdates для обработки команд Telegram."""
    global _telegram_last_update
    logger.info("Telegram commands polling started")
    while not _telegram_poll_stop.is_set():
        try:
            if fetch_telegram_updates is None:
                break
            offset = (_telegram_last_update + 1) if _telegram_last_update is not None else None
            updates = fetch_telegram_updates(limit=25, offset=offset)
            results = updates.get("result") or []
            for item in results:
                update_id = item.get("update_id")
                if update_id is not None:
                    _telegram_last_update = max(_telegram_last_update or 0, int(update_id))
                _handle_telegram_update(item)
        except Exception:
            logger.exception("Telegram polling error")
        _telegram_poll_stop.wait(2.0)


def _start_telegram_polling() -> bool:
    """Запускает фоновый polling команд Telegram.

    Returns:
        True, если поток polling был запущен; False, если уже запущен или нет токена.
    """
    global _telegram_poll_thread
    if _telegram_poll_thread and _telegram_poll_thread.is_alive():
        return False
    token = (os.getenv("TELEGRAM_BOT_TOKEN") or getattr(cfg, "TELEGRAM_BOT_TOKEN", "")).strip()
    if not token:
        logger.warning("Telegram polling не запущен: TELEGRAM_BOT_TOKEN не задан")
        return False
    _telegram_poll_stop.clear()
    _telegram_poll_thread = threading.Thread(
        target=_telegram_poll_loop,
        name="previsor-telegram",
        daemon=True,
    )
    _telegram_poll_thread.start()
    return True


def _collector_loop(config: Dict[str, Any], out_queue: queue.Queue) -> None:
    """Фоновый сбор трафика для непрерывного мониторинга.

    Args:
        config: Конфигурация мониторинга (mode/collect_params и т.п.).
        out_queue: Очередь, куда складываются батчи DataFrame.
    """
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
    """Фоновая обработка трафика для непрерывного мониторинга.

    Собирает входящие DataFrame в буфер и периодически запускает пайплайн.

    Args:
        config: Конфигурация мониторинга (model/batch_size/flush_sec и т.п.).
        in_queue: Очередь с батчами DataFrame от collector.
    """
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
                summary = _handle_pipeline_result(
                    result,
                    mode=str(config.get("mode") or "real"),
                    model_type=pipeline.model_type,
                    send_summary=send_summary,
                )
                _record_monitor_batch(len(batch_df), summary)
            except Exception as exc:
                logger.exception("Continuous processor failed")
                _record_monitor_error(exc)


def _start_continuous_monitor() -> bool:
    """Запускает непрерывный мониторинг (collector + processor).

    Returns:
        True, если мониторинг был запущен; False, если уже работал.
    """
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
    """Останавливает непрерывный мониторинг и очищает очередь.

    Returns:
        True, если была выполнена остановка; False, если мониторинг не запускался.
    """
    global _collector_thread, _processor_thread, _monitor_queue
    if not _collector_thread and not _processor_thread:
        return False
    _monitor_stop.set()
    if _monitor_queue is not None:
        try:
            while not _monitor_queue.empty():
                _monitor_queue.get_nowait()
        except Exception:
            pass
    if _collector_thread:
        _collector_thread.join(timeout=5)
    if _processor_thread:
        _processor_thread.join(timeout=5)
    _collector_thread = None
    _processor_thread = None
    _monitor_queue = None
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


def _iso_utc(dt: Optional[datetime]) -> Optional[str]:
    """Возвращает ISO-строку в UTC для даты/времени."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()


def _write_env_value(env_path: str, key: str, value: str) -> None:
    """Записывает ключ/значение в .env (создаёт файл при отсутствии)."""
    lines = []
    if os.path.exists(env_path):
        with open(env_path, "r", encoding="utf-8") as f:
            lines = f.read().splitlines()

    out = []
    replaced = False
    for line in lines:
        if not line.strip() or line.strip().startswith("#"):
            out.append(line)
            continue
        if line.split("=", 1)[0].strip() == key:
            out.append(f"{key}={value}")
            replaced = True
        else:
            out.append(line)

    if not replaced:
        out.append(f"{key}={value}")

    with open(env_path, "w", encoding="utf-8") as f:
        f.write("\n".join(out) + "\n")

def _handle_pipeline_result(
    result,
    *,
    mode: str,
    model_type: str,
    send_summary: bool = True,
) -> Dict[str, Any]:
    """Сохраняет алерты, отправляет уведомления и возвращает сводку по запуску.

    Args:
        result: Результат PreVisorPipeline.run().
        mode: Режим запуска пайплайна (real/demo/test/dataset).
        model_type: Идентификатор модели классификатора (rf/xgb).
        send_summary: Отправлять ли сводку в Telegram.

    Returns:
        Словарь со сводкой (new_alerts/total_alerts/telegram_sent/alerts).
    """
    alert_rows: List[Dict[str, Any]] = [
        a for a in (result.alerts or []) if int(a.get("alert", 0)) == 1
    ]

    new_alerts = 0
    for a in alert_rows:
        alert_type = a.get("alert_type") or a.get("type") or "Unknown"
        prob = float(a.get("probability", 0.0) or 0.0)
        ip = a.get("source_ip")
        traffic_log_id = a.get("traffic_log_id")
        save_alert(
            alert_type=str(alert_type),
            probability=prob,
            source_ip=ip,
            traffic_log_id=int(traffic_log_id) if traffic_log_id is not None else None,
        )
        new_alerts += 1

    anomaly_retrained = False
    if str(mode) == "real":
        try:
            policy = BaselinePolicy()
            if policy.auto_enabled:
                anomaly_retrained = bool(
                    maybe_train_anomaly_model_from_db(
                        feature_schema_path=getattr(cfg, "FEATURE_SCHEMA_PATH", ""),
                        mode=str(mode),
                    )
                )
        except Exception:
            logger.exception("Auto baseline/retrain failed (_handle_pipeline_result)")

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
                mode=str(mode),
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
        "anomaly_retrained": bool(anomaly_retrained),
        "alerts": (result.alerts or []),
    }


DEV_ENDPOINTS_ENABLED = _env_bool("PREVISOR_ENABLE_DEV_ENDPOINTS", True)
DEV_UI_ENABLED = _env_bool("PREVISOR_ENABLE_DEV_UI", False)
CONTINUOUS_MONITOR_ENABLED = _env_bool("PREVISOR_CONTINUOUS_MONITOR", True)
TELEGRAM_COMMANDS_ENABLED = _env_bool(
    "PREVISOR_TELEGRAM_COMMANDS",
    bool(getattr(cfg, "PREVISOR_TELEGRAM_COMMANDS", True)),
)


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
    baseline_rows = None
    try:
        baseline_rows = count_baseline_rows(mode=str(config.get("mode") or "real"))
    except Exception:
        baseline_rows = None
    return jsonify(
        {
            "running": running,
            "mode": config["mode"],
            "model": config["model"],
            "batch_size": int(config["batch_size"]),
            "flush_sec": float(config["flush_sec"]),
            "queue_size": int(queue_size),
            "iface": config.get("collect_params", {}).get("iface"),
            "baseline_rows": baseline_rows,
            **state,
        }
    )


@app.route("/monitor/start", methods=["POST"])
def monitor_start():
    """Запускает непрерывный мониторинг (если он не запущен)."""
    started = _start_continuous_monitor()
    return jsonify({"status": "OK", "running": _is_monitor_running(), "started": bool(started)})


@app.route("/monitor/stop", methods=["POST"])
def monitor_stop():
    """Останавливает непрерывный мониторинг."""
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
        store_db: если true — дополнительно сохраняет пачку в БД (traffic_logs).
        baseline: если true — эквивалентно store_db=true и пытается дообучить IsolationForest на baseline из БД.

    Returns:
        JSON со статусом и количеством строк.
    """
    mode = (request.args.get("mode") or getattr(cfg, "MODE", "demo")).strip().lower()
    rows = int(request.args.get("rows") or getattr(cfg, "DEMO_ROWS", 1200))
    source = (request.args.get("source") or getattr(cfg, "DEMO_SOURCE", "mixed")).strip().lower()
    dataset_name = (request.args.get("dataset") or getattr(cfg, "DATASET_NAME", "cicids2017_processed.csv")).strip()

    baseline = _parse_bool(request.args.get("baseline"))
    store_db = _parse_bool(request.args.get("store_db"))
    if baseline:
        store_db = True

    if mode == "simulated":
        mode = "demo"
        source = "simulated"

    collect_kwargs: Dict[str, Any] = {
        "mode": mode,
        "save_csv": True,
        "demo_source": source,
        "dataset_name": dataset_name,
    }

    # В real интерпретируем rows как число пакетов за сбор.
    if mode == "real":
        collect_kwargs["num_packets"] = int(rows)
        collect_kwargs["iface"] = os.getenv("PREVISOR_NET_IFACE", getattr(cfg, "NETWORK_INTERFACE", "auto"))
        collect_kwargs["timeout_sec"] = int(
            os.getenv(
                "PREVISOR_PACKET_TIMEOUT",
                str(getattr(cfg, "PACKET_SNIFF_TIMEOUT_SEC", 30)),
            )
        )
        collect_kwargs["bpf_filter"] = os.getenv("PREVISOR_BPF_FILTER", getattr(cfg, "BPF_FILTER", ""))
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

    saved_rows = None
    if store_db:
        try:
            saved_rows = int(save_traffic_logs(df, mode=mode))
        except Exception:
            logger.exception("Не удалось сохранить traffic_logs (collect_endpoint)")
            saved_rows = None

    baseline_pool_rows = None
    anomaly_retrained = False
    if baseline and mode == "real":
        try:
            policy = BaselinePolicy()
            if policy.auto_enabled:
                anomaly_retrained = bool(
                    maybe_train_anomaly_model_from_db(
                        feature_schema_path=getattr(cfg, "FEATURE_SCHEMA_PATH", ""),
                        mode=mode,
                    )
                )
            baseline_pool_rows = int(count_baseline_rows(mode=mode))
        except Exception:
            logger.exception("Auto baseline/retrain failed (collect_endpoint)")
            baseline_pool_rows = None
            anomaly_retrained = False

    target_csv = getattr(cfg, "COLLECTED_TRAFFIC_CSV", None)

    warning = None
    if int(len(df)) == 0 and mode == "real":
        warning = "no_packets_captured"
    return jsonify(
        {
            "status": "OK",
            "mode": mode,
            "baseline": bool(baseline),
            "stored_to_db": bool(store_db),
            "saved_rows": saved_rows,
            "baseline_pool_rows": baseline_pool_rows,
            "anomaly_retrained": bool(anomaly_retrained),
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

        summary = _handle_pipeline_result(result, mode=mode, model_type=model_type, send_summary=True)
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
                "timestamp": _iso_utc(a.timestamp),
                "type": a.alert_type,
                "probability": a.probability,
                "source_ip": a.source_ip,
                "status": a.status,
                "traffic_log_id": a.traffic_log_id,
            }
        for a in alerts
        ]
    )


@app.route("/settings/interface", methods=["POST"])
def set_interface():
    """Устанавливает сетевой интерфейс (PREVISOR_NET_IFACE) для сборщика."""
    payload: Dict[str, Any] = request.get_json(silent=True) or {}
    iface = payload.get("iface") or request.form.get("iface") or request.args.get("iface")
    persist_raw = payload.get("persist") or request.form.get("persist") or request.args.get("persist")
    persist = _parse_bool(str(persist_raw)) if persist_raw is not None else False

    if not iface:
        return jsonify({"error": "iface is required"}), 400

    os.environ["PREVISOR_NET_IFACE"] = str(iface)
    if persist:
        _write_env_value(os.path.join(_project_root(), ".env"), "PREVISOR_NET_IFACE", str(iface))

    return jsonify(
        {
            "status": "OK",
            "iface": str(iface),
            "persisted": bool(persist),
            "restart_monitor": bool(_is_monitor_running()),
        }
    )


@app.route("/telegram/status")
def telegram_status_api():
    """Возвращает статус Telegram-канала (сконфигурирован/готов)."""
    if telegram_status is None:
        return jsonify({"enabled": False, "ready": False, "configured": False})
    data = telegram_status()
    return jsonify(data)


@app.route("/telegram/webhook_info")
def telegram_webhook_info_api():
    """Возвращает getWebhookInfo у Telegram Bot API (dev endpoint)."""
    if not DEV_ENDPOINTS_ENABLED:
        return jsonify({"error": "dev endpoints disabled"}), 403
    if get_telegram_webhook_info is None:
        return jsonify({"error": "telegram integration not available"}), 503
    try:
        return jsonify(get_telegram_webhook_info())
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/telegram/delete_webhook", methods=["POST"])
def telegram_delete_webhook_api():
    """Отключает webhook у Telegram-бота (dev endpoint)."""
    if not DEV_ENDPOINTS_ENABLED:
        return jsonify({"error": "dev endpoints disabled"}), 403
    if delete_telegram_webhook is None:
        return jsonify({"error": "telegram integration not available"}), 503

    payload: Dict[str, Any] = request.get_json(silent=True) or {}
    raw_drop = payload.get("drop_pending_updates")
    drop = _parse_bool(str(raw_drop)) if raw_drop is not None else True

    try:
        return jsonify(delete_telegram_webhook(drop_pending_updates=drop))
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/telegram/webhook", methods=["POST"])
def telegram_webhook():
    """Webhook для Telegram-бота (обработка команд /start и т.д.)."""
    payload: Dict[str, Any] = request.get_json(silent=True) or {}
    try:
        _handle_telegram_update(payload)
    except Exception:
        logger.exception("Telegram webhook error")
    return jsonify({"status": "OK"})


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

    retrained = False
    baseline_pool_rows = None

    if str(status) == "false_positive":
        baseline_mode = "real"
        alert_row = get_alert_by_id(alert_id)
        if alert_row and alert_row.traffic_log_id:
            log_row = get_traffic_log_by_id(alert_row.traffic_log_id)
            if log_row and getattr(log_row, "mode", None):
                baseline_mode = str(log_row.mode)

        try:
            policy = BaselinePolicy()
            if policy.auto_enabled and baseline_mode == "real":
                retrained = bool(
                    maybe_train_anomaly_model_from_db(
                        feature_schema_path=getattr(cfg, "FEATURE_SCHEMA_PATH", ""),
                        mode=baseline_mode,
                    )
                )
            baseline_pool_rows = int(count_baseline_rows(mode=baseline_mode))
        except Exception:
            logger.exception("Auto baseline/retrain failed (false_positive)")
            retrained = False
            baseline_pool_rows = None

    return jsonify(
        {
            "status": "OK",
            "id": alert_id,
            "new_status": status,
            "baseline_appended": False,
            "baseline_pool_rows": baseline_pool_rows,
            "anomaly_retrained": bool(retrained),
        }
    )


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


@app.route("/traffic_logs/<int:log_id>")
def traffic_log_detail_api(log_id: int):
    """Возвращает одну запись traffic_logs по ID."""
    row = get_traffic_log_by_id(int(log_id))
    if row is None:
        return jsonify({"error": f"traffic_log id={log_id} not found"}), 404

    return jsonify(
        {
            "id": int(row.id),
            "timestamp": _iso_utc(row.timestamp),
            "source_ip": row.source_ip,
            "dest_ip": row.dest_ip,
            "protocol": row.protocol,
            "src_port": row.src_port,
            "dest_port": row.dest_port,
            "packet_len": row.packet_len,
            "ttl": row.ttl,
            "tcp_flags": row.tcp_flags,
            "http_method": row.http_method,
            "mode": row.mode,
        }
    )


if __name__ == "__main__":
    if CONTINUOUS_MONITOR_ENABLED:
        _start_continuous_monitor()
    if TELEGRAM_COMMANDS_ENABLED and fetch_telegram_updates is not None:
        _start_telegram_polling()
    app.run(host="0.0.0.0", port=5000)
