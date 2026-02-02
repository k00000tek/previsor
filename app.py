from __future__ import annotations

import logging
import os
from typing import Any, Dict, Optional

from flask import Flask, jsonify, render_template, request
from werkzeug.utils import secure_filename

import config as cfg
from modules.data_collector import collect_traffic
from modules.database import get_alerts, save_alert, update_alert_status, purge_alerts
from modules.pipeline import PreVisorPipeline

logger = logging.getLogger(__name__)
if not logging.getLogger().handlers:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

app = Flask(__name__)


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


@app.route("/health")
def health():
    """Healthcheck для Docker/оркестрации."""
    return jsonify({"status": "OK"})


@app.route("/")
def index():
    """Главная страница: рендерим дашборд."""
    return render_template("dashboard.html")


@app.route("/dashboard")
def dashboard():
    """Рендерит HTML-дашборд."""
    return render_template("dashboard.html")


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

    if mode == "simulated":
        mode = "demo"
        source = "simulated"

    df = collect_traffic(
        mode=mode,  # type: ignore[arg-type]
        save_csv=True,
        demo_source=source,  # type: ignore[arg-type]
        demo_rows=rows,
        dataset_name=dataset_name,
    )
    return jsonify({"status": "OK", "mode": mode, "rows": int(len(df))})


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

        # Сохраняем в БД только alert == 1
        saved = 0
        found = 0
        for a in (result.alerts or []):
            if int(a.get("alert", 0)) != 1:
                continue

            found += 1
            alert_type = a.get("alert_type") or a.get("type") or "Unknown"
            prob = float(a.get("probability", 0.0) or 0.0)
            ip = a.get("source_ip")

            save_alert(alert_type=str(alert_type), probability=prob, source_ip=ip)
            saved += 1

        return jsonify(
            {
                "status": "OK",
                "mode": mode,
                "model": model_type,
                "alerts_found": found,
                "saved_to_db": saved,
                "alerts": (result.alerts or [])[:10],
            }
        )

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
    app.run(host="0.0.0.0", port=5000)
