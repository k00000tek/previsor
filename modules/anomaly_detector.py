from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

import config as cfg
from config import IFOREST_MODEL_PATH

logger = logging.getLogger(__name__)
if not logging.getLogger().handlers:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


def _env_float(name: str, default: float) -> float:
    """Безопасно читает float из переменной окружения."""
    raw = os.getenv(name)
    if raw is None:
        return float(default)
    try:
        return float(raw)
    except Exception:
        return float(default)


def _env_int(name: str, default: int) -> int:
    """Безопасно читает int из переменной окружения."""
    raw = os.getenv(name)
    if raw is None:
        return int(default)
    try:
        return int(raw)
    except Exception:
        return int(default)


def _env_csv_floats(name: str, default: Iterable[float]) -> List[float]:
    """Reads a CSV list of floats from env."""
    raw = os.getenv(name)
    if not raw:
        return list(default)
    out: List[float] = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            out.append(float(part))
        except Exception:
            continue
    return out or list(default)


@dataclass
class AnomalyPolicy:
    """Политика детекции аномалий.

    Attributes:
        contamination: Доля аномалий для IsolationForest (грубая априорная оценка).
        quantile: Квантиль anomaly_score для отбора (например 0.99 = топ-1%).
        max_alerts: Максимум алертов-анoмалий за прогон.
        require_pred_minus1: Требовать ли условие IsolationForest preds == -1.
        decision_threshold: Порог по decision_function для режима threshold.
    """

    contamination: float = _env_float("PREVISOR_ANOMALY_CONTAMINATION", 0.02)
    quantile: float = _env_float("PREVISOR_ANOMALY_QUANTILE", 0.99)
    max_alerts: int = _env_int("PREVISOR_ANOMALY_MAX_ALERTS", 50)
    require_pred_minus1: bool = os.getenv("PREVISOR_ANOMALY_REQUIRE_MINUS1", "true").strip().lower() in {"1", "true", "yes", "y", "on"}
    decision_threshold: float = _env_float("PREVISOR_ANOMALY_DECISION_THRESHOLD", -0.1)
    strategy: str = os.getenv("PREVISOR_ANOMALY_STRATEGY", "baseline").strip().lower()
    baseline_quantile: float = _env_float("PREVISOR_ANOMALY_BASELINE_QUANTILE", 0.999)
    baseline_quantiles: List[float] = field(default_factory=lambda: _env_csv_floats(
        "PREVISOR_ANOMALY_BASELINE_QUANTILES",
        default=[0.95, 0.99, 0.995, 0.999],
    ))


class AnomalyDetector:
    """Детектор аномалий на основе IsolationForest.

    Назначение:
    - хранит/загружает baseline-модель IsolationForest;
    - выдаёт предсказания (preds) и decision_function.

    Важная инженерная оговорка (для стабильности пайплайна):
    - если baseline-модель отсутствует, мы можем "bootstrap"-обучить её на текущем батче,
      сохранить и вернуть пустой список аномалий на первом прогоне. Это позволяет пользователю
      запустить систему "из коробки": первый прогон инициализирует baseline, а со второго
      уже возможна полноценная детекция.
    """

    def __init__(
        self,
        *,
        contamination: Optional[float] = None,
        random_state: int = 42,
        model_path: str = IFOREST_MODEL_PATH,
        fallback_path: Optional[str] = None,
    ) -> None:
        """Инициализирует IsolationForest детектор.

        Args:
            contamination: Оценка доли аномалий.
            random_state: Seed.
            model_path: Путь к модели.
        """
        self.model_path = model_path
        self.fallback_path = fallback_path

        if contamination is None:
            contamination = _env_float("PREVISOR_ANOMALY_CONTAMINATION", 0.02)

        self.model = IsolationForest(
            contamination=float(contamination),
            random_state=int(random_state),
            n_estimators=200,
            n_jobs=-1,
        )

    def fit(self, X: Union[pd.DataFrame, np.ndarray]) -> None:
        """Обучает IsolationForest и сохраняет модель на диск.

        Args:
            X: Матрица признаков (DataFrame или numpy array).
        """
        os.makedirs(os.path.dirname(self.model_path) or ".", exist_ok=True)
        self.model.fit(X)
        joblib.dump(self.model, self.model_path)
        logger.info("IsolationForest обучен и сохранён: %s", self.model_path)

    def load(self) -> bool:
        """Загружает модель с диска.

        Returns:
            True, если модель успешно загружена, иначе False.
        """
        if os.path.exists(self.model_path):
            self.model = joblib.load(self.model_path)
            return True
        if self.fallback_path and os.path.exists(self.fallback_path):
            self.model = joblib.load(self.fallback_path)
            return True
        return False

    def predict(self, X: Union[pd.DataFrame, np.ndarray]) -> Tuple[np.ndarray, np.ndarray]:
        """Возвращает предсказания и decision_function.

        Args:
            X: Матрица признаков.

        Returns:
            preds: -1 = аномалия, 1 = норма.
            decision: decision_function (чем меньше, тем объект “аномальнее”).
        """
        preds = self.model.predict(X)
        decision = self.model.decision_function(X)
        return preds, decision


def _normalize_quantiles(values: Iterable[float]) -> List[float]:
    out: List[float] = []
    for raw in values:
        try:
            q = float(raw)
        except Exception:
            continue
        q = min(max(q, 0.5), 0.9999)
        out.append(q)
    if not out:
        return []
    out = sorted(set(out))
    return out


def compute_anomaly_stats(
    X: Union[pd.DataFrame, np.ndarray],
    *,
    model: IsolationForest,
    quantiles: Iterable[float],
) -> Dict[str, Any]:
    """Computes baseline anomaly score stats for thresholding."""
    decision = model.decision_function(X)
    score = -decision.astype(float)
    quantiles = _normalize_quantiles(quantiles)
    q_map = {str(q): float(np.quantile(score, q)) for q in quantiles}
    return {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "rows": int(len(score)),
        "score_min": float(np.min(score)) if len(score) else 0.0,
        "score_max": float(np.max(score)) if len(score) else 0.0,
        "score_mean": float(np.mean(score)) if len(score) else 0.0,
        "score_std": float(np.std(score)) if len(score) else 0.0,
        "quantiles": q_map,
    }


def save_anomaly_stats(stats: Dict[str, Any], path: str) -> bool:
    """Saves anomaly stats to JSON."""
    if not path:
        return False
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(stats, fh, ensure_ascii=False, indent=2)
        logger.info("IsolationForest stats saved: %s", path)
        return True
    except Exception as exc:
        logger.warning("Failed to save IsolationForest stats (%s): %s", path, exc)
        return False


def load_anomaly_stats(path: Optional[str], fallback_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Loads anomaly stats from JSON."""
    for candidate in (path, fallback_path):
        if not candidate or not os.path.exists(candidate):
            continue
        try:
            with open(candidate, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except Exception as exc:
            logger.warning("Failed to load IsolationForest stats (%s): %s", candidate, exc)
            return None
    return None


def _select_stats_threshold(stats: Dict[str, Any], target_q: float) -> Optional[float]:
    quantiles = stats.get("quantiles") or {}
    parsed: List[Tuple[float, float]] = []
    for key, value in quantiles.items():
        try:
            parsed.append((float(key), float(value)))
        except Exception:
            continue
    if parsed:
        parsed.sort(key=lambda item: abs(item[0] - target_q))
        return float(parsed[0][1])
    score_max = stats.get("score_max")
    return float(score_max) if score_max is not None else None


def _normalize_scores(scores: np.ndarray, stats: Optional[Dict[str, Any]]) -> np.ndarray:
    if stats and isinstance(stats, dict):
        s_min = stats.get("score_min")
        s_max = stats.get("score_max")
        if s_min is not None and s_max is not None:
            s_min = float(s_min)
            s_max = float(s_max)
            if s_max > s_min:
                return np.clip((scores - s_min) / (s_max - s_min), 0.0, 1.0)
    s_min = float(np.min(scores))
    s_max = float(np.max(scores))
    if s_max > s_min:
        return (scores - s_min) / (s_max - s_min)
    return np.zeros_like(scores)


def detect_anomalies(
    X: Union[pd.DataFrame, np.ndarray],
    *,
    source_ips: Optional[List[str]] = None,
    # Старый режим: если threshold задан, используем (pred=-1 AND decision < threshold)
    threshold: Optional[float] = None,
    # Новый режим по умолчанию: выбираем аномалии по квантилю аномальности
    strategy: str = "baseline",  # "baseline" | "quantile" | "threshold"
    quantile: float = 0.99,
    max_alerts: int = 50,
    require_pred_minus1: bool = True,
    # Поведение при отсутствии baseline модели:
    # True  -> обучаем на текущем батче и возвращаем []
    # False -> возвращаем [] без обучения
    bootstrap_if_missing: bool = True,
) -> List[Dict[str, Any]]:
    """Ищет аномалии в X и возвращает список алертов в едином формате.

    Ключевые определения:
    - decision_function: чем меньше, тем объект аномальнее.
    - anomaly_score = -decision_function: чем больше, тем объект аномальнее.
    - probability: нормированный anomaly_score в диапазоне 0..1 (нормировка на текущем батче).

    Args:
        X: Матрица признаков.
        source_ips: Список IP, параллельный строкам X (опционально).
        threshold: Порог decision_function для режима threshold.
        strategy: "quantile" (по умолчанию) или "threshold".
        quantile: Квантиль anomaly_score (например 0.99 = топ-1%).
        max_alerts: Максимум аномалий за прогон.
        require_pred_minus1: Требовать ли условие preds == -1.
        bootstrap_if_missing: Если baseline отсутствует — обучить на текущем X и вернуть [].

    Returns:
        Список словарей-алертов. Поле probability нормировано 0..1.
    """
    policy = AnomalyPolicy()

    # Применяем env-конфигурацию, если параметр не задан явно вызывающим кодом
    if max_alerts == 50:
        max_alerts = policy.max_alerts
    if quantile == 0.99:
        quantile = policy.quantile
    if require_pred_minus1 is True:
        require_pred_minus1 = policy.require_pred_minus1
    if not strategy:
        strategy = policy.strategy
    strategy = str(strategy).strip().lower()

    det = AnomalyDetector(
        contamination=policy.contamination,
        model_path=IFOREST_MODEL_PATH,
        fallback_path=cfg.IFOREST_PRETRAINED_PATH,
    )

    if not det.load():
        if bootstrap_if_missing:
            # Bootstrap baseline: чтобы pipeline работал "из коробки" для real режима.
            if isinstance(X, pd.DataFrame) and X.empty:
                logger.warning("IsolationForest отсутствует и X пустой — bootstrap невозможен. Аномалии пропущены.")
                return []
            if isinstance(X, np.ndarray) and X.size == 0:
                logger.warning("IsolationForest отсутствует и X пустой — bootstrap невозможен. Аномалии пропущены.")
                return []

            logger.info("IsolationForest модель не найдена: %s. Выполняю bootstrap-обучение baseline на текущем батче.", det.model_path)
            try:
                det.fit(X)
            except Exception as exc:
                logger.warning("Bootstrap-обучение IsolationForest не удалось: %s. Аномалии пропущены.", exc)
            return []

        logger.warning("IsolationForest модель не найдена: %s (аномалии пропущены)", det.model_path)
        return []

    preds, decision = det.predict(X)

    # anomaly_score: больше = аномальнее
    anomaly_score = -decision.astype(float)

    baseline_stats: Optional[Dict[str, Any]] = None
    threshold_score: Optional[float] = None

    # Выбор индексов-кандидатов
    if strategy == "baseline":
        baseline_stats = load_anomaly_stats(
            getattr(cfg, "IFOREST_STATS_PATH", None),
            getattr(cfg, "IFOREST_STATS_PRETRAINED_PATH", None),
        )
        if baseline_stats:
            baseline_q = float(policy.baseline_quantile)
            baseline_q = min(max(baseline_q, 0.5), 0.9999)
            threshold_score = _select_stats_threshold(baseline_stats, baseline_q)
        if threshold_score is not None:
            mask = anomaly_score >= threshold_score
        else:
            mask = preds == -1
    elif threshold is not None or strategy == "threshold":
        thr = float(threshold) if threshold is not None else float(policy.decision_threshold)
        mask = decision < thr
    else:
        q = float(quantile)
        q = min(max(q, 0.5), 0.9999)
        thr_score = float(np.quantile(anomaly_score, q))
        mask = anomaly_score >= thr_score

    norm = _normalize_scores(anomaly_score, baseline_stats if strategy == "baseline" else None)

    if require_pred_minus1:
        mask = mask & (preds == -1)

    idx = np.where(mask)[0].tolist()
    if not idx:
        return []

    # Сортируем по убыванию аномальности
    idx.sort(key=lambda i: anomaly_score[i], reverse=True)
    if max_alerts > 0:
        idx = idx[:max_alerts]

    score_cap: Optional[float] = None
    if threshold_score is not None and baseline_stats:
        try:
            score_cap = float(baseline_stats.get("score_max"))
        except Exception:
            score_cap = None

    alerts: List[Dict[str, Any]] = []
    now = datetime.now().isoformat()

    for i in idx:
        ip = source_ips[i] if source_ips and i < len(source_ips) else None
        if threshold_score is not None and score_cap is not None and score_cap > threshold_score:
            prob = (float(anomaly_score[i]) - float(threshold_score)) / (score_cap - float(threshold_score))
            prob = float(np.clip(prob, 0.0, 1.0))
        else:
            prob = float(norm[i])
        alerts.append(
            {
                "alert": 1,
                "type": "Anomaly",
                "probability": prob,  # 0..1
                "timestamp": now,
                "source_ip": ip,
            }
        )

    return alerts
