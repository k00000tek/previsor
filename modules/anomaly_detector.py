# modules/anomaly_detector.py
from sklearn.ensemble import IsolationForest
import joblib
import logging
import os
from datetime import datetime

class AnomalyDetector:
    def __init__(self):
        self.model = IsolationForest(contamination=0.1, random_state=42)  # 10% аномалий
        self.model_path = 'models/isolation_forest.pkl'

    def fit(self, X):
        self.model.fit(X)
        joblib.dump(self.model, self.model_path)
        logging.info("IsolationForest обучен")

    def predict(self, X):
        preds = self.model.predict(X)  # -1 = аномалия, 1 = норма
        scores = self.model.decision_function(X)  # чем ниже, тем аномальнее
        return preds, scores

def detect_anomalies(X, source_ips=None, threshold=-0.1):
    det = AnomalyDetector()
    if os.path.exists(det.model_path):
        det.model = joblib.load(det.model_path)
    else:
        logging.error("IsolationForest модель не найдена")
        return []

    preds, scores = det.predict(X)
    alerts = []
    for i, (p, s) in enumerate(zip(preds, scores)):
        if p == -1 and s < threshold:
            ip = source_ips[i] if source_ips and i < len(source_ips) else None
            alerts.append({
                'alert': 1,
                'type': 'Anomaly',
                'probability': float(-s),   # условная «степень аномальности»
                'timestamp': datetime.now().isoformat(),
                'source_ip': ip,
            })
    return alerts