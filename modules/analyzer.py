import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, f1_score
from xgboost import XGBClassifier
import joblib
import logging
import os
from datetime import datetime
from utils.api_integration import enrich_alert_with_reputation

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class Analyzer:
    def __init__(self, model_type='rf'):
        self.model_type = model_type.lower()
        self.model = None
        self.label_encoder = None
        self.model_path = 'models/previsor_model.pkl'
        self.report_path = 'models/last_report.txt'
        os.makedirs('models', exist_ok=True)

    def train_model(self, X_train, y_train):
        """Обучение модели."""
        logging.info(f"Запуск обучения модели: {self.model_type.upper()}")

        if self.model_type == 'rf':
            self.model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
        elif self.model_type == 'xgb':
            self.model = XGBClassifier(use_label_encoder=False, eval_metric='mlogloss', random_state=42)
        else:
            raise ValueError("model_type должен быть 'rf' или 'xgb'")

        self.model.fit(X_train, y_train)
        logging.info("Обучение завершено")

        # Сохранение модели
        self.save_model()
        return self.model

    def evaluate(self, X_test, y_test):
        """Оценка модели."""
        if self.model is None:
            raise ValueError("Модель не обучена. Сначала вызовите train_model()")

        y_pred = self.model.predict(X_test)
        f1 = f1_score(y_test, y_pred, average='weighted')
        report = classification_report(y_test, y_pred, output_dict=True)

        # Сохранение отчёта
        with open(self.report_path, 'w', encoding='utf-8') as f:
            f.write(f"Отчёт по модели {self.model_type.upper()} ({datetime.now()})\n")
            f.write(f"F1-score (weighted): {f1:.4f}\n\n")
            f.write(classification_report(y_test, y_pred))
            f.write("\nМатрица ошибок:\n")
            f.write(str(confusion_matrix(y_test, y_pred)))

        logging.info(f"F1-score: {f1:.4f}")
        logging.info(f"Отчёт сохранён: {self.report_path}")
        return {'f1_score': f1, 'report': report}

    def analyze(self, X, source_ips=None) -> list:
        """Инференс: предсказание угроз и расчёт риска."""
        if self.model is None:
            self.load_model()

        if self.model is None:
            raise ValueError("Модель не найдена. Обучите или загрузите модель.")

        # Предсказания модели
        probs = self.model.predict_proba(X)              # shape: (n_samples, n_classes)
        pred = self.model.predict(X)                     # предсказанные классы (int)
        max_prob = np.max(probs, axis=1)                 # максимальная вероятность по классам

        alerts = []
        for i, (p, base_prob) in enumerate(zip(pred, max_prob)):
            ip = source_ips[i] if source_ips and i < len(source_ips) else None
            label = self._decode_label(p)

            # Базовая вероятность (из модели)
            base_prob = float(base_prob)

            # Обогащаем риск репутацией IP (AbuseIPDB)
            risk_score = enrich_alert_with_reputation(label, base_prob, ip)
            risk_score = float(risk_score)

            # Определяем, нормальный ли это трафик ПО ПРЕДСКАЗАННОМУ КЛАССУ
            label_lower = str(label).lower()
            is_normal = (
                label_lower.startswith("normal") or
                "benign" in label_lower or
                "background" in label_lower
            )
            is_attack = not is_normal

            # Порог срабатывания по риск-скорe (пока простой, потом усложним)
            THRESHOLD = 0.95
            is_alert = bool(is_attack and risk_score >= THRESHOLD)

            alert = {
                "alert": int(is_alert),
                "type": label,
                # base_probability — как считает модель без учёта репутации
                "base_probability": base_prob,
                # probability — уже обогащённый риск (то, что пишем в БД)
                "probability": risk_score,
                "timestamp": datetime.now().isoformat(),
                "source_ip": ip,
            }
            alerts.append(alert)

            if is_alert:
                logging.warning(
                    f"УГРОЗА: {label} "
                    f"(base_prob={base_prob:.2f}, risk={risk_score:.2f}, IP={ip})"
                )

        return alerts

    def save_model(self):
        """Сохранение модели."""
        joblib.dump(self.model, self.model_path)
        logging.info(f"Модель сохранена: {self.model_path}")

    def load_model(self):
        """Загрузка модели."""
        if os.path.exists(self.model_path):
            self.model = joblib.load(self.model_path)
            logging.info(f"Модель загружена: {self.model_path}")
        else:
            logging.error(f"Модель не найдена: {self.model_path}")
            self.model = None

    def _decode_label(self, encoded):
        """Обратное преобразование label_encoded → оригинал."""
        # Пока заглушка — в будущем будет из preprocessor
        try:
            le = joblib.load('models/label_encoder.pkl')
            return le.inverse_transform([encoded])[0]
        except:
            # fallback
            labels = {0: 'Normal', 1: 'DDoS', 2: 'PortScan', 3: 'Brute_Force'}
            return labels.get(encoded, 'Unknown')