# train_anomaly.py
from modules.preprocessor import preprocess_data
from modules.anomaly_detector import AnomalyDetector

result = preprocess_data('data/collected_traffic.csv')
X_train = result['X_train'].select_dtypes(include=['float64', 'int64'])

detector = AnomalyDetector()
detector.fit(X_train)
print("Anomaly model обучен")