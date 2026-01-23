# TODO: черновик мультидатасета

# train_multidataset.py
from modules.preprocessor import preprocess_data
from modules.anomaly_detector import AnomalyDetector
from modules.analyzer import Analyzer

# 1. Объединение
df = pd.concat([
    pd.read_csv('../data/cicids2017_processed.csv'),
    pd.read_csv('../data/mscad_processed.csv')
])

# 2. Предобработка
result = preprocess_data(df, save_csv=False)
X_train, y_train = result['X_train'], result['y_train']

# 3. Anomaly
anomaly = AnomalyDetector()
anomaly.fit(X_train)

# 4. Классификация
analyzer = Analyzer()
analyzer.train_model(X_train, y_train)