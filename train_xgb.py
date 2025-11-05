from modules.preprocessor import preprocess_data
from modules.analyzer import Analyzer

if __name__ == "__main__":
    result = preprocess_data('data/collected_traffic.csv')
    X_train = result['X_train'].drop(columns=['label_encoded'], errors='ignore')
    X_test = result['X_test']
    y_train = result['y_train']
    y_test = result['y_test']

    analyzer = Analyzer(model_type='xgb')
    analyzer.model_path = 'models/previsor_model_xgb.pkl'  # ← отдельный файл
    analyzer.report_path = 'models/last_report_xgb.txt'

    analyzer.train_model(X_train, y_train)
    metrics = analyzer.evaluate(X_test, y_test)
    print(f"XGBoost F1-score: {metrics['f1_score']:.4f}")