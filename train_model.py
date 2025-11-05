from modules.preprocessor import preprocess_data
from modules.analyzer import Analyzer

if __name__ == "__main__":
    result = preprocess_data('data/collected_traffic.csv')
    X_train = result['X_train'].drop(columns=['label_encoded'], errors='ignore')
    X_test = result['X_test']
    y_train = result['y_train']
    y_test = result['y_test']

    if X_train is None or y_train is None:
        print("Ошибка: X_train или y_train is None")
        exit()

    print("X_train shape:", X_train.shape)
    print("X_train dtypes:", X_train.dtypes.unique())  # Должно быть только float64

    analyzer = Analyzer(model_type='rf')
    analyzer.train_model(X_train, y_train)
    metrics = analyzer.evaluate(X_test, y_test)
    print(f"F1-score: {metrics['f1_score']:.4f}")