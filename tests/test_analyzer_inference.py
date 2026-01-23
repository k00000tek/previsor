# tests/test_analyzer_inference.py
from modules.preprocessor import preprocess_data
from modules.analyzer import Analyzer

def test_analyzer_on_processed_data():
    result = preprocess_data('data/collected_traffic.csv')
    X_test = result['X_test']

    analyzer = Analyzer(model_type='rf')
    analyzer.model_path = 'models/previsor_model.pkl'
    alerts = analyzer.analyze(X_test.values, source_ips=None)

    assert len(alerts) == len(X_test)
