from flask import Flask, jsonify, request
from modules.data_collector import collect_traffic
from modules.preprocessor import preprocess_data
from celery_app import celery
from modules.analyzer import Analyzer
from modules.preprocessor import preprocess_data
import pandas as pd

app = Flask(__name__)

@app.route('/health')
def health():
    return jsonify({'status': 'OK'})

@app.route('/dashboard')
def dashboard():
    return 'Dashboard placeholder'

@app.route('/collect', methods=['GET'])
def collect():
    df = collect_traffic(mode='simulated', num_packets=50)
    return jsonify({'status': 'Сбор завершён', 'rows': len(df)})

@app.route('/preprocess', methods=['GET'])
def preprocess_endpoint():
    file = request.args.get('file', 'data/collected_traffic.csv')
    try:
        result = preprocess_data(file)
        return jsonify({'status': 'Предобработка завершена', 'rows': len(result['processed_df'])})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/analyze', methods=['POST'])
def analyze_endpoint():
    model_type = request.form.get('model', 'rf')  # rf или xgb
    analyzer = Analyzer(model_type=model_type)
    if model_type == 'xgb':
        analyzer.model_path = 'models/previsor_model_xgb.pkl'

    try:
        if 'file' in request.files:
            file = request.files['file']
            file_path = f"data/uploaded_{file.filename}"
            file.save(file_path)
        else:
            file_path = 'data/collected_traffic_processed.csv'

        # Читаем CSV
        df = pd.read_csv(file_path)

        # УДАЛЯЕМ НЕЧИСЛОВЫЕ
        df = df.select_dtypes(include=['int64', 'float64'])
        df = df.drop(columns=['label_encoded'], errors='ignore')

        X = df.values  # → numpy array

        # Загружаем модель

        alerts = analyzer.analyze(X)

        return jsonify({
            'status': 'Анализ завершён',
            'alerts_found': sum(a['alert'] for a in alerts),
            'alerts': alerts[:10]
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)