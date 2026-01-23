from flask import Flask, jsonify, request, render_template
from modules.data_collector import collect_traffic
from celery_app import celery
from modules.analyzer import Analyzer
from modules.preprocessor import preprocess_data
from modules.database import save_alert, get_alerts
import pandas as pd
import os
import logging

# Настройка логирования
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)

@app.route('/health')
def health():
    return jsonify({'status': 'OK'})

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

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
    file_path = None
    try:
        if 'file' in request.files:
            file = request.files['file']
            file_path = os.path.join('data', f"uploaded_{file.filename}")
            file.save(file_path)
        else:
            # Пытаемся взять путь из query-параметра
            file_path = request.args.get('file', 'data/collected_traffic_processed.csv')

        # Читаем CSV
        df = pd.read_csv(file_path)

        # Извлекаем source_ip
        source_ips = df['source_ip'].tolist() if 'source_ip' in df.columns else [None] * len(df)

        # Удаляем нечисловые, кроме source_ip
        X = df.select_dtypes(include=['int64', 'float64']).drop(columns=['label_encoded'], errors='ignore')

        # Загружаем модель
        alerts = analyzer.analyze(X.values, source_ips=source_ips)

        for alert in alerts:
            if alert['alert']:
                save_alert(
                    alert_type=alert['type'],
                    probability=alert['probability'],
                    source_ip=alert.get('source_ip')
                )

        return jsonify({
            'status': 'Анализ завершён',
            'alerts_found': sum(a['alert'] for a in alerts),
            'alerts': alerts[:10]
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        if file_path and file_path.startswith('data/uploaded_'):
            try:
                os.remove(file_path)
                logging.info(f"Удалён временный файл: {file_path}")
            except:
                pass

@app.route('/alerts')
def alerts_api():
    alert_type = request.args.get('type')
    limit = int(request.args.get('limit', 50))
    alerts = get_alerts(alert_type=alert_type, limit=limit)
    return jsonify([{
        'id': a.id,
        'timestamp': a.timestamp.isoformat(),
        'type': a.alert_type,
        'probability': a.probability,
        'source_ip': a.source_ip,
        'status': a.status
    } for a in alerts])

if __name__ == '__main__':
    app.run(debug=True)