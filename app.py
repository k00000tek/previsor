from flask import Flask, jsonify, request
from modules.data_collector import collect_traffic
from modules.preprocessor import preprocess_data
from celery_app import celery

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

if __name__ == '__main__':
    app.run(debug=True)