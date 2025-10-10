from flask import Flask, jsonify

app = Flask(__name__)

@app.route('/health')
def health():
    return jsonify({'status': 'OK'})

@app.route('/dashboard')
def dashboard():
    return 'Dashboard placeholder'

if __name__ == '__main__':
    app.run(debug=True)