from flask import Flask, request, jsonify, render_template
import joblib
import numpy as np
from sklearn.preprocessing import LabelEncoder
from flask_cors import CORS
import sqlite3
import os

def load_model():
    global model
    if model is None:
        model = joblib.load('model.joblib')

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

@app.route('/', methods=['GET'])
def home():
    return render_template('front.html')

@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({"error": "Method Not Allowed. Use /analyze or /check_ip for POST requests."}), 405

# Check if model file exists
model_path = 'model.joblib'
if not os.path.exists(model_path):
    raise FileNotFoundError(f"Model file {model_path} not found.")

# Load the model once
tcp_flags_encoder = LabelEncoder()
protocol_encoder = LabelEncoder()
l7_proto_encoder = LabelEncoder()

tcp_flags_encoder.fit(["SYN", "ACK", "FIN", "RST", "PSH", "URG", "ECE", "CWR", "NS"])
protocol_encoder.fit(["TCP", "UDP", "ICMP", "IP", "SNMP", "SSL", "TLS", "IPsec"])
l7_proto_encoder.fit(["HTTP", "FTP", "DNS", "HTTPS", "SMTP", "IMAP", "POP3", "SSH"])

model = None
load_model()

@app.route('/analyze', methods=['POST'])
def analyze():
    try:
        data = request.get_json()
        L4_SRC_PORT = int(data.get('L4_SRC_PORT'))
        L4_DST_PORT = int(data.get('L4_DST_PORT'))
        TCP_FLAGS = tcp_flags_encoder.transform([data.get('TCP_FLAGS')])[0]
        protocol_sum = np.sum(protocol_encoder.transform(data.get('PROTOCOL').split('+')))
        L7_proto_sum = np.sum(l7_proto_encoder.transform(data.get('L7_PROTO').split('+')))

        input_features = np.array([[L4_SRC_PORT, L4_DST_PORT, TCP_FLAGS, protocol_sum, L7_proto_sum]], dtype=np.float32)
        prediction = model.predict(input_features)
        prediction_probability = float(prediction[0][0])
        predicted_class = int(prediction_probability > 0.5)

        return jsonify({
            'prediction': predicted_class,
            'prediction_probability': prediction_probability,
            'protocol_combination_sum': f"Sum of Protocols: {protocol_sum} + {L7_proto_sum}"
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 400

def check_ip_in_db(ip_address):
    with sqlite3.connect("network_security.db") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM blocked_ips WHERE ip_address = ?", (ip_address,))
        return cursor.fetchone()[0] > 0

@app.route('/check_ip', methods=['POST'])
def check_ip():
    try:
        data = request.get_json()
        ip_address = data.get("ip_address")
        if not ip_address:
            return jsonify({"error": "IP address is required"}), 400
        return jsonify({"blocked": check_ip_in_db(ip_address)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    from gunicorn.app.base import BaseApplication
    class StandaloneApplication(BaseApplication):
        def __init__(self, app, options=None):
            self.application = app
            self.options = options or {}
            super().__init__()
        def load_config(self):
            for key, value in self.options.items():
                self.cfg.set(key, value)
        def load(self):
            return self.application
    options = {"bind": "0.0.0.0:8080", "workers": 10, "worker_class": "gevent"}  # Reduced workers to 1
    StandaloneApplication(app, options).run()
