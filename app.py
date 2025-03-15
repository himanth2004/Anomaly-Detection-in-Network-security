from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import sqlite3
import datetime
import numpy as np
import pandas as pd
import joblib
import bcrypt
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from sklearn.preprocessing import LabelEncoder


app = Flask(__name__)
CORS(app)



logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

model_data = joblib.load('model.joblib')
model = model_data['model']
scaler = model_data['scaler']

tcp_flags_encoder = LabelEncoder()
protocol_encoder = LabelEncoder()
l7_proto_encoder = LabelEncoder()

tcp_flags_encoder.fit(["SYN", "ACK", "FIN", "RST", "PSH", "URG", "ECE", "CWR", "NS"])
protocol_encoder.fit(["TCP", "UDP", "ICMP", "IP", "SNMP", "SSL", "TLS", "IPsec"])
l7_proto_encoder.fit(["HTTP", "FTP", "DNS", "HTTPS", "SMTP", "IMAP", "POP3", "SSH"])

DATABASE = "database.db"

EMAIL_SENDER = "hvmanomalydetection@gmail.com"
EMAIL_PASSWORD ="emfw ujyy heaq ombp"

def get_db_connection():
    
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL
        );
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        date TEXT NOT NULL,
        time TEXT NOT NULL,
        src_port INTEGER NOT NULL,
        dst_port INTEGER NOT NULL,
        tcp_flags TEXT NOT NULL,
        protocol TEXT NOT NULL,
        l7_proto TEXT NOT NULL,
        threats_detected INTEGER NOT NULL,
        status TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
""")


    conn.commit()
    conn.close()

def hash_password(password):
    if not password:
        return None
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()  

def check_password(hashed_password, user_password):
    return bcrypt.checkpw(user_password.encode(), hashed_password.encode()) 

def send_email(recipient_email, status, threats_detected):
    subject = "Network Analysis Result"
    body = f"""
    Hello,

    Your network analysis has been completed.

    📌 Status: {status}
    🔴 Threats Detected: {threats_detected}

    Stay Safe,
    by
    Network Security 
    """

    msg = MIMEMultipart()
    msg['From'] = EMAIL_SENDER
    msg['To'] = recipient_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.sendmail(EMAIL_SENDER, recipient_email, msg.as_string())
        print("✅ Email sent successfully.")
    except Exception as e:
        print("❌ Error sending email:", e)



@app.route('/')
def home():
    return render_template('landingpage.html')
@app.route("/register", methods=["POST"])
def register():
    """Register a new user"""
    data = request.get_json()
    print("📩 Received Data:", data)  # Debugging output

    if not data:
        return jsonify({"message": "No data received"}), 400

    username = data.get("username")
    password = data.get("password")
    email = data.get("email")

    if not username or not password or not email:
        print("❌ Missing fields: Username, Password, or Email is empty")
        return jsonify({"message": "Username, password, and email are required"}), 400

    hashed_password = hash_password(password)

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("INSERT INTO users (username, password, email) VALUES (?, ?, ?)", 
                       (username, hashed_password, email))
        conn.commit()
        print("✅ Registration successful!")
        return jsonify({"message": "Registration successful"}), 201
    except sqlite3.IntegrityError as e:
        print("❌ Integrity Error:", e)
        return jsonify({"message": "Username or email already exists"}), 400
    except Exception as e:
        print("❌ Unexpected Error:", e)
        return jsonify({"message": "Internal server error"}), 500
    finally:
        conn.close()



@app.route('/login.html', methods=["GET"])
def loginpage():
    return render_template('login.html')

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"message": "Username and password are required"}), 400

    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, password FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()

        if user and check_password(user["password"], password):
            return jsonify({
                "message": "Login successful",
                "user_id": user["id"],
                "username": user["username"]
            }), 200
        else:
            return jsonify({"message": "Invalid username or password"}), 401

    except Exception as e:
        logger.error(f"Error in login route: {str(e)}")
        return jsonify({"message": "An error occurred while logging in"}), 500

    finally:
        if conn:
            conn.close()
            
            
@app.route('/main.html', methods=["GET"])
def analyzepage():
    return render_template('main.html')

@app.route("/analyze", methods=["POST"])
def analyze():
    conn = None
    try:
        data = request.get_json()
        user_id = data.get("user_id")

        if not user_id:
            return jsonify({"message": "User ID is required"}), 400

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT email FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()

        if not user:
            return jsonify({"message": "User not found"}), 404

        user_email = user["email"]  # Store email

        L4_SRC_PORT = int(data.get('L4_SRC_PORT', -1))
        L4_DST_PORT = int(data.get('L4_DST_PORT', -1))
        TCP_FLAGS = data.get('TCP_FLAGS', "UNKNOWN")
        PROTOCOL = data.get('PROTOCOL', "UNKNOWN")
        L7_PROTO = data.get('L7_PROTO', "UNKNOWN")

        if not (0 <= L4_SRC_PORT <= 65535) or not (0 <= L4_DST_PORT <= 65535):
            return jsonify({"message": "Invalid port number"}), 400

        try:
            protocol_sum = sum(protocol_encoder.transform([p])[0] for p in PROTOCOL.split('+') if p in protocol_encoder.classes_)
        except ValueError:
            protocol_sum = -1

        try:
            L7_proto_sum = sum(l7_proto_encoder.transform([p])[0] for p in L7_PROTO.split('+') if p in l7_proto_encoder.classes_)
        except ValueError:
            L7_proto_sum = -1

        try:
            TCP_FLAGS = tcp_flags_encoder.transform([TCP_FLAGS])[0] if TCP_FLAGS in tcp_flags_encoder.classes_ else -1
        except ValueError:
            TCP_FLAGS = -1

        input_features = np.array([[L4_SRC_PORT, L4_DST_PORT, TCP_FLAGS, protocol_sum, L7_proto_sum]])
        input_features = scaler.transform(input_features)


        prediction = model.predict(input_features)
        predicted_class = int(prediction[0])

        now = datetime.datetime.now()
        date = now.strftime("%Y-%m-%d")
        time = now.strftime("%H:%M")

        status = "Threat Detected" if predicted_class == 1 else "Safe, No Threat Detected"

        cursor.execute("""
            INSERT INTO history (user_id, date, time, src_port, dst_port, tcp_flags, protocol, l7_proto, threats_detected, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (user_id, date, time, L4_SRC_PORT, L4_DST_PORT, TCP_FLAGS, PROTOCOL, L7_PROTO, predicted_class, status))
        
        conn.commit()

        send_email(user_email, status, predicted_class)

        return jsonify({"message": "Data submitted successfully", "threats_detected": predicted_class, "status": status}), 200

    except Exception as e:
        logger.error(f"Error in submit_network_data: {str(e)}")
        return jsonify({'error': str(e)}), 400

    finally:
        if conn:
            conn.close()

@app.route("/get-user-stats", methods=["GET"])
def get_user_stats():
    user_id = request.args.get("user_id")
    if not user_id:
        return jsonify({"message": "User ID is required"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) as total_checks FROM history WHERE user_id = ?", (user_id,))
    total_checks = cursor.fetchone()["total_checks"]

    cursor.execute("SELECT COUNT(*) as total_threats FROM history WHERE user_id = ? AND threats_detected = 1", (user_id,))
    total_threats = cursor.fetchone()["total_threats"]

    cursor.execute("SELECT COUNT(*) as total_safe FROM history WHERE user_id = ? AND threats_detected = 0", (user_id,))
    total_safe = cursor.fetchone()["total_safe"]

    conn.close()

    return jsonify({"total_checks": total_checks, "total_threats": total_threats, "total_safe": total_safe}), 200

@app.route("/get-user-history", methods=["GET"])
def get_user_history():
    user_id = request.args.get("user_id")

    if not user_id:
        return jsonify({"message": "User ID is required"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM history WHERE user_id = ? ORDER BY date DESC, time DESC", (user_id,))
    history = cursor.fetchall()
    conn.close()

    history_list = []
    for row in history:
        history_list.append({
            "date": row["date"],
            "time": row["time"],
            "src_port": row["src_port"],
            "dst_port": row["dst_port"],
            "tcp_flags": row["tcp_flags"].decode() if isinstance(row["tcp_flags"], bytes) else row["tcp_flags"],
            "protocol": row["protocol"].decode() if isinstance(row["protocol"], bytes) else row["protocol"],
            "l7_proto": row["l7_proto"].decode() if isinstance(row["l7_proto"], bytes) else row["l7_proto"],
            "status": row["status"]
        })

    return jsonify(history_list), 200


@app.route('/ipchecker.html', methods=["GET"])
def ipcheckerpage():
    return render_template('ipchecker.html')


ip_df = pd.read_csv("ips.csv") 
blocked_ips = set(ip_df["IP Address"].astype(str)) 
@app.route("/check_ip", methods=["POST"])
def check_ip():
    data = request.get_json()
    ip_address = data.get("ip_address", "").strip()

    if ip_address in blocked_ips:
        return jsonify({"blocked": True, "message": f"IP {ip_address} is BLOCKED 🚨"})
    else:
        return jsonify({"blocked": False, "message": f"IP {ip_address} is SAFE ✅"})



@app.route('/dashboard.html', methods=["GET"])
def dashboardpage():
    return render_template('dashboard.html')
@app.route('/logout.html', methods=["GET"])
def logoutpage():
    return render_template('logout.html')
@app.route('/landingpage.html', methods=["GET"])
def logoutpage():
    return render_template('landingpage.html')


if __name__ == "__main__":
    init_db()
    app.run(debug=True)