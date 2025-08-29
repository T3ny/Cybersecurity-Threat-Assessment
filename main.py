from flask import Flask, render_template, request, redirect, url_for, session
import pandas as pd
from ctad_model.ml_model import predict_threat
import json
import os
import platform
import socket
import psutil
import tempfile
import uuid
from config import auth_client
from werkzeug.utils import secure_filename
from collections import Counter
from functools import wraps
from dotenv import load_dotenv
import datetime

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "fallbackkey")


from functools import wraps

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


# Load datasets
cve_csv_path = "ctad_data/allitems.csv"
cve_json_path = "ctad_data/nvdcve-2.0-modified.json"
df_csv = pd.read_csv(cve_csv_path, encoding='latin1', low_memory=False)
df_csv = df_csv.dropna(subset=['Name', 'Description'])

with open(cve_json_path, 'r', encoding='utf-8') as f:
    json_data = json.load(f)
    vulnerabilities = json_data.get('vulnerabilities', [])

THREAT_WEIGHTS = {
    "Remote Code Execution": 5,
    "Privilege Escalation": 4,
    "Denial of Service": 3,
    "Information Disclosure": 2,
    "Buffer Overflow": 4,
    "SQL Injection": 5,
    "Cross-Site Scripting": 3,
    "Authentication Bypass": 4,
    "Insecure Defaults": 2,
    "Command Injection": 5
}

THREAT_KEYWORDS = {
    "Remote Code Execution": ["remote code execution", "rce"],
    "Privilege Escalation": ["privilege escalation", "elevation of privilege"],
    "Denial of Service": ["denial of service", "dos attack"],
    "Information Disclosure": ["information disclosure", "data leak"],
    "Buffer Overflow": ["buffer overflow"],
    "SQL Injection": ["sql injection"],
    "Cross-Site Scripting": ["xss", "cross-site scripting"],
    "Authentication Bypass": ["authentication bypass"],
    "Insecure Defaults": ["default password", "insecure default"],
    "Command Injection": ["command injection"]
}

def score_risk(description):
    score = 0
    matched = []
    for threat, keywords in THREAT_KEYWORDS.items():
        for keyword in keywords:
            if keyword in description.lower():
                score += THREAT_WEIGHTS[threat]
                matched.append(threat)
                break
    return score, matched

def get_risk_level(score):
    if score >= 8:
        return "High", "danger"
    elif score >= 4:
        return "Medium", "warning"
    else:
        return "Low", "success"

def get_system_info():
    return {
        "OS": platform.system(),
        "OS Version": platform.version(),
        "Processor": platform.processor(),
        "CPU Cores": psutil.cpu_count(logical=True),
        "Memory (GB)": round(psutil.virtual_memory().total / (1024 ** 3), 2),
        "Hostname": socket.gethostname(),
        "IP Address": socket.gethostbyname(socket.gethostname())
    }

@app.route('/')
@login_required
def index():
    system_info = get_system_info()
    return render_template('index.html', threats=THREAT_WEIGHTS.keys(), system_info=system_info)

@app.route('/dashboard')
@login_required
def dashboard():
    user_email = session.get('user')
    analysis_history = session.get('upload_history', [])

    # Counters to collect stats from existing dataset
    threat_counter = Counter()
    risk_counter = Counter()

    for _, row in df_csv.iterrows():
        description = row['Description']
        predicted_threat = predict_threat(description)
        matched_threats = [predicted_threat]
        score = THREAT_WEIGHTS.get(predicted_threat, 1)
        level, _ = get_risk_level(score)

        threat_counter.update(matched_threats)
        risk_counter[level] += 1

        PRECOMPUTED_DASHBOARD_DATA = {
        "threat_counts": dict(threat_counter),
        " risk_counts": dict(risk_counter)
    }

    return render_template(
        'dashboard.html',
        user_email=user_email,
        history=analysis_history,
        **PRECOMPUTED_DASHBOARD_DATA
    )


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        try:
            auth_client.create_user_with_email_and_password(email, password)
            return redirect(url_for('login'))
        except Exception as e:
            return render_template('signup.html', e, error = 'sorry email already exist')
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        try:
            user = auth_client.sign_in_with_email_and_password(email, password)
            session['user'] = user.get('email', email)
            return redirect(url_for('dashboard'))
        except Exception as e:
            print("Invalid email or password: " , e)
            return render_template('login.html', error="Invalid email or password ")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        email = request.form['email']
        try:
            auth_client.send_password_reset_email(email)
            return render_template('reset_password.html', message="Password reset email sent.")
        except Exception as e:
            return render_template('reset_password.html', error="Error sending reset email.")
    return render_template('reset_password.html')


@app.route('/analyze', methods=['POST'])
@login_required
def analyze():
    selected_threats = request.form.getlist('threats')
    if not selected_threats:
        return render_template('index.html', threats=THREAT_WEIGHTS.keys(), system_info=get_system_info(),
                            error="⚠️ You must select at least one threat type.")
    risk_level_filter = request.form.get('risk_level')
    domain_filter = request.form.get('domain')
    selected_threats_lower = [t.lower() for t in selected_threats]
    results = []
    threat_counter = Counter()
    risk_counter = Counter()
    domain_counter = Counter()

    for _, row in df_csv.iterrows():
        predicted_threat = predict_threat(row['Description'])
        matched_threats = [predicted_threat]
        score = THREAT_WEIGHTS.get(predicted_threat, 1)
        level, color = get_risk_level(score)
        if not any(mt.lower() in selected_threats_lower for mt in matched_threats):
            continue
        level, color = get_risk_level(score)

        domain = "Application"
        if any(x in row['Description'].lower() for x in ["network", "tcp", "port"]):
            domain = "Network"
        elif any(x in row['Description'].lower() for x in ["kernel", "os", "driver"]):
            domain = "Operating System"

        if risk_level_filter and risk_level_filter != level:
            continue
        if domain_filter and domain_filter != domain:
            continue

        threat_counter.update(matched_threats)
        risk_counter[level] += 1
        domain_counter[domain] += 1

        results.append({
            'id': row['Name'],
            'description': row['Description'],
            'impact': level,
            'score': score,
            'matched': ", ".join(matched_threats),
            'color': color,
            'domain': domain,
            'advice': generate_advice(matched_threats)
        })

    results = sorted(results, key=lambda x: x['score'], reverse=True)[:50]
    return render_template('Results.html', data=results,
                            risk_counts=dict(risk_counter),
                            threat_counts=dict(threat_counter),
                            domain_counts=dict(domain_counter))

def generate_advice(threats):
    advice_map = {
        "Remote Code Execution": "Apply patches immediately and restrict remote access.",
        "Privilege Escalation": "Harden system permissions and audit user roles.",
        "Denial of Service": "Rate-limit requests and use firewalls.",
        "Information Disclosure": "Encrypt sensitive data and reduce logging exposure.",
        "Buffer Overflow": "Use safe memory functions and apply system updates.",
        "SQL Injection": "Sanitize database inputs and use prepared statements.",
        "Cross-Site Scripting": "Escape HTML and validate user input.",
        "Authentication Bypass": "Implement MFA and validate authentication paths.",
        "Insecure Defaults": "Enforce secure configuration policies.",
        "Command Injection": "Sanitize shell inputs and avoid unsafe calls."
    }
    return [advice_map[t] for t in threats if t in advice_map]

ALLOWED_EXTENSIONS = {'csv', 'json'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload', methods=['POST'])
@login_required
def upload():
    if 'file' not in request.files:
        return "No file part", 400

    file = request.files['file']
    if file.filename == '':
        return "No selected file", 400

    if file and allowed_file(file.filename):
        unique_filename = f"{uuid.uuid4().hex}_{secure_filename(file.filename)}"
        temp_path = os.path.join(tempfile.gettempdir(), unique_filename)
        file.save(temp_path)

        ext = unique_filename.rsplit('.', 1)[1].lower()
        if ext == 'csv':
            df = pd.read_csv(temp_path, encoding='latin1')
        elif ext == 'json':
            with open(temp_path, 'r', encoding='utf-8') as f:
                json_data = json.load(f)
            df = pd.DataFrame(json_data.get('vulnerabilities', []))

        df = df.dropna(subset=['Description'])
        results = []
        for _, row in df.iterrows():
            desc = row.get('Description') or row.get('description') or ""
            cve_id = row.get('Name') or row.get('cve') or row.get('id') or "Unknown"
            predicted_threat = predict_threat(desc)
            matched_threats = [predicted_threat]
            score = THREAT_WEIGHTS.get(predicted_threat, 1)
            level, color = get_risk_level(score)
            level, color = get_risk_level(score)
            results.append({
                'id': cve_id,
                'description': desc,
                'impact': level,
                'score': score,
                'matched': ", ".join(matched_threats),
                'color': color,
                'advice': generate_advice(matched_threats)
            })

        # Save upload history in session
        if 'upload_history' not in session:
            session['upload_history'] = []

        session['upload_history'].append({
            "filename": file.filename,
            "date": datetime.datetime.now().strftime("%Y-%m-%d"),
            "result_url": "#"  # Add actual result view route later
        })

        results = sorted(results, key=lambda x: x['score'], reverse=True)[:50]
        return render_template('results.html', data=results)
    else:
        return "Invalid file type", 400

if __name__ == '__main__':
    app.run(debug=True)
