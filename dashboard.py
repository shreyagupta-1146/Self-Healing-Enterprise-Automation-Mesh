import json
import os
import random
import threading
import time
import requests
import dotenv
from flask import Flask, jsonify, request

try:
    from flask_cors import CORS
    _has_cors = True
except ImportError:
    _has_cors = False

# Load environment variables
dotenv.load_dotenv()

app = Flask(__name__)
if _has_cors:
    CORS(app, resources={r"/api/*": {"origins": "*"}})

BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "").strip()

# Global states for threat approval bridge
threat_await_active = False
threat_approval_status = "PENDING"
threat_await_start_time = 0.0
threat_await_timeout = 90.0

# Active OTPs for admin login
active_otps = {}

# User file lock
users_lock = threading.Lock()

def load_users():
    with users_lock:
        if not os.path.exists("data/users.json"):
            return {}
        try:
            with open("data/users.json", "r") as f:
                return json.load(f)
        except Exception as e:
            print(f"[AUTH] Error loading users: {e}")
            return {}

def save_users(users):
    with users_lock:
        try:
            with open("data/users.json", "w") as f:
                json.dump(users, f, indent=2)
            return True
        except Exception as e:
            print(f"[AUTH] Error saving users: {e}")
            return False

def init_db():
    if not os.path.exists("data"):
        os.makedirs("data")
    if not os.path.exists("data/users.json"):
        with open("data/users.json", "w") as f:
            json.dump({
                "admin": {
                    "password": "sentinel2026",
                    "role": "admin",
                    "status": "approved",
                    "access_code": None
                }
            }, f, indent=2)

def handle_user_approval_action(username, action):
    users = load_users()
    if username not in users:
        return f"❌ User {username} not found."
    
    user = users[username]
    if user["status"] != "pending":
        return f"⚠️ User {username} is already {user['status']}."
    
    if action == "approve_user":
        # Generate 6-digit static access code
        access_code = "".join([str(random.randint(0, 9)) for _ in range(6)])
        user["status"] = "approved"
        user["access_code"] = access_code
        save_users(users)
        return f"✅ *Registration Approved*\n\n*Username:* {username}\n*Assigned Access Code:* `{access_code}`\n\nApproved at: {time.strftime('%Y-%m-%d %H:%M:%S')}"
    elif action == "reject_user":
        user["status"] = "rejected"
        save_users(users)
        return f"❌ *Registration Rejected*\n\n*Username:* {username}\n\nRejected at: {time.strftime('%Y-%m-%d %H:%M:%S')}"
    
    return "Unknown action."

def telegram_poller():
    if not BOT_TOKEN or BOT_TOKEN == "YOUR_TELEGRAM_BOT_TOKEN":
        print("[TELEGRAM POLLER] Warning: Telegram Bot Token not configured. Poller thread disabled.")
        return
    
    print("[TELEGRAM POLLER] Poller thread started.")
    offset = 0
    
    # Initialize offset to get latest updates only
    try:
        url = f"https://api.telegram.org/bot{BOT_TOKEN}/getUpdates"
        r = requests.get(url, timeout=10).json()
        if r.get("ok") and r.get("result"):
            offset = r["result"][-1]["update_id"] + 1
    except Exception as e:
        print(f"[TELEGRAM POLLER] Initial getUpdates failed: {e}")

    global threat_await_active, threat_approval_status
    
    while True:
        try:
            url = f"https://api.telegram.org/bot{BOT_TOKEN}/getUpdates?offset={offset}&timeout=10"
            resp = requests.get(url, timeout=15).json()
            if resp.get("ok") and resp.get("result"):
                for update in resp["result"]:
                    offset = update["update_id"] + 1
                    
                    # Handle callback queries (Inline keyboard button clicks)
                    if "callback_query" in update:
                        cb = update["callback_query"]
                        cb_id = cb["id"]
                        cb_data = cb.get("data", "")
                        message = cb.get("message", {})
                        chat = message.get("chat", {})
                        chat_id = chat.get("id")
                        msg_id = message.get("message_id")
                        
                        if cb_data.startswith("approve_user:") or cb_data.startswith("reject_user:"):
                            parts = cb_data.split(":", 1)
                            action = parts[0]
                            username = parts[1]
                            
                            result_msg = handle_user_approval_action(username, action)
                            
                            # Answer Callback Query
                            answer_url = f"https://api.telegram.org/bot{BOT_TOKEN}/answerCallbackQuery"
                            requests.post(answer_url, json={"callback_query_id": cb_id, "text": "Registration updated!"}, timeout=5)
                            
                            # Edit original message with result
                            edit_url = f"https://api.telegram.org/bot{BOT_TOKEN}/editMessageText"
                            requests.post(edit_url, json={
                                "chat_id": chat_id,
                                "message_id": msg_id,
                                "text": result_msg,
                                "parse_mode": "Markdown"
                            }, timeout=5)
                            
                    # Handle normal messages
                    elif "message" in update and "text" in update["message"]:
                        msg = update["message"]
                        text = msg.get("text", "").strip().upper()
                        
                        if threat_await_active:
                            if text == "YES":
                                threat_approval_status = "YES"
                                threat_await_active = False
                                print("[TELEGRAM POLLER] Threat approved (YES)")
                            elif text == "IGNORE":
                                threat_approval_status = "IGNORE"
                                threat_await_active = False
                                print("[TELEGRAM POLLER] Threat ignored (IGNORE)")
                                
        except Exception as e:
            pass
        time.sleep(1)

# API Auth routes
@app.route('/api/auth/register', methods=['POST'])
def api_register():
    data = request.json or {}
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    
    if not username or not password:
        return jsonify({"success": False, "message": "Username and password are required."}), 400
        
    users = load_users()
    if username in users:
        return jsonify({"success": False, "message": "Username already exists."}), 400
        
    # Create user with pending status
    users[username] = {
        "password": password,
        "role": "user",
        "status": "pending",
        "access_code": None
    }
    save_users(users)
    
    # Send request to admin on Telegram
    if BOT_TOKEN and BOT_TOKEN != "YOUR_TELEGRAM_BOT_TOKEN" and CHAT_ID:
        try:
            msg_text = f"🔔 *New Registration Request*\n\n*Username:* `{username}`\n*IP Address:* `{request.remote_addr}`\n*Time:* `{time.strftime('%Y-%m-%d %H:%M:%S')}`\n\nPlease approve or reject this request."
            reply_markup = {
                "inline_keyboard": [
                    [
                        {"text": "Approve ✅", "callback_data": f"approve_user:{username}"},
                        {"text": "Reject ❌", "callback_data": f"reject_user:{username}"}
                    ]
                ]
            }
            url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
            requests.post(url, json={
                "chat_id": CHAT_ID,
                "text": msg_text,
                "parse_mode": "Markdown",
                "reply_markup": reply_markup
            }, timeout=10)
        except Exception as e:
            print(f"[AUTH] Failed to send Telegram alert: {e}")
            
    return jsonify({"success": True, "message": "Registration submitted. Awaiting administrator approval."})

@app.route('/api/auth/login', methods=['POST'])
def api_login():
    data = request.json or {}
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    
    if not username or not password:
        return jsonify({"success": False, "message": "Username and password are required."}), 400
        
    users = load_users()
    if username not in users:
        return jsonify({"success": False, "message": "Invalid username or password."}), 401
        
    user = users[username]
    if user["password"] != password:
        return jsonify({"success": False, "message": "Invalid username or password."}), 401
        
    if user["status"] == "pending":
        return jsonify({"success": False, "message": "Your registration request is pending administrator approval."}), 403
    elif user["status"] == "rejected":
        return jsonify({"success": False, "message": "Your registration request was rejected by the administrator."}), 403
        
    # Handle admin dynamic OTP
    if username == "admin":
        otp = "".join([str(random.randint(0, 9)) for _ in range(6)])
        active_otps[username] = otp
        
        if BOT_TOKEN and BOT_TOKEN != "YOUR_TELEGRAM_BOT_TOKEN" and CHAT_ID:
            try:
                msg_text = f"🛡️ *SentiHealth MFA Verification*\n\nAdmin Access OTP: `{otp}`\n\nThis OTP is valid for this session."
                url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
                requests.post(url, json={
                    "chat_id": CHAT_ID,
                    "text": msg_text,
                    "parse_mode": "Markdown"
                }, timeout=10)
            except Exception as e:
                print(f"[AUTH] Failed to send OTP: {e}")
        else:
            print(f"[AUTH] Telegram not configured. Local Admin OTP: {otp}")
            
        return jsonify({
            "success": True,
            "stage": "otp",
            "username": "admin",
            "is_admin": True
        })
        
    # Handle approved user static access code
    return jsonify({
        "success": True,
        "stage": "otp",
        "username": username,
        "is_admin": False
    })

@app.route('/api/auth/verify-otp', methods=['POST'])
def api_verify_otp():
    data = request.json or {}
    username = data.get("username", "").strip()
    code = data.get("code", "").strip()
    
    if not username or not code:
        return jsonify({"success": False, "message": "Username and verification code are required."}), 400
        
    users = load_users()
    if username not in users:
        return jsonify({"success": False, "message": "User not found."}), 404
        
    user = users[username]
    
    if username == "admin":
        expected = active_otps.get(username)
        if not expected or code != expected:
            return jsonify({"success": False, "message": "Incorrect verification code."}), 401
        active_otps.pop(username, None)
    else:
        expected = user.get("access_code")
        if not expected or code != expected:
            return jsonify({"success": False, "message": "Incorrect access code."}), 401
            
    token = f"session-token-{username}-{random.randint(100000, 999999)}"
    return jsonify({
        "success": True,
        "token": token,
        "username": username
    })

# Threat coordination routes for live_sentinel
@app.route('/api/telegram/start-threat-await', methods=['POST'])
def api_start_threat_await():
    global threat_await_active, threat_approval_status, threat_await_start_time, threat_await_timeout
    data = request.json or {}
    threat_await_timeout = data.get("timeout", 90.0)
    threat_await_start_time = time.time()
    threat_await_active = True
    threat_approval_status = "PENDING"
    return jsonify({"success": True})

@app.route('/api/telegram/threat-status', methods=['GET'])
def api_threat_status():
    global threat_await_active, threat_approval_status
    if threat_await_active and (time.time() - threat_await_start_time > threat_await_timeout):
        threat_await_active = False
        threat_approval_status = "TIMEOUT"
    return jsonify({"status": threat_approval_status})

# Existing functionality below
def get_system_state():
    status = "NORMAL"
    threats = []
    blocked_count = 0
    blockchain_status = "INTACT"

    if os.path.exists('logs/threat_log.json'):
        with open('logs/threat_log.json', 'r') as f:
            lines = [json.loads(line) for line in f if line.strip()]
            threats = list(reversed(lines))[:10]
            if threats and threats[0]['action'] == 'pending':
                status = "LOCKDOWN"
            elif threats:
                status = "THREAT"
                
            # Count pending instances per IP for the visual indicator
            pending_counts = {}
            for t in threats:
                if t['action'] == 'pending':
                    pending_counts[t['ip']] = pending_counts.get(t['ip'], 0) + 1
                    
            for t in threats:
                if t['action'] == 'pending' and pending_counts.get(t['ip'], 0) > 1:
                    t['display_action'] = f"pending x{pending_counts[t['ip']]}"
                else:
                    t['display_action'] = t['action']
                
    if os.path.exists('logs/blocked_ips.json'):
        with open('logs/blocked_ips.json', 'r') as f:
            blocked_count = len([line for line in f if line.strip()])

    # Live three-layer chain verification (hash linkage + HMAC + block index)
    blockchain_status = "INTACT"
    if os.path.exists('data/audit_chain.json'):
        try:
            import hmac as _hmac_dash
            import hashlib as _hl_dash
            from scoring_matrix import SESSION_SECRET as _secret
            with open('data/audit_chain.json', 'r') as f:
                chain = json.load(f)
            for i, entry in enumerate(chain[1:], 1):
                # Layer 1: block index continuity
                if entry.get('block_index') is not None and entry['block_index'] != i:
                    blockchain_status = "COMPROMISED"
                    break
                # Layer 2: hash chain
                prev_hash = chain[i-1]['entry_hash']
                e_clean = {k: v for k, v in entry.items() if k not in ('entry_hash','block_hmac')}
                expected = _hl_dash.sha256((prev_hash + json.dumps(e_clean, sort_keys=True)).encode()).hexdigest()
                if entry['entry_hash'] != expected:
                    blockchain_status = "COMPROMISED"
                    break
                # Layer 3: HMAC content signature
                if 'block_hmac' in entry:
                    payload = {k: v for k, v in entry.items() if k not in ('entry_hash','block_hmac')}
                    expected_hmac = _hmac_dash.new(_secret, json.dumps(payload, sort_keys=True).encode(), _hl_dash.sha256).hexdigest()
                    if not _hmac_dash.compare_digest(entry['block_hmac'], expected_hmac):
                        blockchain_status = "COMPROMISED"
                        break
        except Exception:
            blockchain_status = "UNKNOWN"

    return {
        "status": status,
        "threats": threats,
        "blocked_count": blocked_count,
        "blockchain_status": blockchain_status
    }

@app.route('/api/status')
def api_status():
    return jsonify(get_system_state())

@app.route('/api/metrics')
def api_metrics():
    """Returns ML evaluation metrics from evaluation_metrics.json for the React frontend."""
    if not os.path.exists('evaluation_metrics.json'):
        return jsonify([])
    with open('evaluation_metrics.json', 'r') as f:
        return jsonify(json.load(f))

def get_metrics_html():
    if not os.path.exists('evaluation_metrics.json'):
        return "<p style='color: #888;'>Metrics not generated yet.</p>"
    with open('evaluation_metrics.json', 'r') as f:
        metrics = json.load(f)
        
    html = "<h3><strong>Overall Operational Performance</strong></h3>\n"
    html += "<table><thead><tr>"
    headers = ["Model", "Accuracy", "Precision", "Recall", "F1 Score", "AUC-ROC"]
    for h in headers:
        html += f"<th>{h}</th>"
    html += "</tr></thead><tbody>"
    
    for row in metrics:
        html += "<tr>"
        html += f"<td><strong>{row['model']}</strong></td>"
        html += f"<td>{row['accuracy']:.2f}</td>"
        html += f"<td>{row['precision']:.2f}</td>"
        html += f"<td>{row['recall']:.2f}</td>"
        html += f"<td>{row['f1']:.2f}</td>"
        html += f"<td>{row['auc_roc']:.4f}</td>"
        html += "</tr>"
        
    html += "</tbody></table>"
    return html

@app.route('/')
def index():
    state = get_system_state()
    metrics_html = get_metrics_html()
    
    bg_color = "#121212"
    status_color = "#4CAF50"
    if state["status"] == "THREAT": status_color = "#F44336"
    elif state["status"] == "LOCKDOWN": status_color = "#FF9800"
    
    bc_color = "#4CAF50" if state["blockchain_status"] == "INTACT" else "#F44336"
    
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>SentiHealth Dashboard</title>
        <meta http-equiv="refresh" content="5">
        <style>
            body {{ font-family: -apple-system, sans-serif; background-color: {bg_color}; color: #ffffff; padding: 20px; }}
            .container {{ max-width: 1000px; margin: 0 auto; }}
            .card {{ background: #1e1e1e; padding: 20px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }}
            h1, h2 {{ color: #e0e0e0; margin-top: 0; }}
            .status-badge {{ padding: 10px 20px; border-radius: 4px; font-weight: bold; background-color: {status_color}; display: inline-block; }}
            .bc-badge {{ padding: 5px 10px; border-radius: 4px; background-color: {bc_color}; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
            th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #333; }}
            th {{ color: #aaa; font-weight: 500; }}
            .grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🛡️ SentiHealth Live Console</h1>
            
            <div class="grid">
                <div class="card">
                    <h2>System Status</h2>
                    <div class="status-badge">{state['status']}</div>
                    {f'<p style="color:#aaa; font-size:0.85em; margin-top:10px;">⚠️ Multiple simultaneous High-tier threats are active and pending human authorization.</p>' if state["status"] == "LOCKDOWN" else ''}
                </div>
                <div class="card">
                    <h2>Blockchain Audit Ledger</h2>
                    <span class="bc-badge">{state['blockchain_status']}</span>
                    <p style="color: #aaa; margin-top: 10px;">Total Blocked IPs: {state['blocked_count']}</p>
                </div>
            </div>
            
            <div class="card">
                <h2>Recent Threat Detections (Last 10)</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Timestamp</th>
                            <th>IP Address</th>
                            <th>Tier</th>
                            <th>Score</th>
                            <th>Action</th>
                        </tr>
                    </thead>
                    <tbody>
    """
    for t in state['threats']:
        tier_color = "#F44336" if t['tier'] == 'High' else "#FF9800"
        html += f"""
                        <tr>
                            <td>{t['timestamp']}</td>
                            <td style="font-family: monospace;">{t['ip']}</td>
                            <td style="color: {tier_color};">{t['tier']}</td>
                            <td>{t['score']:.3f}</td>
                            <td>{t.get('display_action', t.get('action', ''))}</td>
                        </tr>
        """
    if not state['threats']:
        html += "<tr><td colspan='5' style='text-align:center; color:#888;'>No threats detected yet. System secure.</td></tr>"
        
    html += f"""
                    </tbody>
                </table>
            </div>

            <div class="card">
                <h2>Machine Learning Ensemble Metrics</h2>
                {metrics_html}
            </div>
        </div>
    </body>
    </html>
    """
    return html

if __name__ == "__main__":
    init_db()
    poller = threading.Thread(target=telegram_poller, daemon=True)
    poller.start()
    print("[TELEGRAM POLLER] Poller thread started.")
    print("[DASHBOARD] Running at http://localhost:5001")
    app.run(port=5001, debug=False, host='0.0.0.0')
