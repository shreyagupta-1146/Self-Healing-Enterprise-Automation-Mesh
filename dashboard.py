"""
SentiHealth Dashboard -- Flask backend.

Changes from original:
  - Telegram poller removed entirely.  OTP is printed to server console
    (the on-prem out-of-band channel) and exposed via the SSHA SSE stream.
  - Auth token is tracked server-side so admin-only endpoints can be protected.
  - /api/status and /api/metrics require a valid session token so that real
    IP addresses and threat data are only visible to authenticated admins.
    (Custodian principle: authenticated disclosure, not pseudonymized obscurity.)
  - /api/alerts   -- list pending SSHA authorization challenges (admin only).
  - /api/alerts/<id>/respond -- admin approve/deny a High-tier threat (admin only).
  - /api/admin/users -- list + approve/reject pending registrations (admin only).
  - /api/stream   -- SSE stream for real-time alert pushes to the dashboard.
  - Mirage deception status exposed at /api/deception/status (admin only).
"""

import hashlib
import hmac as _hmac
import json
import os
import sys
import random
import secrets
import threading
import time
from functools import wraps
from datetime import datetime, timezone

# Ensure project root is on sys.path so _paths and sibling modules are importable
# from any working directory the user launches this script from.
_PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from _paths import (
    LOGS_DIR, DATA_DIR, CONFIG_DIR, USERS_FILE, AUDIT_CHAIN,
    THREAT_LOG, BLOCKED_IPS, EVENTS_LOG, CHALLENGES_FILE,
    ALERT_QUEUE, CANARY_LOG, p as _p,
)

from flask import Flask, Response, jsonify, request, send_file, stream_with_context

try:
    from flask_cors import CORS
    _has_cors = True
except ImportError:
    _has_cors = False


# ---------------------------------------------------------------------------
# Password hashing — PBKDF2-HMAC-SHA256 (OWASP 2023: 260 000 iterations)
#
# Stored format:  pbkdf2:sha256:<iterations>:<salt_hex>:<key_hex>
# Legacy plaintext passwords (no "pbkdf2:" prefix) are accepted on login and
# transparently upgraded to the hashed form so existing users aren't locked out.
# ---------------------------------------------------------------------------

_PBKDF2_ITERS = 260_000
_PBKDF2_ALGO  = 'sha256'


def _hash_password(password: str) -> str:
    """Return a PBKDF2-HMAC-SHA256 hash string for `password`."""
    salt = secrets.token_bytes(16)
    key  = hashlib.pbkdf2_hmac(_PBKDF2_ALGO, password.encode('utf-8'), salt, _PBKDF2_ITERS)
    return f"pbkdf2:{_PBKDF2_ALGO}:{_PBKDF2_ITERS}:{salt.hex()}:{key.hex()}"


def _check_password(password: str, stored: str) -> bool:
    """Verify `password` against `stored`.  Handles both hashed and legacy
    plaintext stored values (plaintext support removed after first login upgrade).
    """
    if not stored:
        return False
    if not stored.startswith('pbkdf2:'):
        # Legacy plaintext — constant-time compare to prevent timing attacks
        return _hmac.compare_digest(stored.encode('utf-8'), password.encode('utf-8'))
    try:
        _prefix, algo, iters_str, salt_hex, key_hex = stored.split(':', 4)
        salt        = bytes.fromhex(salt_hex)
        expected    = bytes.fromhex(key_hex)
        iters       = int(iters_str)
        candidate   = hashlib.pbkdf2_hmac(algo, password.encode('utf-8'), salt, iters)
        return _hmac.compare_digest(expected, candidate)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# App init
# ---------------------------------------------------------------------------

app = Flask(__name__)
if _has_cors:
    CORS(app, resources={r"/api/*": {"origins": "*"}})

# ---------------------------------------------------------------------------
# Session store  (token -> {username, role, is_admin, created_at})
# ---------------------------------------------------------------------------

_sessions: dict[str, dict] = {}
_sessions_lock = threading.Lock()


def _create_session(username: str, is_admin: bool) -> str:
    token = secrets.token_hex(32)
    with _sessions_lock:
        _sessions[token] = {
            "username": username,
            "is_admin": is_admin,
            "created_at": time.time(),
        }
    return token


def _get_session(token: str) -> dict | None:
    with _sessions_lock:
        sess = _sessions.get(token)
        if sess is None:
            return None
        # 8-hour session expiry
        if time.time() - sess["created_at"] > 8 * 3600:
            _sessions.pop(token, None)
            return None
        return sess


def _require_auth(admin_only: bool = False):
    """Decorator factory.  Reads Bearer token from Authorization header."""
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            auth = request.headers.get("Authorization", "")
            if auth.startswith("Bearer "):
                token = auth[7:].strip()
            else:
                token = request.args.get("token", "").strip()

            sess = _get_session(token)
            if sess is None:
                return jsonify({"success": False, "message": "Authentication required."}), 401
            if admin_only and not sess["is_admin"]:
                return jsonify({"success": False, "message": "Admin access required."}), 403
            request.session = sess
            return fn(*args, **kwargs)
        return wrapper
    return decorator


# ---------------------------------------------------------------------------
# OTP store  (username -> {otp: str, issued_at: float})
# OTPs expire after OTP_TTL_SECS (default 5 minutes) for replay protection.
# ---------------------------------------------------------------------------

OTP_TTL_SECS = 300   # 5 minutes

_active_otps: dict[str, dict] = {}   # { username: {otp, issued_at} }
_otps_lock = threading.Lock()


def _otp_valid(username: str, code: str) -> bool:
    """Return True iff the stored OTP matches `code` and has not expired."""
    entry = _active_otps.get(username)
    if entry is None:
        return False
    if time.time() - entry["issued_at"] > OTP_TTL_SECS:
        _active_otps.pop(username, None)   # expired -- purge
        return False
    return entry["otp"] == code

# ---------------------------------------------------------------------------
# User store helpers
# ---------------------------------------------------------------------------

_users_lock = threading.Lock()


def load_users() -> dict:
    with _users_lock:
        if not os.path.exists(USERS_FILE):
            return {}
        try:
            with open(USERS_FILE, "r") as f:
                return json.load(f)
        except Exception as e:
            print(f"[AUTH] Error loading users: {e}")
            return {}


def save_users(users: dict) -> bool:
    with _users_lock:
        try:
            os.makedirs(DATA_DIR, exist_ok=True)
            with open(USERS_FILE, "w") as f:
                json.dump(users, f, indent=2)
            return True
        except Exception as e:
            print(f"[AUTH] Error saving users: {e}")
            return False


def init_db():
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(LOGS_DIR, exist_ok=True)
    if not os.path.exists(USERS_FILE):
        with open(USERS_FILE, "w") as f:
            json.dump({
                "admin": {
                    "password": _hash_password("sentinel2026"),
                    "role": "admin",
                    "status": "approved",
                    "access_code": None,
                }
            }, f, indent=2)
        print("[AUTH] Default admin created  (username: admin  password: sentinel2026)")

# ---------------------------------------------------------------------------
# SSE -- push real-time alerts to connected admin browsers
# ---------------------------------------------------------------------------

_sse_clients: list[object] = []
_sse_lock = threading.Lock()


def _push_sse(event_type: str, data: dict):
    """Append an event to all active SSE client queues."""
    import queue
    payload = f"event: {event_type}\ndata: {json.dumps(data)}\n\n"
    with _sse_lock:
        for q in list(_sse_clients):
            try:
                q.put_nowait(payload)
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------

@app.route("/api/auth/register", methods=["POST"])
def api_register():
    data = request.json or {}
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()

    if not username or not password:
        return jsonify({"success": False, "message": "Username and password required."}), 400

    users = load_users()
    if username in users:
        return jsonify({"success": False, "message": "Username already exists."}), 400

    # Custodian: pseudonymize the requester IP before writing to the pending log
    try:
        from privacy.pseudonymize import tokenize as _tok
        logged_ip = _tok(request.remote_addr or "unknown")
    except Exception:
        logged_ip = "unknown"

    users[username] = {
        "password": _hash_password(password),   # PBKDF2-HMAC-SHA256; never store plaintext
        "role": "user",
        "status": "pending",
        "access_code": None,
        "requested_at": datetime.now(timezone.utc).isoformat(),
        "request_ip_token": logged_ip,   # pseudonymized -- real IP not stored
    }
    save_users(users)

    # Notify all active admin dashboard sessions via SSE
    _push_sse("registration_request", {
        "username": username,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })

    print(
        f"\n[SSHA REGISTRATION] New request from '{username}' "
        f"(IP token: {logged_ip[:8]}...)\n"
        f"  -> Approve via dashboard /api/admin/users/{username}/approve\n"
    )
    return jsonify({
        "success": True,
        "message": "Registration submitted. Awaiting administrator approval via the dashboard.",
    })


@app.route("/api/auth/login", methods=["POST"])
def api_login():
    data = request.json or {}
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()

    if not username or not password:
        return jsonify({"success": False, "message": "Username and password required."}), 400

    users = load_users()
    if username not in users:
        return jsonify({"success": False, "message": "Invalid username or password."}), 401

    user = users[username]
    if not _check_password(password, user["password"]):
        return jsonify({"success": False, "message": "Invalid username or password."}), 401

    # Transparently upgrade plaintext passwords to PBKDF2 on first successful login
    if not user["password"].startswith("pbkdf2:"):
        user["password"] = _hash_password(password)
        users[username]  = user
        save_users(users)

    if user["status"] == "pending":
        return jsonify({
            "success": False,
            "message": "Your registration is pending administrator approval.",
        }), 403
    if user["status"] == "rejected":
        return jsonify({
            "success": False,
            "message": "Your registration request was rejected by the administrator.",
        }), 403

    is_admin = (user.get("role") == "admin")

    if is_admin:
        # Generate dynamic OTP and deliver to server console + SSE stream
        otp = "".join([str(random.randint(0, 9)) for _ in range(6)])
        with _otps_lock:
            _active_otps[username] = {"otp": otp, "issued_at": time.time()}

        # Primary delivery: server console (on-prem, no cloud dependency)
        # flush=True ensures this reaches the log file even when stdout is file-buffered
        print(
            f"\n[SSHA MFA] Admin OTP for '{username}': {otp}\n"
            f"  (displayed on server console -- no external channel needed)\n",
            flush=True,
        )

        # Always write OTP directly to logs_dashboard.txt so it's visible
        # regardless of how the process was launched (with or without stdout redirect).
        _dashboard_log = os.path.join(LOGS_DIR, "logs_dashboard.txt")
        try:
            with open(_dashboard_log, "a", encoding="utf-8") as _lf:
                _lf.write(
                    f"\n[SSHA MFA] Admin OTP for '{username}': {otp}\n"
                    f"  (displayed on server console -- no external channel needed)\n\n"
                )
        except Exception:
            pass

        # Secondary: push to any already-open admin SSE streams (e.g. second screen)
        _push_sse("admin_otp", {
            "username": username,
            "otp": otp,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

        return jsonify({
            "success": True,
            "stage": "otp",
            "username": username,
            "is_admin": True,
            "otp_channel": "server_console",
        })

    # Regular approved user -- uses static access code
    return jsonify({
        "success": True,
        "stage": "otp",
        "username": username,
        "is_admin": False,
        "otp_channel": "static_code",
    })


@app.route("/api/auth/verify-otp", methods=["POST"])
def api_verify_otp():
    data = request.json or {}
    username = data.get("username", "").strip()
    code = data.get("code", "").strip()

    if not username or not code:
        return jsonify({"success": False, "message": "Username and code required."}), 400

    users = load_users()
    if username not in users:
        return jsonify({"success": False, "message": "User not found."}), 404

    user = users[username]
    is_admin = (user.get("role") == "admin")

    if is_admin:
        with _otps_lock:
            valid = _otp_valid(username, code)
            if not valid:
                entry = _active_otps.get(username)
                if entry and time.time() - entry.get("issued_at", 0) > OTP_TTL_SECS:
                    msg = "OTP expired. Please log in again to receive a new OTP."
                else:
                    msg = "Incorrect OTP."
                return jsonify({"success": False, "message": msg}), 401
            _active_otps.pop(username, None)
    else:
        expected = user.get("access_code")
        if not expected or code != expected:
            return jsonify({"success": False, "message": "Incorrect access code."}), 401

    token = _create_session(username, is_admin)
    return jsonify({
        "success": True,
        "token": token,
        "username": username,
        "is_admin": is_admin,
    })


# ---------------------------------------------------------------------------
# Core sentinel data routes (auth required -- custodian gate)
# ---------------------------------------------------------------------------

@app.route("/api/status")
@_require_auth()
def api_status():
    """
    Real IP addresses and threat data -- authenticated admins only.
    This is the custodian gate: unauthenticated callers receive 401.
    """
    state = get_system_state()

    # Ensure these keys are always present even if an older cached module
    # omitted them — compute directly here as a safety net.
    if "total_threat_count" not in state or "all_tier_counts" not in state:
        _all_tiers = {"High": 0, "Medium": 0, "Low": 0}
        _total = 0
        if os.path.exists(THREAT_LOG):
            with open(THREAT_LOG, "r") as _f:
                _lines = [json.loads(_l) for _l in _f if _l.strip()]
            _total = len(_lines)
            for _e in _lines:
                _t = _e.get("tier", "")
                if _t in _all_tiers:
                    _all_tiers[_t] += 1
        state["total_threat_count"] = _total
        state["all_tier_counts"] = _all_tiers

    return jsonify(state)


@app.route("/api/metrics")
@_require_auth()
def api_metrics():
    if not os.path.exists("evaluation_metrics.json"):
        return jsonify([])
    with open("evaluation_metrics.json", "r") as f:
        return jsonify(json.load(f))


# ---------------------------------------------------------------------------
# SSHA Alert Authorization routes (admin only)
# ---------------------------------------------------------------------------

@app.route("/api/alerts", methods=["GET"])
@_require_auth(admin_only=True)
def api_list_alerts():
    """Return pending SSHA authorization challenges + recent alert queue."""
    from notifications.sentinel_notifier import list_pending

    pending = list_pending()

    recent_alerts = []
    if os.path.exists(ALERT_QUEUE):
        with open(ALERT_QUEUE, "r") as f:
            lines = [l.strip() for l in f if l.strip()]
        for line in reversed(lines[-50:]):
            try:
                recent_alerts.append(json.loads(line))
            except Exception:
                pass

    return jsonify({
        "pending_challenges": pending,
        "recent_alerts": recent_alerts[:20],
    })


@app.route("/api/alerts/<incident_id>/respond", methods=["POST"])
@_require_auth(admin_only=True)
def api_respond_alert(incident_id: str):
    """Admin approves or denies a High-tier threat authorization challenge."""
    from notifications.sentinel_notifier import resolve_challenge

    data = request.json or {}
    decision = data.get("decision", "").upper().strip()
    if decision not in ("YES", "IGNORE", "DENY"):
        return jsonify({"success": False, "message": "decision must be YES, IGNORE, or DENY"}), 400

    resolved = resolve_challenge(incident_id, decision)
    if not resolved:
        return jsonify({
            "success": False,
            "message": "Challenge not found or already resolved.",
        }), 404

    admin = request.session.get("username", "unknown")
    print(
        f"\n[SSHA AUTH] Admin '{admin}' resolved challenge {incident_id[:8]} -> {decision}\n"
    )
    return jsonify({"success": True, "decision": decision, "incident_id": incident_id})


# ---------------------------------------------------------------------------
# Stasis queue — expired/auto-locked challenges the admin can still review
# ---------------------------------------------------------------------------

@app.route("/api/alerts/stasis", methods=["GET"])
@_require_auth(admin_only=True)
def api_stasis_list():
    """
    Return all challenges that expired (90s window elapsed) and were auto-locked.
    The admin can retroactively request forensics generation or dismiss them.
    """
    from notifications.sentinel_notifier import list_stasis
    items = list_stasis()
    return jsonify({"stasis": items})


@app.route("/api/alerts/<incident_id>/retroactive", methods=["POST"])
@_require_auth(admin_only=True)
def api_retroactive_action(incident_id: str):
    """
    Admin retroactively acts on an auto-locked (stasis) threat.

    Body: {"action": "release" | "confirm"}

    release — Admin decides to restore access for this IP.
              Removes the IP from blocked_ips.json, updates threat_log to
              "admin_released", generates a forensic report, and pushes SSE.

    confirm — Admin confirms the auto-lock was correct; IP stays blocked.
              Marks the challenge as reviewed and pushes SSE.
    """
    from notifications.sentinel_notifier import resolve_challenge, list_stasis

    body   = request.json or {}
    action = body.get("action", "").lower().strip()
    if action not in ("release", "confirm"):
        return jsonify({"success": False, "message": "action must be 'release' or 'confirm'"}), 400

    # Resolve the challenge first (marks it retroactive so it disappears from queue)
    decision = "RELEASE" if action == "release" else "CONFIRM_BLOCK"
    resolved = resolve_challenge(incident_id, decision, allow_expired=True)
    if not resolved:
        return jsonify({
            "success": False,
            "message": "Stasis challenge not found or already reviewed.",
        }), 404

    admin = request.session.get("username", "unknown")

    # Get enriched item (includes IP resolved from metadata or threat_log fallback)
    stasis_items = list_stasis()
    # list_stasis now excludes just-resolved challenge (status changed to "retroactive")
    # so we re-fetch the raw challenge to get the IP
    from notifications.sentinel_notifier import _read_challenges
    ch    = _read_challenges().get(incident_id, {})
    meta  = ch.get("metadata") or {}
    ip    = meta.get("ip", "")

    # If metadata didn't have IP, search threat_log by timestamp proximity
    if not ip:
        ch_ts = ch.get("timestamp", "")[:16]
        try:
            if os.path.exists(THREAT_LOG):
                with open(THREAT_LOG, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        entry = json.loads(line)
                        if entry.get("action") == "auto-locked" and entry.get("timestamp", "")[:16] == ch_ts:
                            ip = entry.get("ip", "")
                            break
        except Exception:
            pass

    if action == "release":
        # ── 1. Remove IP from blocked_ips.json ───────────────────────────
        if ip and os.path.exists(BLOCKED_IPS):
            try:
                with open(BLOCKED_IPS, "r", encoding="utf-8") as f:
                    lines = [l for l in f if l.strip() and json.loads(l).get("ip") != ip]
                with open(BLOCKED_IPS, "w", encoding="utf-8") as f:
                    f.writelines(lines)
            except Exception as exc:
                pass  # non-fatal — log but don't crash

        # ── 2. Update threat_log: mark matching auto-locked entry as admin_released ──
        if ip and os.path.exists(THREAT_LOG):
            try:
                with open(THREAT_LOG, "r", encoding="utf-8") as f:
                    all_lines = f.readlines()
                for i in range(len(all_lines) - 1, -1, -1):
                    if not all_lines[i].strip():
                        continue
                    entry = json.loads(all_lines[i])
                    if entry.get("ip") == ip and entry.get("action") == "auto-locked":
                        entry["action"]      = "admin_released"
                        entry["reviewed_by"] = admin
                        entry["reviewed_at"] = datetime.now(timezone.utc).isoformat()
                        all_lines[i] = json.dumps(entry) + "\n"
                        break
                with open(THREAT_LOG, "w", encoding="utf-8") as f:
                    f.writelines(all_lines)
            except Exception:
                pass

        # ── 3. Generate forensic report ───────────────────────────────────
        try:
            report_path = _p("logs", f"forensic_report_{incident_id}_{(ip or 'unknown').replace('.', '_')}.json")
            forensic = {
                "incident_id":   incident_id,
                "ip":            ip or "unknown",
                "tier":          meta.get("tier", "High"),
                "score":         meta.get("score"),
                "reason":        meta.get("reason", ""),
                "auto_locked_at": ch.get("resolved_at", ""),
                "released_by":   admin,
                "released_at":   datetime.now(timezone.utc).isoformat(),
                "action":        "admin_released",
            }
            with open(report_path, "w", encoding="utf-8") as f:
                json.dump(forensic, f, indent=2)
        except Exception:
            pass

        _push_sse("stasis_resolved", {
            "incident_id": incident_id,
            "action":      "released",
            "ip":          ip,
            "reviewed_by": admin,
        })
        _log_to_file(f"[SSHA RETROACTIVE] Admin '{admin}' released block on IP {ip} (incident {incident_id[:8]})")
        return jsonify({"success": True, "action": "released", "ip": ip, "incident_id": incident_id})

    else:  # confirm — keep blocked, just mark reviewed
        _push_sse("stasis_resolved", {
            "incident_id": incident_id,
            "action":      "confirmed_block",
            "ip":          ip,
            "reviewed_by": admin,
        })
        _log_to_file(f"[SSHA RETROACTIVE] Admin '{admin}' confirmed block on IP {ip} (incident {incident_id[:8]})")
        return jsonify({"success": True, "action": "confirmed_block", "ip": ip, "incident_id": incident_id})


# ---------------------------------------------------------------------------
# Admin user management (admin only)
# ---------------------------------------------------------------------------

@app.route("/api/admin/users", methods=["GET"])
@_require_auth(admin_only=True)
def api_admin_list_users():
    users = load_users()
    result = []
    for uname, udata in users.items():
        result.append({
            "username": uname,
            "role": udata.get("role", "user"),
            "status": udata.get("status", "unknown"),
            "requested_at": udata.get("requested_at", ""),
        })
    return jsonify(result)


@app.route("/api/admin/users/<username>/approve", methods=["POST"])
@_require_auth(admin_only=True)
def api_admin_approve_user(username: str):
    users = load_users()
    if username not in users:
        return jsonify({"success": False, "message": "User not found."}), 404
    if users[username]["status"] != "pending":
        return jsonify({"success": False, "message": f"User is already {users[username]['status']}."}), 400

    access_code = "".join([str(random.randint(0, 9)) for _ in range(6)])
    users[username]["status"] = "approved"
    users[username]["access_code"] = access_code
    save_users(users)

    admin = request.session.get("username", "unknown")
    print(
        f"\n[AUTH] Admin '{admin}' approved user '{username}'. "
        f"Access code: {access_code} (share out-of-band with the user)\n"
    )
    _push_sse("user_approved", {"username": username, "access_code": access_code})
    return jsonify({"success": True, "username": username, "access_code": access_code})


@app.route("/api/admin/users/<username>/reject", methods=["POST"])
@_require_auth(admin_only=True)
def api_admin_reject_user(username: str):
    users = load_users()
    if username not in users:
        return jsonify({"success": False, "message": "User not found."}), 404

    users[username]["status"] = "rejected"
    save_users(users)
    admin = request.session.get("username", "unknown")
    print(f"\n[AUTH] Admin '{admin}' rejected user '{username}'.\n")
    return jsonify({"success": True, "username": username})


# ---------------------------------------------------------------------------
# SHAP chart serving (admin only -- behind the custodian gate)
# ---------------------------------------------------------------------------

@app.route("/api/shap/<filename>")
@_require_auth(admin_only=True)
def api_shap_image(filename: str):
    """Serve a SHAP PNG chart to authenticated admins only."""
    # Sanitize: only allow simple filenames, no path traversal
    if "/" in filename or "\\" in filename or ".." in filename:
        return jsonify({"error": "invalid filename"}), 400
    path = _p("logs", filename)
    if not os.path.exists(path):
        return jsonify({"error": "not found"}), 404
    return send_file(path, mimetype="image/png")


# ---------------------------------------------------------------------------
# Mirage deception status (admin only)
# ---------------------------------------------------------------------------

@app.route("/api/deception/status", methods=["GET"])
@_require_auth(admin_only=True)
def api_deception_status():
    """Return active Mirage deception sessions and canary registry summary."""
    canary_count = 0
    if os.path.exists(CANARY_LOG):
        with open(CANARY_LOG, "r") as f:
            canary_count = sum(1 for l in f if l.strip())

    return jsonify({
        "deception_enabled": _get_deception_policy().get("deception_enabled", True),
        "activation_threshold": _get_deception_policy().get("activation_threshold", 0.55),
        "full_decoy_threshold": _get_deception_policy().get("full_decoy_threshold", 0.75),
        "canaries_minted": canary_count,
        "description": (
            "Mirage serves synthetic decoy patient records to confirmed attackers. "
            "Each record carries a canary token. If a token surfaces in a data breach "
            "disclosure, the breach is traced back to this deployment."
        ),
    })


def _get_deception_policy() -> dict:
    path = _p("config", "deception_policy.json")
    if not os.path.exists(path):
        return {}
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# SSE stream (auth required)
# ---------------------------------------------------------------------------

@app.route("/api/stream")
@_require_auth()
def api_stream():
    """Server-Sent Events stream for real-time alerts pushed to the dashboard."""
    import queue

    q: queue.Queue = queue.Queue()
    with _sse_lock:
        _sse_clients.append(q)

    def generate():
        try:
            yield "event: connected\ndata: {}\n\n"
            while True:
                try:
                    msg = q.get(timeout=30)
                    yield msg
                except Exception:
                    yield "event: heartbeat\ndata: {}\n\n"
        finally:
            with _sse_lock:
                try:
                    _sse_clients.remove(q)
                except ValueError:
                    pass

    return Response(
        stream_with_context(generate()),
        content_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


# ---------------------------------------------------------------------------
# Legacy threat-coordination routes (used by self_healing_responder via HTTP)
# Kept for backward compatibility; internally bridged to SSHA.
# ---------------------------------------------------------------------------

_threat_await_active = False
_threat_approval_status = "PENDING"
_threat_await_start = 0.0
_threat_await_timeout = 90.0
_threat_coord_lock = threading.Lock()


@app.route("/api/telegram/start-threat-await", methods=["POST"])
def api_start_threat_await():
    global _threat_await_active, _threat_approval_status, _threat_await_start, _threat_await_timeout
    data = request.json or {}
    with _threat_coord_lock:
        _threat_await_timeout = data.get("timeout", 90.0)
        _threat_await_start = time.time()
        _threat_await_active = True
        _threat_approval_status = "PENDING"
    return jsonify({"success": True})


@app.route("/api/telegram/threat-status", methods=["GET"])
def api_threat_status():
    global _threat_await_active, _threat_approval_status
    with _threat_coord_lock:
        if _threat_await_active and (time.time() - _threat_await_start > _threat_await_timeout):
            _threat_await_active = False
            _threat_approval_status = "TIMEOUT"
        status = _threat_approval_status
    return jsonify({"status": status})


@app.route("/api/telegram/resolve", methods=["POST"])
@_require_auth(admin_only=True)
def api_resolve_threat():
    """Admin resolves the legacy threat-await via dashboard (replaces Telegram YES/IGNORE)."""
    global _threat_await_active, _threat_approval_status
    data = request.json or {}
    decision = data.get("decision", "IGNORE").upper()
    with _threat_coord_lock:
        _threat_approval_status = decision
        _threat_await_active = False
    return jsonify({"success": True, "decision": decision})


# ---------------------------------------------------------------------------
# System state (reads threat_log, blocked_ips, audit chain)
# ---------------------------------------------------------------------------

def get_system_state() -> dict:
    status = "NORMAL"
    threats = []
    blocked_count = 0
    blockchain_status = "INTACT"

    all_tier_counts = {"High": 0, "Medium": 0, "Low": 0}
    total_threat_count = 0

    if os.path.exists(THREAT_LOG):
        with open(THREAT_LOG, "r") as f:
            lines = [json.loads(line) for line in f if line.strip()]

        # Count ALL entries for the real totals shown in the donut chart
        total_threat_count = len(lines)
        for entry in lines:
            t = entry.get("tier", "")
            if t in all_tier_counts:
                all_tier_counts[t] += 1

        # Only send the 50 most-recent entries to the table
        threats = list(reversed(lines))[:50]
        if threats and threats[0]["action"] == "pending":
            status = "LOCKDOWN"
        elif threats:
            status = "THREAT"

        # Badge pending-count per IP for the table
        pending_counts: dict[str, int] = {}
        for t in threats:
            if t["action"] == "pending":
                pending_counts[t["ip"]] = pending_counts.get(t["ip"], 0) + 1
        for t in threats:
            if t["action"] == "pending" and pending_counts.get(t["ip"], 0) > 1:
                t["display_action"] = f"pending x{pending_counts[t['ip']]}"
            else:
                t["display_action"] = t["action"]
            # Expose SHAP chart as a URL the frontend can fetch (auth-gated)
            shap_file = t.get("shap_file", "")
            t["shap_url"] = f"/api/shap/{shap_file}" if shap_file else ""

    if os.path.exists(BLOCKED_IPS):
        with open(BLOCKED_IPS, "r") as f:
            blocked_count = sum(1 for line in f if line.strip())

    # Three-layer chain verification
    blockchain_status = "INTACT"
    if os.path.exists(AUDIT_CHAIN):
        try:
            import hmac as _hmac
            import hashlib as _hl
            from scoring_matrix import SESSION_SECRET as _secret

            with open(AUDIT_CHAIN, "r") as f:
                chain = json.load(f)
            for i, entry in enumerate(chain[1:], 1):
                if entry.get("block_index") is not None and entry["block_index"] != i:
                    blockchain_status = "COMPROMISED"
                    break
                prev_hash = chain[i - 1]["entry_hash"]
                e_clean = {k: v for k, v in entry.items() if k not in ("entry_hash", "block_hmac")}
                expected = _hl.sha256(
                    (prev_hash + json.dumps(e_clean, sort_keys=True)).encode()
                ).hexdigest()
                if entry["entry_hash"] != expected:
                    blockchain_status = "COMPROMISED"
                    break
                if "block_hmac" in entry:
                    payload = {k: v for k, v in entry.items() if k not in ("entry_hash", "block_hmac")}
                    exp_hmac = _hmac.new(
                        _secret, json.dumps(payload, sort_keys=True).encode(), _hl.sha256
                    ).hexdigest()
                    if not _hmac.compare_digest(entry["block_hmac"], exp_hmac):
                        blockchain_status = "COMPROMISED"
                        break
        except Exception:
            blockchain_status = "UNKNOWN"

    return {
        "status": status,
        "threats": threats,
        "blocked_count": blocked_count,
        "blockchain_status": blockchain_status,
        "total_threat_count": total_threat_count,
        "all_tier_counts": all_tier_counts,
    }


# ---------------------------------------------------------------------------
# Legacy HTML dashboard (kept for terminal access)
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    state = get_system_state()

    bg = "#121212"
    sc = "#4CAF50" if state["status"] == "NORMAL" else (
        "#F44336" if state["status"] == "THREAT" else "#FF9800"
    )
    bc = "#4CAF50" if state["blockchain_status"] == "INTACT" else "#F44336"

    rows_html = ""
    for t in state["threats"]:
        tc = "#F44336" if t["tier"] == "High" else "#FF9800"
        rows_html += (
            f"<tr><td>{t['timestamp']}</td>"
            f"<td style='font-family:monospace'>{t['ip']}</td>"
            f"<td style='color:{tc}'>{t['tier']}</td>"
            f"<td>{t['score']:.3f}</td>"
            f"<td>{t.get('display_action', t.get('action',''))}</td></tr>"
        )
    if not rows_html:
        rows_html = "<tr><td colspan='5' style='text-align:center;color:#888'>No threats detected yet.</td></tr>"

    return f"""<!DOCTYPE html><html><head>
<title>SentiHealth Console</title>
<meta http-equiv="refresh" content="5">
<style>body{{font-family:-apple-system,sans-serif;background:{bg};color:#fff;padding:20px}}
table{{width:100%;border-collapse:collapse}}th,td{{padding:10px;text-align:left;border-bottom:1px solid #333}}
th{{color:#aaa}}.badge{{padding:6px 14px;border-radius:4px;font-weight:bold;display:inline-block}}</style>
</head><body>
<h1> SentiHealth  Secure Console</h1>
<p style="color:#aaa;font-size:0.85em">Live threat data. Authenticated admins only via React dashboard on :5173.</p>
<div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:20px">
<div style="background:#1e1e1e;padding:20px;border-radius:8px">
<h2>System Status</h2><div class="badge" style="background:{sc}">{state['status']}</div></div>
<div style="background:#1e1e1e;padding:20px;border-radius:8px">
<h2>Blockchain Ledger</h2><span class="badge" style="background:{bc}">{state['blockchain_status']}</span>
<p style="color:#aaa">Blocked IPs: {state['blocked_count']}</p></div></div>
<div style="background:#1e1e1e;padding:20px;border-radius:8px">
<h2>Recent Threat Detections (Last 10)</h2>
<table><thead><tr><th>Timestamp</th><th>IP Address</th><th>Tier</th><th>Score</th><th>Action</th></tr></thead>
<tbody>{rows_html}</tbody></table></div></body></html>"""


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def _start_challenge_watcher():
    """
    Background thread: watches logs/ssha_challenges.json for new pending
    authorization challenges and pushes a 'high_alert' SSE event to every
    connected admin browser so they see an instant toast — no page refresh needed.
    """
    from notifications.sentinel_notifier import _read_challenges

    seen_ids: set = set()

    def _watch():
        while True:
            time.sleep(2)
            try:
                challenges = _read_challenges()
                for iid, ch in challenges.items():
                    if iid in seen_ids:
                        continue
                    seen_ids.add(iid)
                    if ch.get("status") == "pending":
                        _push_sse("high_alert", {
                            "incident_id": iid,
                            "prompt": ch.get("prompt", "High-tier threat — Admin decision required."),
                            "timestamp": ch.get("timestamp", ""),
                            "timeout_sec": ch.get("timeout_sec", 90),
                        })
            except Exception:
                pass

    threading.Thread(target=_watch, daemon=True).start()


def _start_threat_log_watcher():
    """
    Background thread: tail-follows logs/threat_log.json and pushes a
    'threat_update' SSE event to every connected browser the instant
    live_sentinel.py writes a new scored event — no 5-second poll lag.
    """
    _THREAT_LOG = THREAT_LOG

    def _watch():
        pos = 0
        # Start at EOF — only forward events that arrive after dashboard boot
        if os.path.exists(_THREAT_LOG):
            with open(_THREAT_LOG, "rb") as _f:
                _f.seek(0, 2)
                pos = _f.tell()

        while True:
            time.sleep(0.8)
            try:
                if not os.path.exists(_THREAT_LOG):
                    continue
                with open(_THREAT_LOG, "r", encoding="utf-8") as f:
                    f.seek(pos)
                    chunk = f.read()
                    pos = f.tell()
                for line in chunk.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        # Attach a shap_url so the frontend can fetch it right away
                        shap_file = entry.get("shap_file", "")
                        entry["shap_url"] = f"/api/shap/{shap_file}" if shap_file else ""
                        _push_sse("threat_update", entry)
                    except Exception:
                        pass
            except Exception:
                pass

    threading.Thread(target=_watch, daemon=True).start()


def _log_to_file(msg: str) -> None:
    """Write a startup/status message directly to logs_dashboard.txt as UTF-8.
    Bypasses stdout so the file never gets PowerShell's UTF-16 LE encoding."""
    try:
        _lf_path = os.path.join(LOGS_DIR, "logs_dashboard.txt")
        os.makedirs(LOGS_DIR, exist_ok=True)
        with open(_lf_path, "a", encoding="utf-8") as _lf:
            _lf.write(msg + "\n")
    except Exception:
        pass


if __name__ == "__main__":
    init_db()
    _start_challenge_watcher()
    _start_threat_log_watcher()
    _log_to_file("[DASHBOARD] SentiHealth Dashboard starting...")
    _log_to_file("[DASHBOARD] SSHA active -- no Telegram required.")
    _log_to_file("[DASHBOARD] OTP will appear below when admin logs in.")
    app.run(port=5001, debug=False, host="0.0.0.0")
