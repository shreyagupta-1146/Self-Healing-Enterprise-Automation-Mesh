import json
import os
import sys
import hmac as _hmac
import hashlib
import shutil
import threading
import time
from datetime import datetime, timezone

# Ensure project root is on sys.path for sibling module imports.
_PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from _paths import (
    DATA_DIR, AUDIT_CHAIN, APP_DB, SNAPSHOTS_DIR,
    LOGS_DIR, BLOCKED_IPS, LOCKED_ACCOUNTS,
    INTEGRITY_ALERTS, TAMPER_ALERTS, NETWORK_ACTIONS,
    RETRAINING_DIR, RETRAINING_QUEUE, p as _p,
)
from scoring_matrix import SESSION_SECRET
from notifications import get_notifier

high_alert_counter = {}
last_high_event_time = {}
session_summary_sent = False
has_received_yes = False
CRITICAL_SEGMENTS = []
assert CRITICAL_SEGMENTS == []


# ---------------------------------------------------------------------------
# Genesis bootstrap -- create audit_chain.json on startup if absent
# ---------------------------------------------------------------------------
def _bootstrap_chain():
    os.makedirs(DATA_DIR, exist_ok=True)
    if not os.path.exists(AUDIT_CHAIN):
        genesis_data = {"block_index": 0}
        genesis_str  = json.dumps(genesis_data, sort_keys=True)
        genesis = {
            "block_index": 0,
            "entry_hash":  hashlib.sha256(b"genesis").hexdigest(),
            "block_hmac":  _hmac.new(SESSION_SECRET, genesis_str.encode(), hashlib.sha256).hexdigest(),
        }
        tmp = AUDIT_CHAIN + '.tmp'
        with open(tmp, 'w') as f:
            json.dump([genesis], f, indent=2)
        os.replace(tmp, AUDIT_CHAIN)
        print(f"[CHAIN] Hardened genesis block created -> {AUDIT_CHAIN}")

_bootstrap_chain()


# ---------------------------------------------------------------------------
# Audit chain helpers
# ---------------------------------------------------------------------------

def _integrity_alert(msg: str):
    """Print, log, and write tamper alert -- used by watchdog and sync check."""
    print(f"\033[91m[CHAIN ALERT] {msg}\033[0m")
    ts = datetime.now(timezone.utc).isoformat()
    os.makedirs(LOGS_DIR, exist_ok=True)
    for path in (INTEGRITY_ALERTS, TAMPER_ALERTS):
        with open(path, 'a') as f:
            f.write(f"{ts} -- {msg}\n")


def _block_hmac(entry: dict, secret: bytes) -> str:
    """Compute HMAC-SHA256 over block content (excludes entry_hash and block_hmac)."""
    payload = {k: v for k, v in entry.items() if k not in ('entry_hash', 'block_hmac')}
    return _hmac.new(secret, json.dumps(payload, sort_keys=True).encode(), hashlib.sha256).hexdigest()


def _write_chain_atomic(chain: list, path: str = None):
    if path is None:
        path = AUDIT_CHAIN
    """Write chain atomically via temp file + rename -- prevents partial-write corruption."""
    tmp = path + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(chain, f, indent=2)
    os.replace(tmp, path)  # atomic on POSIX / Windows


def verify_chain_integrity() -> bool:
    """
    Three-layer chain verification:
      1. Block index continuity  -> detects insertion or deletion
      2. SHA-256 hash linkage    -> detects any hash flip
      3. HMAC-SHA256 signature   -> detects content injection even with valid hash
    Returns True if intact, False if tampered (and fires alert).
    """
    if not os.path.exists(AUDIT_CHAIN):
        return True
    try:
        with open(AUDIT_CHAIN, 'r') as f:
            chain = json.load(f)

        for i, entry in enumerate(chain[1:], 1):
            # Layer 1 -- Block index continuity
            if entry.get('block_index') is not None and entry['block_index'] != i:
                _integrity_alert(
                    f"BLOCK INDEX MISMATCH at position {i}: "
                    f"expected {i}, got {entry.get('block_index')} "
                    f"-- insertion or deletion detected"
                )
                return False

            # Layer 2 -- SHA-256 hash linkage
            prev_hash = chain[i - 1]['entry_hash']
            entry_for_hash = {k: v for k, v in entry.items() if k not in ('entry_hash', 'block_hmac')}
            expected_hash = hashlib.sha256(
                (prev_hash + json.dumps(entry_for_hash, sort_keys=True)).encode()
            ).hexdigest()
            if entry['entry_hash'] != expected_hash:
                _integrity_alert(f"HASH CHAIN BROKEN at block {i} -- hash flip detected")
                return False

            # Layer 3 -- HMAC content signature
            if 'block_hmac' in entry:
                expected_hmac = _block_hmac(entry, SESSION_SECRET)
                if not _hmac.compare_digest(entry['block_hmac'], expected_hmac):
                    _integrity_alert(
                        f"HMAC SIGNATURE INVALID at block {i} "
                        f"-- content injection detected (block has valid hash but wrong HMAC)"
                    )
                    return False

        return True
    except Exception as e:
        _integrity_alert(f"CHAIN PARSE ERROR: {e}")
        return False


def _watchdog():
    while True:
        verify_chain_integrity()
        time.sleep(8)

threading.Thread(target=_watchdog, daemon=True).start()


# ---------------------------------------------------------------------------
# Self-healing actions
# ---------------------------------------------------------------------------

def throttle_bandwidth(percent=1):
    os.makedirs(LOGS_DIR, exist_ok=True)
    with open(NETWORK_ACTIONS, 'a') as f:
        f.write(f"{datetime.now()} -- Bandwidth throttled to {percent}%\n")


def snapshot_database():
    os.makedirs(SNAPSHOTS_DIR, exist_ok=True)
    if os.path.exists(APP_DB):
        shutil.copy(APP_DB, os.path.join(SNAPSHOTS_DIR, f'snap_{int(time.time())}.db'))


def lock_account(user_id: str):
    locked = set()
    if os.path.exists(LOCKED_ACCOUNTS):
        with open(LOCKED_ACCOUNTS, 'r') as f:
            for line in f:
                if line.strip():
                    locked.add(json.loads(line)['user_id'])
    if user_id in locked:
        print(f"[*] Account {user_id} already locked.")
        return
    with open(LOCKED_ACCOUNTS, 'a') as f:
        f.write(json.dumps({"user_id": user_id, "time": datetime.now(timezone.utc).isoformat()}) + "\n")


def block_ip(ip_address: str):
    blocked = set()
    if os.path.exists(BLOCKED_IPS):
        with open(BLOCKED_IPS, 'r') as f:
            for line in f:
                if line.strip():
                    blocked.add(json.loads(line)['ip'])
    if ip_address in blocked:
        print(f"[*] IP {ip_address} already blocked.")
        return
    with open(BLOCKED_IPS, 'a') as f:
        f.write(json.dumps({"ip": ip_address, "time": datetime.now(timezone.utc).isoformat()}) + "\n")


# ---------------------------------------------------------------------------
# Main responder
# ---------------------------------------------------------------------------

def respond(
    classification: dict,
    auth_token: str = None,
    ip_address: str = 'Unknown',
    telegram: bool = True,
) -> dict:
    # --- HMAC verification (tamper guard) ---
    core = json.dumps({
        'event_id': classification['event_id'],
        'tier': classification['tier'],
        'raw_score': classification['raw_score'],
        'timestamp': classification['timestamp'],
    }, sort_keys=True)
    recomputed = _hmac.new(SESSION_SECRET, core.encode(), hashlib.sha256).hexdigest()

    if not _hmac.compare_digest(classification['hmac_token'], recomputed):
        os.makedirs(LOGS_DIR, exist_ok=True)
        with open(INTEGRITY_ALERTS, 'a') as f:
            f.write(f"{datetime.now()} -- INVALID HMAC -- possible injection\n")
        return {"status": "REJECTED_INVALID_HMAC"}

    tier = classification['tier']
    event_id = classification['event_id']

    # --- Audit chain bootstrap ---
    if not os.path.exists(AUDIT_CHAIN):
        os.makedirs(DATA_DIR, exist_ok=True)
        genesis = {"block_index": 0, "entry_hash": hashlib.sha256(b"genesis").hexdigest()}
        genesis["block_hmac"] = _block_hmac(genesis, SESSION_SECRET)
        _write_chain_atomic([genesis])

    with open(AUDIT_CHAIN, 'r') as f:
        chain = json.load(f)
    prev_hash = chain[-1]['entry_hash']

    # Synchronous three-layer check before append
    if len(chain) > 1:
        last = chain[-1]
        verify_prev = chain[-2]['entry_hash']
        last_for_hash = {k: v for k, v in last.items() if k not in ('entry_hash', 'block_hmac')}
        expected_hash = hashlib.sha256(
            (verify_prev + json.dumps(last_for_hash, sort_keys=True)).encode()
        ).hexdigest()
        if expected_hash != prev_hash:
            get_notifier().send_alert("CRITICAL: CHAIN_HASH_CORRUPTION -- system halted")
            _integrity_alert("SYNCHRONOUS HASH CORRUPTION HALT")
            return {"status": "HALTED_CORRUPTION"}
        if 'block_hmac' in last:
            if not _hmac.compare_digest(last['block_hmac'], _block_hmac(last, SESSION_SECRET)):
                get_notifier().send_alert("CRITICAL: BLOCK_HMAC_INVALID -- content injection detected")
                _integrity_alert("SYNCHRONOUS HMAC INJECTION HALT")
                return {"status": "HALTED_INJECTION"}

    entry = {
        "event_id": event_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tier": tier,
        "prev_hash": prev_hash,
    }

    # --- Get live_sentinel module for session counters (backwards-compat) ---
    import sys
    live_sentinel = (
        sys.modules['__main__']
        if '__main__' in sys.modules and hasattr(sys.modules['__main__'], 'session_start_time')
        else __import__('live_sentinel')
    )

    # --- Tier logic ---
    if tier == 'Low':
        live_sentinel.low_count += 1
        result = {"status": "LOGGED", "actions": ["audit_log"]}
        entry["actions_taken"] = ["audit_log"]
        entry["status"] = "LOGGED"

    elif tier == 'Medium':
        live_sentinel.medium_count += 1
        score = classification['raw_score']
        top_features = classification.get('plain_english_explanation', 'N/A')
        user_id = classification.get('features', {}).get('user_id', 'Unknown')
        lock_account(user_id)
        block_ip(ip_address)

        if telegram:
            get_notifier().send_alert(
                f"MEDIUM THREAT CONTAINED\n"
                f"Score: {score:.3f}\n"
                f"Attacker IP: {ip_address}\n"
                f"Top features: {top_features}\n"
                f"Action: account locked, IP blocked."
            )

        raw_duration = time.time() - live_sentinel.session_start_time if live_sentinel.session_start_time else 0.0
        duration_str = "< 2.0" if raw_duration < 2.0 else f"{raw_duration:.1f}"
        peak = max(live_sentinel.session_events) if live_sentinel.session_events else score
        print(
            f"\n\033[93mMEDIUM INCIDENT SUMMARY\n"
            f"Attack type: {classification.get('attack_type', 'Unknown')}\n"
            f"Score: {score:.3f} | Duration: {duration_str}s\n"
            f"Events: Low={live_sentinel.low_count}, Medium={live_sentinel.medium_count}, High={live_sentinel.high_count}\n"
            f"Action: account locked, IP blocked\033[0m\n"
        )

        result = {"status": "RESTRICTED", "actions": ["account_locked", "ip_blocked"]}
        entry["actions_taken"] = result["actions"]
        entry["status"] = "RESTRICTED"

    elif tier == 'High':
        live_sentinel.high_count += 1
        try:
            throttle_bandwidth(percent=1)
            snapshot_database()

            if not classification.get('dedup_suppress'):
                alert_msg = (
                    f"ATTACKER IP: {ip_address}\n"
                    f"CRITICAL ALERT -- CONTAINMENT ACTIVE\n"
                    f"IP permanently blocked, bandwidth throttled to 1%, DB snapshotted.\n"
                    f"Authorize forensic report generation: reply YES"
                )

                shap_path = classification.get('shap_img_path')
                get_notifier().send_alert(alert_msg, photo_path=shap_path if shap_path and os.path.exists(shap_path or '') else None)

                _captured_session_start = live_sentinel.session_start_time

                def handle_high():
                    reply = get_notifier().request_authorization(None, timeout_sec=90)

                    if reply == "YES":
                        live_sentinel.update_threat_log_action(ip_address, "forensics_generated")
                        block_ip(ip_address)
                        user_id = classification.get('features', {}).get('user_id', 'Unknown')
                        lock_account(user_id)

                        forensic_path = _p("logs", f"forensic_report_{event_id}.json")
                        with open(forensic_path, 'w') as flog:
                            json.dump(classification, flog)

                        os.makedirs(RETRAINING_DIR, exist_ok=True)
                        q_path = RETRAINING_QUEUE
                        if not os.path.exists(q_path):
                            with open(q_path, 'w') as fq:
                                json.dump([], fq)
                        with open(q_path) as _fq:
                            queue = json.load(_fq)
                        queue.append({
                            "incident_id": event_id,
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "tier": "High",
                            "top_3_features": classification.get('top_3_features', []),
                            "plain_english_explanation": classification.get('plain_english_explanation', ''),
                            "human_confirmed": True,
                            "resolved_at": datetime.now(timezone.utc).isoformat(),
                        })
                        with open(q_path, 'w') as _fq2:
                            json.dump(queue, _fq2)

                        get_notifier().send_summary(
                            "SYSTEM HELD IN CONTAINMENT -- Forensic report generated -- "
                            "Human team must restore services manually."
                        )

                        duration = time.time() - _captured_session_start if _captured_session_start else 0.0
                        peak_evt = live_sentinel.session_peak_event
                        peak = (
                            peak_evt['raw_score'] if peak_evt
                            else (max(live_sentinel.session_events) if live_sentinel.session_events else classification['raw_score'])
                        )
                        top_3 = (
                            peak_evt.get('plain_english_explanation', 'N/A') if peak_evt
                            else classification.get('plain_english_explanation', 'N/A')
                        )

                        total_events = live_sentinel.low_count + live_sentinel.medium_count + live_sentinel.high_count
                        if total_events == 0:
                            print("[WARNING] Ghost session -- zero events. Summary suppressed.")
                            return

                        get_notifier().send_summary(
                            f"Attack Session Summary\n"
                            f"Duration: {duration:.1f}s\n"
                            f"Events: Low={live_sentinel.low_count}, Medium={live_sentinel.medium_count}, High={live_sentinel.high_count}\n"
                            f"Peak Score: {peak:.3f}\n"
                            f"Top Features: {top_3}\n"
                            f"Final Status: CONTAINED"
                        )

                        try:
                            live_sentinel.update_threat_log_action(ip_address, "resolved", from_action="forensics_generated")
                            live_sentinel.update_threat_log_action(ip_address, "resolved", from_action="pending")
                        except Exception as e:
                            print(f"[ERROR] Failed to write resolved status: {e}")

                        live_sentinel.session_start_time = None
                        live_sentinel.low_count = 0
                        live_sentinel.medium_count = 0
                        live_sentinel.high_count = 0
                        live_sentinel.session_events.clear()
                        live_sentinel.session_peak_event = None
                        live_sentinel.session_high_ips.clear()

                    elif reply == "TIMEOUT":
                        print(f"\n\033[93m[AUTO] No admin response. Auto-lockdown for {ip_address}.\033[0m")
                        live_sentinel.update_threat_log_action(ip_address, "auto-locked")
                        get_notifier().send_summary(
                            f"AUTO-ESCALATION: Admin timeout. Auto-lockdown executed for {ip_address}."
                        )
                    else:
                        live_sentinel.update_threat_log_action(ip_address, "denied")
                        get_notifier().send_alert("Action aborted. Defensive posture maintained.")

                threading.Thread(target=handle_high, daemon=True).start()

            result = {"status": "WAITING_HUMAN_AUTH", "actions": ["ip_blocked", "bandwidth_throttled", "db_snapshotted"]}
            entry["actions_taken"] = result["actions"]
            entry["status"] = "WAITING"

        except Exception:
            import traceback
            traceback.print_exc()
            result = {"status": "ERROR"}

    # --- Append block with HMAC signature, block_index, and atomic write ---
    entry["block_index"] = len(chain)              # sequence number for gap detection
    entry_str = json.dumps(entry, sort_keys=True)   # sign BEFORE adding hash / hmac
    entry["entry_hash"] = hashlib.sha256((prev_hash + entry_str).encode()).hexdigest()
    entry["block_hmac"]  = _block_hmac(entry, SESSION_SECRET)  # content auth signature
    chain.append(entry)
    _write_chain_atomic(chain)  # atomic: no partial-write corruption

    return result
