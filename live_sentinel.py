import os
import sys
import time
import json
import threading
import logging
import warnings
import atexit
import collections

# Ensure project root is in sys.path so sibling modules resolve correctly
# when this file is imported or run from any working directory.
_PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from _paths import LOGS_DIR, THREAT_LOG, EVENTS_LOG, BLOCKED_IPS, p as _p

# Suppress sklearn feature-name warnings (cosmetic — models trained without
# named DataFrames; predictions are correct, warnings just flood the terminal).
warnings.filterwarnings("ignore", message="X has feature names")
warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")

from colorama import Fore, Style, init
init(autoreset=True)
from dotenv import load_dotenv
load_dotenv()

from notifications import get_notifier
from deception.feedback import flush_mirage_labels, record_flagged_session

# Custodian — pseudonymize IPs/user IDs before writing to the audit chain.
# The threat_log.json (dashboard) keeps real IPs so authenticated admins see them.
# The audit chain (shared/exportable for CERT-In) stores HMAC tokens only.
try:
    from privacy.pseudonymize import tokenize as _tokenize_ip
    _CUSTODIAN_ACTIVE = True
except Exception:
    _tokenize_ip = lambda v: v                 # noqa: E731
    _CUSTODIAN_ACTIVE = False

# Mirage decision engine — decide deception mode for flagged sessions.
try:
    from deception.mirage import decide as _mirage_decide
    _MIRAGE_DECIDE_ACTIVE = True
except Exception:
    _mirage_decide = None
    _MIRAGE_DECIDE_ACTIVE = False

def _check_config():
    optional = {
        "SENTIHEALTH_TEST_MODE": "Test mode bypass (default: off)",
    }
    print(f"\n{Fore.WHITE}[CONFIG CHECK]")
    for var, purpose in optional.items():
        val = os.environ.get(var, "0")
        print(f"  {var:30s}: {val} ({purpose})")
    # Probe the notifier so its status is visible at startup
    try:
        n = get_notifier()
        print(f"  {'NOTIFIER':30s}: {n.__class__.__name__}")
    except Exception as e:
        print(f"  {'NOTIFIER':30s}: ERROR — {e}")
    print()

_check_config()

import matplotlib
matplotlib.use('Agg')  # non-interactive backend — safe from non-main threads
import matplotlib.pyplot as plt
import numpy as np
from datetime import datetime, timezone
from scoring_matrix import score_event
from self_healing_responder import respond

TEST_MODE = os.environ.get("SENTIHEALTH_TEST_MODE", "0") == "1"
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
DEBUG = False

def extract_features(stats: dict) -> dict:
    """Backward compatibility helper for testing feature extraction."""
    failed_logins = stats.get('login', 0)
    attack_type = 'brute_force' if failed_logins >= 5 else 'normal'
    return {
        'failed_logins': failed_logins,
        'cpu_usage': 0.1,
        'memory_spike': 0,
        'ehr_access_per_hour': stats.get('patient', 0),
        'lateral_movement_events': 0,
        'data_export_volume_kb': 0,
        'access_time_deviation': 0.1,
        'source_ip_reputation': 0.5,
        'attack_type': attack_type,
        'asset_type': 'workstation'
    }


_alert_claim_lock = threading.Lock()
_auth_lock = threading.Lock()

alerted_ips = {}
ALERT_COOLDOWN_SECS = 300

session_start_time = None
low_count = 0
medium_count = 0
high_count = 0
session_events = []
session_peak_event = None

medium_incident_tracker = {}
medium_tracker_lock = threading.Lock()
MEDIUM_INCIDENT_TIMEOUT = 300


# ---------------------------------------------------------------------------
# Thin wrappers kept for backward-compat with self_healing_responder.py
# (which calls these via sys.modules['__main__']).  All real work is in the
# Notifier — these are just one-line pass-throughs.
# ---------------------------------------------------------------------------

def send_telegram_message(msg: str) -> bool:
    return get_notifier().send_alert(msg)

def send_telegram_photo(photo_path: str, caption: str = "") -> bool:
    return get_notifier().send_alert(caption, photo_path=photo_path)

def wait_for_telegram_approval(
    prompt_msg,
    timeout_sec: int = 90,
    accept_ignore: bool = False,
) -> str:
    return get_notifier().request_authorization(
        prompt_msg, timeout_sec=timeout_sec, accept_ignore=accept_ignore
    )


# ---------------------------------------------------------------------------
# Medium-incident tracker & timeout watcher
# ---------------------------------------------------------------------------

def _send_medium_summary(ip, incident):
    raw_duration = time.time() - incident["start_time"]
    duration_str = "< 2.0" if raw_duration < 2.0 else f"{raw_duration:.1f}"
    pf = incident["peak_features"]
    msg = (
        f"MEDIUM INCIDENT SUMMARY\n"
        f"Attacker IP : {ip}\n"
        f"Duration    : {duration_str}s\n"
        f"Events      : {incident['event_count']} Medium-tier\n"
        f"Peak Score  : {incident['peak_score']:.3f}\n"
        f"Top Signals : failed_logins={round(pf.get('failed_logins', 0), 2)}, "
        f"cpu_usage={round(pf.get('cpu_usage', 0), 2)}, "
        f"ehr_access={round(pf.get('ehr_access_per_hour', 0), 2)}\n"
        f"Actions     : {', '.join(incident['actions'])}\n"
        f"Contained autonomously. No action required."
    )
    get_notifier().send_summary(msg)
    logger.info(f"[MEDIUM SUMMARY] IP={ip} events={incident['event_count']} peak={incident['peak_score']:.3f}")


def _medium_timeout_watcher():
    while True:
        time.sleep(30)
        now = time.time()
        with medium_tracker_lock:
            expired = [
                ip for ip, t in medium_incident_tracker.items()
                if now - t["start_time"] > MEDIUM_INCIDENT_TIMEOUT
            ]
            for ip in expired:
                incident = medium_incident_tracker.pop(ip)
                threading.Thread(
                    target=_send_medium_summary, args=(ip, incident), daemon=True
                ).start()

threading.Thread(target=_medium_timeout_watcher, daemon=True).start()


def _flush_medium_incidents():
    with medium_tracker_lock:
        for ip, incident in medium_incident_tracker.items():
            _send_medium_summary(ip, incident)

atexit.register(_flush_medium_incidents)
atexit.register(flush_mirage_labels)


# ---------------------------------------------------------------------------
# SHAP chart helper
# ---------------------------------------------------------------------------

def generate_shap_chart(ip, features):
    """Generate a real SHAP feature attribution chart for the given IP/features.

    Uses shap.TreeExplainer on the RF (or GB/XGB) base estimator extracted from
    the CalibratedClassifierCV stored in scoring_matrix.models_cache.  The chart
    shows High-tier SHAP values: red bars increase risk, blue bars decrease it.

    Falls back to normalised raw feature values if SHAP computation fails (e.g.
    models not yet trained), labelling the axis clearly so reviewers know.

    Each call gets a unique filename (timestamp + uuid4 hex) so simultaneous
    Medium + High events never collide on disk.
    """
    import uuid as _uuid
    import pandas as _pd

    _FEATURE_COLS = [
        'failed_logins', 'cpu_usage', 'memory_spike',
        'ehr_access_per_hour', 'lateral_movement_events',
        'data_export_volume_kb', 'access_time_deviation',
        'source_ip_reputation',
    ]

    # Build a single-row DataFrame using the same column order as training
    fvec = _pd.DataFrame([{col: float(features.get(col, 0.0)) for col in _FEATURE_COLS}])

    shap_vals   = None
    is_real_shap = False

    # ------------------------------------------------------------------
    # Attempt 1: real SHAP via TreeExplainer (RF, then GB, then XGB)
    # ------------------------------------------------------------------
    try:
        import shap as _shap
        from scoring_matrix import models_cache as _mc
        for _mname in ('rf', 'gb', 'xgb'):
            _cal = _mc.get(_mname)
            if _cal is None:
                continue
            try:
                # CalibratedClassifierCV with cv=5 stores 5 fold estimators;
                # use the first — all were trained on similar distributions.
                _base = _cal.calibrated_classifiers_[0].estimator
                _exp  = _shap.TreeExplainer(_base)
                _sv   = _exp.shap_values(fvec)
                # Multi-class RF/GB → list of 3 arrays (one per class), each (1, n_features)
                # XGB multi-class → ndarray shape (1, n_features, n_classes)
                if isinstance(_sv, list) and len(_sv) >= 3:
                    shap_vals = np.array(_sv[2][0])        # High-class, first sample
                elif hasattr(_sv, 'ndim') and _sv.ndim == 3:
                    shap_vals = _sv[0, :, 2]               # (sample, feature, High-class)
                elif hasattr(_sv, 'ndim') and _sv.ndim == 2:
                    shap_vals = _sv[0]                     # binary fallback
                if shap_vals is not None:
                    is_real_shap = True
                    break
            except Exception:
                shap_vals = None
                continue
    except Exception:
        pass

    # ------------------------------------------------------------------
    # Fallback: normalise raw feature values to a [-1, 1] proxy scale
    # ------------------------------------------------------------------
    if shap_vals is None:
        _raw    = np.array([float(features.get(col, 0.0)) for col in _FEATURE_COLS])
        _scales = np.array([20.0, 1.0, 1.0, 200.0, 10.0, 3000.0, 1.0, 1.0])
        shap_vals = np.clip(_raw / _scales, -1.0, 1.0)

    # Sort ascending by |SHAP| so largest bar appears at top in a barh plot
    _order        = np.argsort(np.abs(shap_vals))
    _sorted_names = [_FEATURE_COLS[i] for i in _order]
    _sorted_vals  = shap_vals[_order]
    _colors       = ['#d62728' if v >= 0 else '#1f77b4' for v in _sorted_vals]

    fig, ax = plt.subplots(figsize=(9, 5))
    ax.barh(np.arange(len(_sorted_names)), _sorted_vals, color=_colors, align='center')
    ax.set_yticks(np.arange(len(_sorted_names)))
    ax.set_yticklabels(_sorted_names, fontsize=10)
    ax.axvline(x=0, color='black', linewidth=0.8)
    _xlabel = (
        'SHAP Value  (positive = increases High-tier risk,  negative = decreases)'
        if is_real_shap else
        'Normalised Feature Value  (proxy — run model_trainer.py to enable real SHAP)'
    )
    ax.set_xlabel(_xlabel, fontsize=9)
    ax.set_title(f'SHAP Feature Attribution  |  Source: {ip}', fontsize=11, fontweight='bold')
    plt.tight_layout()

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    uid   = _uuid.uuid4().hex[:8]
    path  = os.path.join(LOGS_DIR, f"shap_explanation_{stamp}_{uid}.png")
    plt.savefig(path, dpi=120)
    plt.close()
    return path


# ---------------------------------------------------------------------------
# Threat-log helpers
# ---------------------------------------------------------------------------

def update_threat_log_action(ip, new_action, from_action='pending'):
    """
    Update the most recent threat_log entry for `ip` whose action matches `from_action`.

    If no 'pending' entry exists (because the event was deduplicated and written as
    'resolved' directly), fall back to updating the most recent 'resolved' entry for
    that IP. This prevents silent no-ops when the dedup-cooldown path is taken.
    """
    try:
        if not os.path.exists(THREAT_LOG):
            return
        with open(THREAT_LOG, 'r') as f:
            lines = f.readlines()

        updated = False
        for i in range(len(lines) - 1, -1, -1):
            if not lines[i].strip():
                continue
            data = json.loads(lines[i])
            if data['ip'] == ip and data['action'] == from_action:
                data['action'] = new_action
                lines[i] = json.dumps(data) + '\n'
                updated = True
                break  # update only the most recent matching entry

        # Fallback: if the primary action wasn't found (dedup path wrote 'resolved'),
        # update the most recent 'resolved' entry for this IP instead.
        if not updated and from_action == 'pending':
            for i in range(len(lines) - 1, -1, -1):
                if not lines[i].strip():
                    continue
                data = json.loads(lines[i])
                if data['ip'] == ip and data['action'] == 'resolved':
                    data['action'] = new_action
                    lines[i] = json.dumps(data) + '\n'
                    break

        with open(THREAT_LOG, 'w') as f:
            f.writelines(lines)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# High-tier handling
# ---------------------------------------------------------------------------

def handle_high_tier_threat(ip, features, result, alert_msg):
    start_wait = time.time()
    approved = get_notifier().request_authorization(
        alert_msg,
        metadata={
            "ip": ip,
            "tier": result.get("tier", "High"),
            "score": round(result.get("raw_score", 0), 4),
            "reason": result.get("plain_english_explanation", ""),
            "shap_file": os.path.basename(result.get("shap_img_path") or ""),
        },
    )
    resolve_time = time.time() - start_wait

    if approved == "TIMEOUT":
        print(f"\n{Fore.YELLOW}[AUTO] No admin response in 90s. Auto-lockdown for {ip}.")
        update_threat_log_action(ip, "auto-locked")
        respond(result, auth_token="ADMIN_TIMEOUT_AUTO_ESCALATE")
        get_notifier().send_summary(
            f"AUTO-ESCALATION RESOLVED\n"
            f"Admin timeout (>90s). Auto-lockdown executed.\n"
            f"Attack Tier: {result['tier'].upper()}\n"
            f"Resolution Time: {resolve_time:.1f}s\n"
            f"Attacker {ip} permanently blocked. Database snapshotted."
        )
    elif approved == "YES":
        print(f"\n{Fore.GREEN}[+] Authorization verified. Generating forensic report.")
        update_threat_log_action(ip, "forensics_generated")
        final_res = respond(result, auth_token="admin_approved_123")
        print(f"   -> Final Status: {final_res['status']}")

        global session_start_time, low_count, medium_count, high_count, session_events, session_peak_event
        duration = time.time() - session_start_time if session_start_time else 0
        peak = max(session_events) if session_events else result['raw_score']
        top_3 = (
            session_peak_event.get('plain_english_explanation', 'N/A')
            if session_peak_event else result.get('plain_english_explanation', 'N/A')
        )

        get_notifier().send_summary(
            f"SYSTEM HELD IN CONTAINMENT\n"
            f"Attack Tier: {result['tier'].upper()}\n"
            f"Attacker {ip} permanently blocked. Forensic report generated.\n"
            f"Human team must restore services manually."
        )
        get_notifier().send_summary(
            f"Attack Session Summary\n"
            f"Duration: {duration:.1f}s\n"
            f"Events: Low={low_count}, Medium={medium_count}, High={high_count}\n"
            f"Peak Score: {peak:.3f}\n"
            f"MTTR: {resolve_time:.1f}s\n"
            f"Top Features: {top_3}\n"
            f"Final Status: CONTAINED"
        )

        session_start_time = None
        low_count = 0
        medium_count = 0
        high_count = 0
        session_events.clear()
        session_peak_event = None
    else:
        print(f"\n{Fore.YELLOW}[-] Authorization denied. Holding defensive posture.")
        update_threat_log_action(ip, "denied")
        get_notifier().send_alert("Action aborted. Defensive posture maintained.")


# ---------------------------------------------------------------------------
# Main sentinel loop
# ---------------------------------------------------------------------------

session_high_ips = set()

def run_live_sentinel():
    global session_start_time, low_count, medium_count, high_count, session_events, session_high_ips, session_peak_event

    print("=" * 60)
    print("  SENTINELHEALTH LIVE WATCHDOG ACTIVATED")
    print(f"  Notifier: {get_notifier().__class__.__name__}")
    print("=" * 60)

    log_file = EVENTS_LOG
    os.makedirs(LOGS_DIR, exist_ok=True)
    if not os.path.exists(log_file):
        open(log_file, 'w').close()

    processed_event_ids = set()
    session_high_ips = set()
    session_peak_event = None
    last_high_alert_count = collections.defaultdict(int)

    def _load_blocked_ips() -> set:
        """Read blocked_ips.json and return a set of currently blocked IP strings."""
        blocked: set = set()
        try:
            if os.path.exists(BLOCKED_IPS):
                with open(BLOCKED_IPS, 'r', encoding='utf-8') as _bf:
                    for _line in _bf:
                        _line = _line.strip()
                        if _line:
                            _entry = json.loads(_line)
                            _ip = _entry.get('ip', '')
                            if _ip:
                                blocked.add(_ip)
        except Exception:
            pass
        return blocked

    locked_ips: set = _load_blocked_ips()
    _last_blocked_reload = time.time()
    _BLOCKED_RELOAD_SECS = 15   # re-read blocked_ips.json every 15 s

    f = open(log_file, 'r')
    f.seek(0, 2)

    while True:
        line = f.readline()
        if not line:
            time.sleep(0.5)
            # Periodically refresh the blocked-IP set so new blocks are picked up
            if time.time() - _last_blocked_reload > _BLOCKED_RELOAD_SECS:
                locked_ips = _load_blocked_ips()
                _last_blocked_reload = time.time()
            continue

        try:
            event = json.loads(line)
            event_id = event.get('event_id')
            if event_id:
                if event_id in processed_event_ids:
                    continue
                processed_event_ids.add(event_id)

            features = event.get('features', {})

            if event.get('is_precomputed_feature'):
                if not TEST_MODE:
                    logger.warning("SECURITY: is_precomputed_feature outside test mode. Discarding.")
                    continue
            if not features:
                continue

            ip = event.get('source_ip', event.get('ip_address', 'Unknown'))

            # ── Already-blocked IP: log it once as "blocked" and skip full pipeline ──
            if ip in locked_ips:
                result = score_event(features)
                print(f"{Fore.RED}[BLOCKED] {ip} is already blocked — "
                      f"still attempting ({result['tier']} score={result['raw_score']:.3f})")
                with open(THREAT_LOG, 'a') as _flog:
                    _flog.write(json.dumps({
                        "ip":        ip,
                        "tier":      result['tier'],
                        "score":     result['raw_score'],
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "action":    "blocked",
                        "reason":    f"IP already blocked — repeated attempt. {result.get('plain_english_explanation', '')}",
                        "shap_file": "",
                    }) + "\n")
                continue

            result = score_event(features)

            logger.info(f"{Fore.WHITE}Tier={result['tier']} | Score={result['raw_score']:.3f}")

            if result['tier'] == 'High' and session_start_time is None:
                session_start_time = time.time()

            session_events.append(result['raw_score'])
            if session_peak_event is None or result['raw_score'] > session_peak_event['raw_score']:
                session_peak_event = result.copy()

            _respond_result = result.copy()

            if result['tier'] == 'High':
                _now = time.time()
                with _alert_claim_lock:
                    _last = alerted_ips.get(ip, 0)
                    if _now - _last < ALERT_COOLDOWN_SECS:
                        result['dedup_suppress'] = True
                        _respond_result['dedup_suppress'] = True
                    else:
                        alerted_ips[ip] = _now
                        _respond_result['dedup_suppress'] = False

            shap_path = None

            if result['tier'] == 'High':
                print(f"\n{Fore.RED}[!] THREAT FROM {ip} | Tier: High | Score: {result['raw_score']:.3f}")
                print(f"{Fore.RED}   -> {result['plain_english_explanation']}")
                try:
                    shap_path = generate_shap_chart(ip, features)
                except Exception:
                    pass
            elif result['tier'] == 'Medium':
                print(f"\n{Fore.YELLOW}[!] THREAT FROM {ip} | Tier: Medium | Score: {result['raw_score']:.3f}")
                print(f"{Fore.YELLOW}   -> {result['plain_english_explanation']}")
                try:
                    shap_path = generate_shap_chart(ip, features)
                except Exception:
                    pass
            else:
                print(f"{Fore.CYAN}[*] Low anomaly from {ip} | Score: {result['raw_score']:.3f}")

            with open(THREAT_LOG, 'a') as flog:
                if result['tier'] == 'High' and not result.get('dedup_suppress'):
                    action = "pending"
                else:
                    action = "resolved"
                # threat_log keeps real IP — only authenticated admins see it
                # (custodian gate: /api/status requires Bearer token in dashboard.py).
                log_entry = {
                    "ip": ip,
                    "tier": result['tier'],
                    "score": result['raw_score'],
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "action": action,
                    "reason": result.get('plain_english_explanation', ''),
                    # SHAP chart filename only (no path prefix) so dashboard can
                    # serve it via /api/shap/<filename> behind the auth gate.
                    "shap_file": os.path.basename(shap_path) if shap_path else "",
                }
                flog.write(json.dumps(log_entry) + "\n")

            # Mirage — get deception verdict, then record the session so
            # the feedback/retraining pipeline captures confirmed attack labels.
            if result['tier'] in ('High', 'Medium'):
                try:
                    mirage_mode = "none"
                    if _MIRAGE_DECIDE_ACTIVE and _mirage_decide is not None:
                        _verdict = _mirage_decide(
                            session_id=ip,
                            tier=result['tier'],
                            raw_score=result['raw_score'],
                        )
                        mirage_mode = _verdict.mode
                    record_flagged_session(
                        session_id=ip,
                        tier=result['tier'],
                        score=result['raw_score'],
                        mode=mirage_mode,
                        top_features=[result.get('plain_english_explanation', '')],
                    )
                except Exception:
                    pass

            _respond_result['shap_img_path'] = shap_path

            if result['tier'] == 'High':
                session_high_ips.add(ip)

            if result['tier'] == 'Low':
                with medium_tracker_lock:
                    if ip in medium_incident_tracker:
                        _send_medium_summary(ip, medium_incident_tracker.pop(ip))
                responder_res = respond(_respond_result, ip_address=ip, telegram=False)

            elif result['tier'] == 'Medium':
                with medium_tracker_lock:
                    if ip not in medium_incident_tracker:
                        medium_incident_tracker[ip] = {
                            "start_time": time.time(),
                            "peak_score": result['raw_score'],
                            "event_count": 1,
                            "peak_features": features,
                            "actions": ["Account locked", "IP throttled"],
                        }
                    else:
                        t = medium_incident_tracker[ip]
                        t["event_count"] += 1
                        if result['raw_score'] > t["peak_score"]:
                            t["peak_score"] = result['raw_score']
                            t["peak_features"] = features
                responder_res = respond(_respond_result, ip_address=ip, telegram=False)

            else:  # High
                with medium_tracker_lock:
                    if ip in medium_incident_tracker:
                        _inc = medium_incident_tracker.pop(ip)
                        threading.Thread(
                            target=_send_medium_summary, args=(ip, _inc), daemon=True
                        ).start()
                        logger.info(f"{Fore.MAGENTA}[MEDIUM→HIGH ESCALATION] Summary fired for {ip}")

                if result.get('dedup_suppress'):
                    _now = time.time()
                    _last = alerted_ips.get(ip, 0)
                    logger.info(
                        f"{Fore.MAGENTA}[COOLDOWN] High alert suppressed for {ip} — "
                        f"{int(ALERT_COOLDOWN_SECS - (_now - _last))}s remaining"
                    )

                responder_res = respond(_respond_result, ip_address=ip, telegram=True)

            if responder_res.get('status') in ['RESTRICTED', 'WAITING_HUMAN_AUTH']:
                locked_ips.add(ip)

        except Exception:
            import traceback
            traceback.print_exc()


if __name__ == '__main__':
    run_live_sentinel()
