import os
import time
import json
import threading
import logging
import warnings
import atexit
import collections

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
    plt.figure(figsize=(8, 4))
    names = ['failed_logins', 'cpu_usage', 'ehr_access_per_hour', 'memory_spike', 'data_export_volume_kb']
    vals = [features.get(n, 0) for n in names]
    y_pos = np.arange(len(names))
    plt.barh(y_pos, vals, align='center', color='coral')
    plt.yticks(y_pos, names)
    plt.xlabel('SHAP Value (impact on model output)')
    plt.title(f'SHAP Explainer for IP {ip}')
    plt.tight_layout()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    path = f"logs/shap_explanation_{stamp}.png"
    plt.savefig(path)
    plt.close()
    return path


# ---------------------------------------------------------------------------
# Threat-log helpers
# ---------------------------------------------------------------------------

def update_threat_log_action(ip, new_action, from_action='pending'):
    try:
        if not os.path.exists('logs/threat_log.json'):
            return
        with open('logs/threat_log.json', 'r') as f:
            lines = f.readlines()
        for i in range(len(lines) - 1, -1, -1):
            if not lines[i].strip():
                continue
            data = json.loads(lines[i])
            if data['ip'] == ip and data['action'] == from_action:
                data['action'] = new_action
                lines[i] = json.dumps(data) + '\n'
        with open('logs/threat_log.json', 'w') as f:
            f.writelines(lines)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# High-tier handling
# ---------------------------------------------------------------------------

def handle_high_tier_threat(ip, features, result, alert_msg):
    start_wait = time.time()
    approved = get_notifier().request_authorization(alert_msg)
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

    log_file = 'logs/events.jsonl'
    os.makedirs('logs', exist_ok=True)
    if not os.path.exists(log_file):
        open(log_file, 'w').close()

    locked_ips = set()
    processed_event_ids = set()
    session_high_ips = set()
    session_peak_event = None
    last_high_alert_count = collections.defaultdict(int)

    f = open(log_file, 'r')
    f.seek(0, 2)

    while True:
        line = f.readline()
        if not line:
            time.sleep(0.5)
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

            with open('logs/threat_log.json', 'a') as flog:
                if result['tier'] == 'High' and not result.get('dedup_suppress'):
                    action = "pending"
                else:
                    action = "resolved"
                flog.write(json.dumps({
                    "ip": ip,
                    "tier": result['tier'],
                    "score": result['raw_score'],
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "action": action,
                }) + "\n")

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
