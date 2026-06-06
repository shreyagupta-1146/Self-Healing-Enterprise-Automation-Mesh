import os
import time
import json
import uuid
import random
from datetime import datetime, timezone

# Get the absolute path to the project root logs directory
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# ── unique random public IPv4 generator (pure stdlib — no Faker) ──────────────
def _make_public_ips(n: int) -> list:
    seen, ips = set(), []
    while len(ips) < n:
        a = random.randint(1, 223)
        b = random.randint(0, 255)
        c = random.randint(0, 255)
        d = random.randint(1, 254)
        if a == 10: continue
        if a == 127: continue
        if a == 169 and b == 254: continue
        if a == 172 and 16 <= b <= 31: continue
        if a == 192 and b == 168: continue
        if a == 192 and b == 0: continue
        if a == 198 and b in (18, 19): continue
        if a == 198 and b == 51 and c == 100: continue
        if a == 203 and b == 0 and c == 113: continue
        ip = f"{a}.{b}.{c}.{d}"
        if ip in seen: continue
        seen.add(ip)
        ips.append(ip)
    return ips

_EVENT_IPS  = _make_public_ips(15)
_ip_counter = [0]

def _next_ip() -> str:
    ip = _EVENT_IPS[_ip_counter[0] % len(_EVENT_IPS)]
    _ip_counter[0] += 1
    return ip

print(f"[*] Starting Multi-Phase Exfiltration Simulator — {len(_EVENT_IPS)} unique source IPs pre-generated")

log_file = os.path.join(project_root, 'logs', 'events.jsonl')
os.makedirs(os.path.dirname(log_file), exist_ok=True)

print(f"[*] Starting Multi-Phase Exfiltration Simulator - {datetime.now().isoformat()}")

phases = [
    {
        "name": "Phase 1: Low-level reconnaissance",
        "bursts": 5,
        "failed_logins": 1,
        "cpu_usage": 0.15,
        "ehr_access_per_hour": 2,
        "data_export_volume_kb": 50000 / 1024,
        "request_rate": 0.5
    },
    {
        "name": "Phase 2: Medium-level escalation",
        "bursts": 5,
        "failed_logins": 4,
        "cpu_usage": 0.45,
        "ehr_access_per_hour": 8,
        "data_export_volume_kb": 150000 / 1024,
        "request_rate": 3
    },
    {
        "name": "Phase 3: High-level burst exfiltration",
        "bursts": 5,
        "failed_logins": 9,
        "cpu_usage": 0.85,
        "ehr_access_per_hour": 20,
        "data_export_volume_kb": 500000 / 1024,
        "request_rate": 12
    }
]

with open(log_file, 'a') as f:
    events_to_generate = []
    for phase in phases:
        for _ in range(phase["bursts"]):
            events_to_generate.append(phase)
            
    random.shuffle(events_to_generate)

    print(f"\n>>> Initiating Unordered Multi-Tier Attack Burst ({len(events_to_generate)} events) <<<")
    for event_idx, phase in enumerate(events_to_generate):
        src_ip = _next_ip()   # unique IP for this event
        if "Phase 1" in phase["name"]:
            failed_logins = random.randint(1, 4)
            ehr_access = random.randint(20, 40)
            data_export = random.randint(30, 80)
            cpu_usage = random.uniform(0.25, 0.45)
            req_rate = random.uniform(1.0, 4.0)
        elif "Phase 2" in phase["name"]:
            failed_logins = random.randint(5, 6)
            ehr_access = random.randint(45, 60)
            data_export = random.randint(300, 450)
            cpu_usage = random.uniform(0.58, 0.63)
            req_rate = random.uniform(5.0, 8.0)
        else:
            failed_logins = random.randint(8, 14)
            ehr_access = random.randint(120, 200)
            data_export = random.randint(1500, 3000)
            cpu_usage = random.uniform(0.80, 0.92)
            req_rate = random.uniform(8.0, 12.0)

        # Create the structured precomputed feature event
        event = {
            "event_id": str(uuid.uuid4()),
            "is_precomputed_feature": True,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": src_ip,
            "ip_address": src_ip,
            "endpoint": "/patients",
            "response_time_ms": int(100 / max(req_rate, 0.1)),
            "status_code": 200,
            # ML features injected directly
            "features": {
                "failed_logins": failed_logins,
                "cpu_usage": cpu_usage,
                "ehr_access_per_hour": ehr_access,
                "data_export_volume_kb": data_export,
                "request_rate": req_rate,
                "lateral_movement_events": 0,
                "access_time_deviation": 0.1,
                "source_ip_reputation": 0.5,
                "attack_type": "exfiltration" if failed_logins > 7 else ("ddos" if failed_logins > 4 else "normal"),
                "asset_type": "ehr",
                "emergency_status": False,
                "user_id": "U_SIM",
                "role": "it_staff",
                "memory_spike": 1 if cpu_usage > 0.75 else 0
            }
        }
        
        f.write(json.dumps(event) + '\n')
        f.flush()
        print(f"[{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Injected event ID: {event['event_id']}")
        
        # Wait 5 seconds between events to simulate realistic velocity
        time.sleep(5)

    # Constraint 6: WRITE SAFETY
    f.flush()
    os.fsync(f.fileno())

print(f"\n[*] End timestamp: {datetime.now().isoformat()}")
