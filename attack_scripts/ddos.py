"""
ddos.py  —  SentiHealth Attack Simulator
Volumetric DDoS / Resource Exhaustion Attack (3-phase escalation)

Writes structured feature events directly to logs/events.jsonl so that the
live_sentinel.py watchdog picks them up in real time.

Run from any directory:
    python attack_scripts/ddos.py
"""

import os, sys, time, json, uuid, random
from datetime import datetime, timezone

# ── colorama ──────────────────────────────────────────────────────────────────
try:
    from colorama import Fore, Back, Style, init as _cinit
    _cinit(autoreset=True)
except ImportError:
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "colorama", "-q"])
    from colorama import Fore, Back, Style, init as _cinit
    _cinit(autoreset=True)

# ── paths ─────────────────────────────────────────────────────────────────────
_HERE        = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(_HERE)
LOG_FILE     = os.path.join(PROJECT_ROOT, "logs", "events.jsonl")
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

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

# Pre-generate 15 unique IPs (one per event) — distributed botnet simulation
_EVENT_IPS  = _make_public_ips(15)
_ip_counter = [0]

def _next_ip() -> str:
    ip = _EVENT_IPS[_ip_counter[0] % len(_EVENT_IPS)]
    _ip_counter[0] += 1
    return ip

# ── endpoints hammered by DDoS ────────────────────────────────────────────────
ENDPOINTS = ["/api/patients", "/api/records", "/api/labs",
             "/api/imaging", "/api/billing", "/api/schedule"]

def ts():
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]

def _flood_display(ip, req_per_sec, latency_ms, endpoint, status):
    bar_len  = min(40, int(req_per_sec / 2))
    bar      = ("█" * bar_len).ljust(40)
    bar_col  = Fore.GREEN if req_per_sec < 30 else (Fore.YELLOW if req_per_sec < 70 else Fore.RED)
    return (f"  {Fore.WHITE}[{ts()}]  {bar_col}{bar}{Fore.WHITE}"
            f"  {req_per_sec:>3} req/s"
            f"  {Fore.CYAN}{endpoint:<22}{Fore.WHITE}"
            f"  {Fore.RED if status != 200 else Fore.GREEN}{status}"
            f"  {Fore.WHITE}lat={latency_ms}ms  src={Fore.YELLOW}{ip}")

def _inject(ip, fl, cpu, ehr, export, lateral, reputation,
            attack_type, asset_type="clinical_app", memory_spike=0):
    event = {
        "event_id":               str(uuid.uuid4()),
        "is_precomputed_feature": True,
        "timestamp":              datetime.now(timezone.utc).isoformat(),
        "source_ip":              ip,
        "ip_address":             ip,
        "endpoint":               random.choice(ENDPOINTS),
        "features": {
            "failed_logins":           fl,
            "cpu_usage":               cpu,
            "memory_spike":            memory_spike,
            "ehr_access_per_hour":     ehr,
            "lateral_movement_events": lateral,
            "data_export_volume_kb":   export,
            "access_time_deviation":   round(random.uniform(0.2, 0.7), 3),
            "source_ip_reputation":    reputation,
            "attack_type":             attack_type,
            "asset_type":              asset_type,
            "emergency_status":        False,
            "user_id":                 "U_DDOS_SIM",
            "role":                    "unknown",
            "request_rate":            round(random.uniform(30.0, 90.0), 2),
        },
    }
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(event) + "\n")
        f.flush()
        os.fsync(f.fileno())
    return event["event_id"]


# ═════════════════════════════════════════════════════════════════════════════
#   HEADER
# ═════════════════════════════════════════════════════════════════════════════

print(f"\n{Fore.CYAN}╔{'═'*63}╗")
print(f"{Fore.CYAN}║{'':^63}║")
print(f"{Fore.CYAN}║{'🌊  VOLUMETRIC DDoS / RESOURCE EXHAUSTION SIMULATOR':^63}║")
print(f"{Fore.CYAN}║{'SentiHealth EHR API Gateway':^63}║")
print(f"{Fore.CYAN}║{'':^63}║")
print(f"{Fore.CYAN}╚{'═'*63}╝")
print(f"\n  {Fore.WHITE}Start       : {Fore.YELLOW}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print(f"  {Fore.WHITE}Botnet size : {Fore.RED}{random.randint(800, 2400)} nodes across {random.randint(18, 42)} countries")
print(f"  {Fore.WHITE}Log target  : {Fore.GREEN}{LOG_FILE}")
print(f"  {Fore.WHITE}Events/phase: {Fore.GREEN}5  (5 s apart  →  ~75 s total)")
print()

time.sleep(1.5)


# ═════════════════════════════════════════════════════════════════════════════
#   PHASE 1  —  Low-Volume Probing  (expected: LOW tier)
# ═════════════════════════════════════════════════════════════════════════════

print(f"{Fore.YELLOW}{'─'*65}")
print(f"{Fore.YELLOW}  >>> PHASE 1: LOW-VOLUME PROBING  (expected: LOW) <<<")
print(f"{Fore.YELLOW}{'─'*65}")
print(f"{Fore.WHITE}  Reconnaissance — attacker maps endpoints at low rate.")
print(f"{Fore.WHITE}  Traffic indistinguishable from normal peak-hour load.")
print(f"  Source IPs: {Fore.RED}random per event\n")
time.sleep(0.8)

for i in range(1, 6):
    ip      = _next_ip()
    rps     = random.randint(8, 25)
    lat     = random.randint(12, 45)
    ep      = random.choice(ENDPOINTS)
    fl      = random.randint(0, 2)
    cpu     = round(random.uniform(0.12, 0.28), 3)
    ehr     = random.randint(5, 20)
    exp     = random.randint(80, 300)
    lat_mov = 0
    rep     = round(random.uniform(0.40, 0.65), 3)

    print(_flood_display(ip, rps, lat, ep, 200))
    eid = _inject(ip, fl, cpu, ehr, exp, lat_mov, rep,
                  attack_type="normal", asset_type="clinical_app")
    print(f"           {Fore.MAGENTA}↳ event injected → sentinel ID {eid[:12]}…"
          f"  {Fore.CYAN}[req/s={rps}  cpu={cpu}]")

    if i < 5:
        for remaining in range(5, 0, -1):
            print(f"\r  {Fore.WHITE}    next probe in {remaining}s…  ", end="", flush=True)
            time.sleep(1)
        print(f"\r{' '*40}\r", end="")

print(f"\n  {Fore.GREEN}✓  Phase 1 complete — {5} low-tier events sent.\n")
time.sleep(1.0)


# ═════════════════════════════════════════════════════════════════════════════
#   PHASE 2  —  Amplified Flood  (expected: MEDIUM tier)
# ═════════════════════════════════════════════════════════════════════════════

print(f"{Fore.YELLOW}{'─'*65}")
print(f"{Fore.YELLOW}  >>> PHASE 2: AMPLIFIED DDoS FLOOD  (expected: MEDIUM) <<<")
print(f"{Fore.YELLOW}{'─'*65}")
print(f"{Fore.WHITE}  Botnet activates. Request rate surges. Latency climbing.")
print(f"{Fore.WHITE}  API gateway showing stress. Some 503s beginning to appear.")
print(f"  Source IPs: {Fore.RED}random per event\n")
time.sleep(0.8)

for i in range(1, 6):
    ip      = _next_ip()
    rps     = random.randint(45, 75)
    lat     = random.randint(80, 350)
    ep      = random.choice(ENDPOINTS)
    status  = random.choices([200, 503, 429], weights=[5, 3, 2])[0]
    fl      = random.randint(3, 7)
    cpu     = round(random.uniform(0.52, 0.68), 3)
    ehr     = random.randint(30, 65)
    exp     = random.randint(400, 900)
    lat_mov = random.randint(0, 1)
    rep     = round(random.uniform(0.12, 0.28), 3)

    print(_flood_display(ip, rps, lat, ep, status))
    if lat_mov:
        print(f"           {Fore.YELLOW}⚠  Lateral scan detected — attacker pivoting to 10.0.2.x subnet")
    eid = _inject(ip, fl, cpu, ehr, exp, lat_mov, rep,
                  attack_type="ddos", asset_type="clinical_app")
    print(f"           {Fore.MAGENTA}↳ event injected → sentinel ID {eid[:12]}…"
          f"  {Fore.CYAN}[req/s={rps}  cpu={cpu}  fl={fl}]")

    if i < 5:
        for remaining in range(5, 0, -1):
            print(f"\r  {Fore.WHITE}    next burst in {remaining}s…  ", end="", flush=True)
            time.sleep(1)
        print(f"\r{' '*40}\r", end="")

print(f"\n  {Fore.GREEN}✓  Phase 2 complete — {5} medium-tier events sent.\n")
time.sleep(1.0)


# ═════════════════════════════════════════════════════════════════════════════
#   PHASE 3  —  Full Saturation Attack  (expected: HIGH tier)
# ═════════════════════════════════════════════════════════════════════════════

print(f"{Fore.RED}{'═'*65}")
print(f"{Fore.RED}  >>> PHASE 3: FULL SATURATION ATTACK  (expected: HIGH) <<<")
print(f"{Fore.RED}{'═'*65}")
print(f"{Fore.WHITE}  Infrastructure saturated. Auth system hammered simultaneously.")
print(f"{Fore.WHITE}  CPU critical. Memory exhaustion. EHR database unresponsive.")
print(f"{Fore.WHITE}  Multiple distributed nodes flooding all API routes...")
print(f"  Source IPs: {Fore.RED}random per burst\n")
time.sleep(0.8)

for i in range(1, 6):
    ip      = _next_ip()
    rps     = random.randint(90, 180)
    lat     = random.randint(800, 3000)
    ep      = random.choice(ENDPOINTS)
    fl      = random.randint(16, 22)     # >15 triggers High-tier floor in scoring
    cpu     = round(random.uniform(0.88, 0.99), 3)
    ehr     = random.randint(120, 200)
    exp     = random.randint(2000, 4500)
    lat_mov = random.randint(2, 4)
    rep     = round(random.uniform(0.01, 0.08), 3)
    mem     = 1

    print(_flood_display(ip, rps, lat, ep, 503))
    print(f"           {Fore.RED}⚠  CPU={cpu*100:.0f}%  Memory CRITICAL"
          f"  Lateral-moves={lat_mov}  Rep-score={rep}")

    eid = _inject(ip, fl, cpu, ehr, exp, lat_mov, rep,
                  attack_type="ddos", asset_type="ehr", memory_spike=mem)
    print(f"           {Fore.MAGENTA}↳ event injected → sentinel ID {eid[:12]}…"
          f"  {Fore.RED}[CRITICAL — awaiting SSHA challenge on dashboard]")

    if i < 5:
        for remaining in range(5, 0, -1):
            print(f"\r  {Fore.WHITE}    next burst in {remaining}s…  ", end="", flush=True)
            time.sleep(1)
        print(f"\r{' '*40}\r", end="")


# ═════════════════════════════════════════════════════════════════════════════
#   FOOTER
# ═════════════════════════════════════════════════════════════════════════════

print(f"\n{Fore.CYAN}╔{'═'*63}╗")
print(f"{Fore.CYAN}║{'':^63}║")
print(f"{Fore.CYAN}║{'  SIMULATION COMPLETE':^63}║")
print(f"{Fore.CYAN}║{'':^63}║")
print(f"{Fore.CYAN}║  {'15 events injected across 3 phases':^61}  ║")
print(f"{Fore.CYAN}║  {'Live sentinel is processing — check the dashboard':^61}  ║")
print(f"{Fore.CYAN}║{'':^63}║")
print(f"{Fore.CYAN}╚{'═'*63}╝")
print(f"  {Fore.WHITE}End : {Fore.YELLOW}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
