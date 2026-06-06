"""
port_scan.py  —  SentiHealth Attack Simulator
Network Reconnaissance → Lateral Movement → Exfiltration (3-phase escalation)

An attacker maps the hospital network, pivots through internal hosts,
then escalates to credential compromise and data theft.

Writes structured feature events directly to logs/events.jsonl so that the
live_sentinel.py watchdog picks them up in real time.

Run from any directory:
    python attack_scripts/port_scan.py
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

_EVENT_IPS  = _make_public_ips(15)
_ip_counter = [0]

def _next_ip() -> str:
    ip = _EVENT_IPS[_ip_counter[0] % len(_EVENT_IPS)]
    _ip_counter[0] += 1
    return ip

# First IP used as the visible "origin" in Phase 1 display; each event gets its own
EXTERNAL_IP  = _EVENT_IPS[0]
PIVOT_IP     = f"10.0.{random.randint(1,9)}.{random.randint(10,250)}"   # internal pivot (private OK)

# ── hospital internal subnet for display ──────────────────────────────────────
INTERNAL_HOSTS = [f"10.0.{random.randint(0,5)}.{random.randint(10,250)}" for _ in range(12)]
SERVICES = {
    22:   "SSH",   80:  "HTTP",    443: "HTTPS",
    1433: "MSSQL", 3306: "MySQL",  5432: "PostgreSQL",
    8080: "HTTP-ALT", 8443: "HTTPS-ALT",
    3389: "RDP",   445: "SMB",    21: "FTP",
    5000: "EHR-API", 5001: "Dashboard", 8000: "Frontend",
}

def ts():
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]

def _inject(ip, fl, cpu, ehr, export, lateral, reputation,
            attack_type, asset_type="workstation", memory_spike=0):
    event = {
        "event_id":               str(uuid.uuid4()),
        "is_precomputed_feature": True,
        "timestamp":              datetime.now(timezone.utc).isoformat(),
        "source_ip":              ip,
        "ip_address":             ip,
        "endpoint":               "/internal/network",
        "features": {
            "failed_logins":           fl,
            "cpu_usage":               cpu,
            "memory_spike":            memory_spike,
            "ehr_access_per_hour":     ehr,
            "lateral_movement_events": lateral,
            "data_export_volume_kb":   export,
            "access_time_deviation":   round(random.uniform(0.5, 0.95), 3),
            "source_ip_reputation":    reputation,
            "attack_type":             attack_type,
            "asset_type":              asset_type,
            "emergency_status":        False,
            "user_id":                 "U_SCAN_SIM",
            "role":                    "unknown",
            "request_rate":            round(random.uniform(1.0, 6.0), 2),
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
print(f"{Fore.CYAN}║{'🔍  NETWORK RECON → LATERAL MOVEMENT → EXFIL':^63}║")
print(f"{Fore.CYAN}║{'Port Scan / APT-Style Attack Simulator':^63}║")
print(f"{Fore.CYAN}║{'':^63}║")
print(f"{Fore.CYAN}╚{'═'*63}╝")
print(f"\n  {Fore.WHITE}Start         : {Fore.YELLOW}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print(f"  {Fore.WHITE}Origin IP     : {Fore.RED}{EXTERNAL_IP}")
print(f"  {Fore.WHITE}Pivot IP      : {Fore.RED}{PIVOT_IP}  (internal host compromise)")
print(f"  {Fore.WHITE}Log target    : {Fore.GREEN}{LOG_FILE}")
print(f"  {Fore.WHITE}Events/phase  : {Fore.GREEN}5  (5 s apart  →  ~75 s total)")
print()

time.sleep(1.5)


# ═════════════════════════════════════════════════════════════════════════════
#   PHASE 1  —  External Port Reconnaissance  (expected: LOW tier)
# ═════════════════════════════════════════════════════════════════════════════

print(f"{Fore.YELLOW}{'─'*65}")
print(f"{Fore.YELLOW}  >>> PHASE 1: EXTERNAL RECON / PORT SCAN  (expected: LOW) <<<")
print(f"{Fore.YELLOW}{'─'*65}")
print(f"{Fore.WHITE}  Attacker maps hospital network perimeter.")
print(f"{Fore.WHITE}  Quiet SYN scan — low rate, evading IDS signature rules.")
print(f"  Source IP : {Fore.RED}{EXTERNAL_IP}\n")
time.sleep(0.8)

# Show a realistic port-scan output burst before the first event
sample_ports = random.sample(list(SERVICES.keys()), 8)
for port in sample_ports[:6]:
    is_open = port in [80, 443, 8000, 5001]
    color   = Fore.GREEN if is_open else Fore.WHITE
    status  = "OPEN" if is_open else "CLOSED"
    svc     = SERVICES.get(port, "unknown")
    print(f"  {Fore.WHITE}[{ts()}]  {EXTERNAL_IP}:{port:<6}  {color}{status:<8}"
          f"  {Fore.CYAN}{svc}")
    time.sleep(0.12)
print()

for i in range(1, 6):
    host = random.choice(INTERNAL_HOSTS)
    port = random.choice(list(SERVICES.keys()))
    svc  = SERVICES[port]
    fl   = random.randint(0, 2)
    cpu  = round(random.uniform(0.05, 0.18), 3)
    ehr  = random.randint(2, 12)
    exp  = random.randint(5, 40)
    lat  = 0
    rep  = round(random.uniform(0.35, 0.65), 3)

    print(f"  {Fore.WHITE}[{ts()}] {Fore.CYAN}Probe {i}/5"
          f"  {Fore.WHITE}→  SYN  {host}:{port}"
          f"  {Fore.GREEN}OPEN  {Fore.CYAN}{svc}"
          f"  {Fore.WHITE}lat=2ms  ttl=64")

    eid = _inject(_next_ip(), fl, cpu, ehr, exp, lat, rep,
                  attack_type="normal", asset_type="workstation")
    print(f"           {Fore.MAGENTA}↳ event injected → sentinel ID {eid[:12]}…"
          f"  {Fore.CYAN}[lateral={lat}  cpu={cpu}]")

    if i < 5:
        for remaining in range(5, 0, -1):
            print(f"\r  {Fore.WHITE}    next probe in {remaining}s…  ", end="", flush=True)
            time.sleep(1)
        print(f"\r{' '*40}\r", end="")

print(f"\n  {Fore.GREEN}✓  Phase 1 complete — {5} low-tier events sent.\n")
time.sleep(1.0)


# ═════════════════════════════════════════════════════════════════════════════
#   PHASE 2  —  Lateral Movement / Credential Spray  (expected: MEDIUM tier)
# ═════════════════════════════════════════════════════════════════════════════

print(f"{Fore.YELLOW}{'─'*65}")
print(f"{Fore.YELLOW}  >>> PHASE 2: PIVOT & LATERAL MOVEMENT  (expected: MEDIUM) <<<")
print(f"{Fore.YELLOW}{'─'*65}")
print(f"{Fore.WHITE}  Attacker compromised an internal host via exposed SSH.")
print(f"{Fore.WHITE}  Now pivoting through internal subnets. Credential spraying.")
print(f"{Fore.WHITE}  Attempting to reach EHR database hosts...")
print(f"  Pivot IP  : {Fore.RED}{PIVOT_IP}\n")
time.sleep(0.8)

for i in range(1, 6):
    target  = random.choice(INTERNAL_HOSTS)
    port    = random.choice([22, 445, 3389, 1433, 5432])
    svc     = SERVICES.get(port, "SMB")
    user    = random.choice(["Administrator", "sa", "postgres", "ehr_user", "backup"])
    fl      = random.randint(5, 8)
    cpu     = round(random.uniform(0.42, 0.62), 3)
    ehr     = random.randint(30, 65)
    exp     = random.randint(200, 500)
    lat     = random.randint(2, 4)
    rep     = round(random.uniform(0.12, 0.28), 3)

    print(f"  {Fore.WHITE}[{ts()}] {Fore.YELLOW}Pivot  {i}/5"
          f"  {Fore.WHITE}→  {PIVOT_IP}  ▶  {target}:{port}  ({svc})")
    print(f"           {Fore.YELLOW}   User={user}  Auth-fails={fl}  Lateral-hops={lat}")

    eid = _inject(_next_ip(), fl, cpu, ehr, exp, lat, rep,
                  attack_type="brute_force", asset_type="clinical_app")
    print(f"           {Fore.MAGENTA}↳ event injected → sentinel ID {eid[:12]}…"
          f"  {Fore.CYAN}[fl={fl}  lateral={lat}  cpu={cpu}]")

    if i < 5:
        for remaining in range(5, 0, -1):
            print(f"\r  {Fore.WHITE}    next pivot in {remaining}s…  ", end="", flush=True)
            time.sleep(1)
        print(f"\r{' '*40}\r", end="")

print(f"\n  {Fore.GREEN}✓  Phase 2 complete — {5} medium-tier events sent.\n")
time.sleep(1.0)


# ═════════════════════════════════════════════════════════════════════════════
#   PHASE 3  —  Full Compromise + Data Exfiltration  (expected: HIGH tier)
# ═════════════════════════════════════════════════════════════════════════════

print(f"{Fore.RED}{'═'*65}")
print(f"{Fore.RED}  >>> PHASE 3: FULL COMPROMISE + EXFILTRATION  (expected: HIGH) <<<")
print(f"{Fore.RED}{'═'*65}")
print(f"{Fore.WHITE}  EHR database credentials obtained via memory dump.")
print(f"{Fore.WHITE}  Mass patient record exfiltration underway.")
print(f"{Fore.WHITE}  Multi-stage payload deployed across compromised hosts.")
print(f"{Fore.WHITE}  CONTAINMENT PROTOCOLS ACTIVATING...")
print(f"  Source IPs: {Fore.RED}random per burst\n")
time.sleep(0.8)

RECORD_TYPES = ["patient_demographics", "lab_results", "imaging_reports",
                "prescription_history", "surgical_notes", "billing_records"]

for i in range(1, 6):
    ip      = _next_ip()
    rtype   = random.choice(RECORD_TYPES)
    count   = random.randint(800, 3500)
    fl      = random.randint(16, 22)          # >15 → High-tier floor
    cpu     = round(random.uniform(0.82, 0.99), 3)
    ehr     = random.randint(150, 250)
    exp     = random.randint(2500, 5000)
    lat     = random.randint(4, 8)
    rep     = round(random.uniform(0.01, 0.08), 3)
    mem     = 1

    print(f"  {Fore.WHITE}[{ts()}] {Fore.RED}EXFIL  {i}/5"
          f"  {Fore.WHITE}→  SELECT * FROM {rtype}"
          f"  {Fore.RED}{count:>4} records  ({exp} KB)")
    print(f"           {Fore.RED}   CPU={cpu*100:.0f}%  EHR-access={ehr}/hr"
          f"  Lateral={lat}  Rep={rep}  src={ip}")

    eid = _inject(ip, fl, cpu, ehr, exp, lat, rep,
                  attack_type="exfiltration", asset_type="ehr", memory_spike=mem)
    print(f"           {Fore.MAGENTA}↳ event injected → sentinel ID {eid[:12]}…"
          f"  {Fore.RED}[CRITICAL — awaiting SSHA challenge on dashboard]")

    if i < 5:
        for remaining in range(5, 0, -1):
            print(f"\r  {Fore.WHITE}    next exfil burst in {remaining}s…  ", end="", flush=True)
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
