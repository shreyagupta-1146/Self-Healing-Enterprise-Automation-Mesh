"""
brute_force.py  —  SentiHealth Attack Simulator
Credential Stuffing / Brute-Force Attack (3-phase escalation)

Writes structured feature events directly to logs/events.jsonl so that the
live_sentinel.py watchdog picks them up in real time.

Run from any directory:
    python attack_scripts/brute_force.py
"""

import os, sys, time, json, uuid, random
from datetime import datetime, timezone

# ── colorama (install if missing) ────────────────────────────────────────────
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

# ── unique random public IPv4 generator (pure stdlib — no Faker needed) ───────
# All 15 IPs are generated ONCE at startup into a list, so each event gets a
# pre-verified unique address with zero chance of in-loop repetition.

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

# 15 unique IPs for 15 events (3 phases × 5 events each)
_EVENT_IPS  = _make_public_ips(15)
_ip_counter = [0]   # mutable list so the closure can increment it

def _rand_ip() -> str:
    """Return the next pre-generated unique IP for this run."""
    ip = _EVENT_IPS[_ip_counter[0] % len(_EVENT_IPS)]
    _ip_counter[0] += 1
    return ip

# ── common password lists (display only) ─────────────────────────────────────
PASS_LIST = [
    "admin", "Admin1!", "P@ssw0rd", "Welcome1", "Hospital2026",
    "Senti@123", "SentiH3alth!", "EHR_admin", "doctor99", "nurse2026",
    "letmein", "Summer2026!", "Winter2025!", "Qwerty@1", "Pass#1234",
    "SysAdmin!", "root", "toor", "iloveyou", "654321",
]
USERNAMES = ["admin", "dr.patel", "sysadmin", "nurse01", "it.admin",
             "dbuser", "webapp", "root", "backup_user", "monitor"]

def ts():
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]

def _inject(ip, phase_label, fl, cpu, ehr, export, lateral, reputation,
            attack_type, asset_type="clinical_app", memory_spike=0, inter_event_delay=5):
    """Write one event to events.jsonl and return the event_id."""
    event = {
        "event_id":               str(uuid.uuid4()),
        "is_precomputed_feature": True,
        "timestamp":              datetime.now(timezone.utc).isoformat(),
        "source_ip":              ip,
        "ip_address":             ip,
        "endpoint":               "/auth/login",
        "features": {
            "failed_logins":          fl,
            "cpu_usage":              cpu,
            "memory_spike":           memory_spike,
            "ehr_access_per_hour":    ehr,
            "lateral_movement_events": lateral,
            "data_export_volume_kb":  export,
            "access_time_deviation":  round(random.uniform(0.6, 0.95), 3),
            "source_ip_reputation":   reputation,
            "attack_type":            attack_type,
            "asset_type":             asset_type,
            "emergency_status":       False,
            "user_id":                "U_BF_SIM",
            "role":                   "it_staff",
            "request_rate":           round(random.uniform(2.0, 8.0), 2),
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
print(f"{Fore.CYAN}║{'🔐  BRUTE FORCE / CREDENTIAL STUFFING SIMULATOR':^63}║")
print(f"{Fore.CYAN}║{'SentiHealth EHR Authentication Gateway':^63}║")
print(f"{Fore.CYAN}║{'':^63}║")
print(f"{Fore.CYAN}╚{'═'*63}╝")
print(f"\n  {Fore.WHITE}Start       : {Fore.YELLOW}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print(f"  {Fore.WHITE}IPs         : {Fore.RED}fresh random IP per event (distributed attack)")
print(f"  {Fore.WHITE}Log target  : {Fore.GREEN}{LOG_FILE}")
print(f"  {Fore.WHITE}Events/phase: {Fore.GREEN}5  (5 s apart  →  ~75 s total)")
print()

time.sleep(1.5)


# ═════════════════════════════════════════════════════════════════════════════
#   PHASE 1  —  Low-and-Slow Password Spray  (expected: LOW tier)
# ═════════════════════════════════════════════════════════════════════════════

print(f"{Fore.YELLOW}{'─'*65}")
print(f"{Fore.YELLOW}  >>> PHASE 1: LOW-AND-SLOW PASSWORD SPRAY  (expected: LOW) <<<")
print(f"{Fore.YELLOW}{'─'*65}")
print(f"{Fore.WHITE}  Attacker probes with common passwords at low velocity")
print(f"{Fore.WHITE}  to stay below account-lockout thresholds.")
print(f"  Source IPs: {Fore.RED}random per attempt\n")
time.sleep(0.8)

for i in range(1, 6):
    ip   = _rand_ip()
    user = random.choice(USERNAMES)
    pwd  = random.choice(PASS_LIST[:8])
    fl   = random.randint(1, 3)
    cpu  = round(random.uniform(0.08, 0.20), 3)
    ehr  = random.randint(3, 12)
    exp  = random.randint(10, 50)
    lat  = 0
    rep  = round(random.uniform(0.38, 0.60), 3)

    print(f"  {Fore.WHITE}[{ts()}] {Fore.CYAN}Attempt {i}/5"
          f"  {Fore.WHITE}→  POST /auth/login"
          f"  {Fore.RED}401 UNAUTHORIZED"
          f"  {Fore.WHITE}src={Fore.RED}{ip}{Fore.WHITE}  user={Fore.YELLOW}{user}")

    eid = _inject(ip, "Phase1", fl, cpu, ehr, exp, lat, rep,
                  attack_type="brute_force", asset_type="clinical_app")
    print(f"           {Fore.MAGENTA}↳ event injected → sentinel ID {eid[:12]}…"
          f"  {Fore.CYAN}[failed_logins={fl}  cpu={cpu}]")

    if i < 5:
        for remaining in range(5, 0, -1):
            print(f"\r  {Fore.WHITE}    next attempt in {remaining}s…  ", end="", flush=True)
            time.sleep(1)
        print(f"\r{' '*40}\r", end="")

print(f"\n  {Fore.GREEN}✓  Phase 1 complete — {5} low-tier events sent.\n")
time.sleep(1.0)


# ═════════════════════════════════════════════════════════════════════════════
#   PHASE 2  —  Targeted Dictionary Attack  (expected: MEDIUM tier)
# ═════════════════════════════════════════════════════════════════════════════

print(f"{Fore.YELLOW}{'─'*65}")
print(f"{Fore.YELLOW}  >>> PHASE 2: TARGETED DICTIONARY ATTACK  (expected: MEDIUM) <<<")
print(f"{Fore.YELLOW}{'─'*65}")
print(f"{Fore.WHITE}  Attacker switches to a harvested credential list.")
print(f"{Fore.WHITE}  Login failures escalate. Account throttling observed.")
print(f"  Source IPs: {Fore.RED}random per attempt\n")
time.sleep(0.8)

for i in range(1, 6):
    ip   = _rand_ip()
    user = random.choice(USERNAMES)
    pwd  = random.choice(PASS_LIST[8:16])
    fl   = random.randint(5, 8)
    cpu  = round(random.uniform(0.42, 0.62), 3)
    ehr  = random.randint(35, 60)
    exp  = random.randint(180, 420)
    lat  = random.randint(0, 1)
    rep  = round(random.uniform(0.15, 0.35), 3)

    status = random.choice(["401 UNAUTHORIZED", "401 UNAUTHORIZED", "429 TOO MANY REQUESTS"])
    print(f"  {Fore.WHITE}[{ts()}] {Fore.YELLOW}Attempt {i}/5"
          f"  {Fore.WHITE}→  POST /auth/login"
          f"  {Fore.RED}{status}"
          f"  {Fore.WHITE}src={Fore.RED}{ip}{Fore.WHITE}  user={Fore.YELLOW}{user}")
    if lat:
        print(f"           {Fore.RED}⚠  Lateral probe detected on internal subnet 10.0.0.x")

    eid = _inject(ip, "Phase2", fl, cpu, ehr, exp, lat, rep,
                  attack_type="brute_force", asset_type="clinical_app")
    print(f"           {Fore.MAGENTA}↳ event injected → sentinel ID {eid[:12]}…"
          f"  {Fore.CYAN}[failed_logins={fl}  cpu={cpu}]")

    if i < 5:
        for remaining in range(5, 0, -1):
            print(f"\r  {Fore.WHITE}    next attempt in {remaining}s…  ", end="", flush=True)
            time.sleep(1)
        print(f"\r{' '*40}\r", end="")

print(f"\n  {Fore.GREEN}✓  Phase 2 complete — {5} medium-tier events sent.\n")
time.sleep(1.0)


# ═════════════════════════════════════════════════════════════════════════════
#   PHASE 3  —  Botnet Credential Flood  (expected: HIGH tier)
# ═════════════════════════════════════════════════════════════════════════════

print(f"{Fore.RED}{'═'*65}")
print(f"{Fore.RED}  >>> PHASE 3: BOTNET CREDENTIAL FLOOD  (expected: HIGH) <<<")
print(f"{Fore.RED}{'═'*65}")
print(f"{Fore.WHITE}  Automated botnet unleashes full credential dump.")
print(f"{Fore.WHITE}  Mass parallel auth attempts. System under critical load.")
print(f"{Fore.WHITE}  EHR database targeted. Containment protocols activating...")
print(f"  Source IPs: {Fore.RED}fresh random IP per burst\n")
time.sleep(0.8)

for i in range(1, 6):
    ip   = _rand_ip()          # unique IP per burst — simulates botnet node
    user = random.choice(USERNAMES)
    fl   = random.randint(16, 22)
    cpu  = round(random.uniform(0.80, 0.97), 3)
    ehr  = random.randint(100, 190)
    exp  = random.randint(1500, 3000)
    lat  = random.randint(2, 4)
    rep  = round(random.uniform(0.01, 0.10), 3)
    mem  = 1

    print(f"  {Fore.WHITE}[{ts()}] {Fore.RED}FLOOD  {i}/5"
          f"  {Fore.WHITE}→  POST /auth/login"
          f"  {Back.RED}{Fore.WHITE}503 SERVICE UNAVAILABLE{Style.RESET_ALL}"
          f"  {Fore.RED}[{fl} fails/s]  src={ip}")
    print(f"           {Fore.RED}⚠  Memory spike detected  CPU={cpu*100:.0f}%"
          f"  Lateral-moves={lat}  Rep-score={rep}")

    eid = _inject(ip, "Phase3", fl, cpu, ehr, exp, lat, rep,
                  attack_type="brute_force", asset_type="ehr", memory_spike=mem)
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
