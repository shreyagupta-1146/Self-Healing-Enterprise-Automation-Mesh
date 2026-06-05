import requests
import time
from datetime import datetime

print(f"[*] Starting Brute Force Simulator - {datetime.now().isoformat()}")

import traceback
import sys

def burst(count, idx):
    for i in range(count):
        try:
            resp = requests.post("http://localhost:3000/login", json={"username": "admin", "password": f"pass{i}", "source_ip": "10.0.0.47" if idx == 0 else ("10.0.0.83" if idx == 1 else ("10.0.0.47" if i % 2 == 0 else "10.0.0.83"))}, timeout=2)
            print(f"[{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Attempt {i+1}/{count} -> Status: {resp.status_code}")
        except requests.exceptions.ConnectionError:
            pass
        except requests.exceptions.Timeout:
            pass
        except Exception as e:
            traceback.print_exc()
            sys.exit(1)
        time.sleep(5)

phases = [
    "Phase 1: Low-level brute force",
    "Phase 2: Medium-level brute force",
    "Phase 3: High-level brute force"
]

for idx, phase in enumerate(phases):
    print(f"\n>>> {phase} <<<")
    burst(5, idx)
    
    if idx < len(phases) - 1:
        print("\n[!] Transitioning to next phase...")
        for c in [3, 2, 1]:
            print(f"    {c}...")
            time.sleep(1)

print(f"\n[*] End timestamp: {datetime.now().isoformat()}")
