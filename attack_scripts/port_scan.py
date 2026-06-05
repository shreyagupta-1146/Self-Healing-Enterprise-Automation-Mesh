import socket
import time
from datetime import datetime

print(f"[*] Starting Port Scan Simulator (localhost:3000-3100) - {datetime.now().isoformat()}")

target = "127.0.0.1"

for port in range(3000, 3101):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.05)
    result = sock.connect_ex((target, port))
    if result == 0:
        print(f"[{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Port {port} is OPEN")
    else:
        print(f"[{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] Port {port} is CLOSED")
    sock.close()
    
print(f"\n[*] Scan complete: {datetime.now().isoformat()}")
