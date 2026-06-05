#!/usr/bin/env bash
# ============================================================
#  SentinelHealth — Pre-flight Reset & Startup Script
#  Run this ONCE before every demo session.
#  Usage:  cd ~/sentiHealth && bash reset_and_run.sh
# ============================================================

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

ok()   { echo -e "  ${GREEN}✅ $1${RESET}"; }
fail() { echo -e "  ${RED}❌ $1${RESET}"; PREFLIGHT_FAILED=1; }
warn() { echo -e "  ${YELLOW}⚠️  $1${RESET}"; }
info() { echo -e "  ${CYAN}ℹ️  $1${RESET}"; }

PREFLIGHT_FAILED=0

echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}║      🛡️  SENTINELHEALTH — DEMO RESET SCRIPT          ║${RESET}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════╝${RESET}"
echo ""

# ─────────────────────────────────────────────
# 🔑 DEMO CREDENTIALS (print first!)
# ─────────────────────────────────────────────
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${BOLD}  🔑  DEMO LOGIN CREDENTIALS${RESET}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""
echo -e "  ${BOLD}Admin ID    :${RESET}  ${GREEN}admin${RESET}  (or ANY non-empty text)"
echo -e "  ${BOLD}Security Key:${RESET}  ${GREEN}sentinel2026${RESET}  (or ANY non-empty text)"
echo -e "  ${BOLD}OTP Code    :${RESET}  ${GREEN}123456${RESET}  (if after-hours or new IP triggers it)"
echo ""
echo -e "  ${YELLOW}Note: Credentials always succeed. Risk engine decides if OTP is required.${RESET}"
echo -e "  ${YELLOW}OTP triggers when current hour < 8 or >= 20 (local time).${RESET}"
echo ""

# ─────────────────────────────────────────────
# 🔍 PRE-FLIGHT CHECKS
# ─────────────────────────────────────────────
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${BOLD}  🔍  PRE-FLIGHT CHECKS${RESET}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""

# Check Python 3.10+
PYTHON_BIN=".venv/bin/python3"
if [ ! -f "$PYTHON_BIN" ]; then
  PYTHON_BIN="python3"
fi
PY_VERSION=$($PYTHON_BIN --version 2>&1 | grep -oE '[0-9]+\.[0-9]+' | head -1)
PY_MAJOR=$(echo $PY_VERSION | cut -d. -f1)
PY_MINOR=$(echo $PY_VERSION | cut -d. -f2)
if [ "$PY_MAJOR" -ge 3 ] && [ "$PY_MINOR" -ge 10 ]; then
  ok "Python $PY_VERSION found"
else
  fail "Python 3.10+ required, found $PY_VERSION"
fi

# Check Node.js
if command -v node &>/dev/null; then
  NODE_VER=$(node --version)
  ok "Node.js $NODE_VER found"
else
  fail "Node.js not found — install from nodejs.org"
fi

# Check .env file
if [ -f ".env" ]; then
  ok ".env file exists"
  TELEGRAM_TOKEN=$(grep TELEGRAM_BOT_TOKEN .env | cut -d= -f2 | tr -d '"')
  TELEGRAM_CHAT=$(grep TELEGRAM_CHAT_ID .env | cut -d= -f2 | tr -d '"')
  if [ -n "$TELEGRAM_TOKEN" ] && [ "$TELEGRAM_TOKEN" != "YOUR_TELEGRAM_BOT_TOKEN" ]; then
    ok "TELEGRAM_BOT_TOKEN is set"
  else
    fail "TELEGRAM_BOT_TOKEN is missing or placeholder — Telegram alerts will fail"
  fi
  if [ -n "$TELEGRAM_CHAT" ] && [ "$TELEGRAM_CHAT" != "YOUR_TELEGRAM_CHAT_ID" ]; then
    ok "TELEGRAM_CHAT_ID is set"
  else
    fail "TELEGRAM_CHAT_ID is missing or placeholder — Telegram alerts will fail"
  fi
else
  fail ".env file not found — create it with TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID"
fi

# Check Python packages
$PYTHON_BIN -c "import flask, sklearn, shap, requests, colorama, dotenv" 2>/dev/null \
  && ok "Python packages (flask, sklearn, shap, requests, colorama, dotenv) installed" \
  || fail "Some Python packages missing — run: pip install -r requirements.txt"

# Check Node webapp dependencies
if [ -d "webapp/node_modules" ]; then
  ok "webapp/node_modules installed"
else
  warn "webapp/node_modules missing — installing now..."
  (cd webapp && npm install --silent) && ok "webapp npm install complete"
fi

# Check frontend dependencies
if [ -d "frontend/node_modules" ]; then
  ok "frontend/node_modules installed"
else
  warn "frontend/node_modules missing — installing now..."
  (cd frontend && npm install --silent) && ok "frontend npm install complete"
fi

# Check ML models
if ls models/*.pkl &>/dev/null 2>&1; then
  MODEL_COUNT=$(ls models/*.pkl | wc -l | tr -d ' ')
  ok "ML models found ($MODEL_COUNT .pkl files)"
else
  fail "No ML model files found in models/ — run: python3 model_trainer.py"
fi

# Stop if pre-flight failed
echo ""
if [ "$PREFLIGHT_FAILED" -eq 1 ]; then
  echo -e "${RED}${BOLD}  ❌ Pre-flight failed. Fix errors above before continuing.${RESET}"
  exit 1
fi
ok "All pre-flight checks passed!"

# ─────────────────────────────────────────────
# 🧹 RESET DATA
# ─────────────────────────────────────────────
echo ""
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${BOLD}  🧹  RESETTING DEMO DATA${RESET}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""

# Reset audit chain to clean genesis block
$PYTHON_BIN - << 'PYEOF'
import json, hashlib, datetime

genesis = {
    "entry_hash": hashlib.sha256(b"GENESIS").hexdigest(),
    "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "tier": "GENESIS",
    "prev_hash": "0" * 64,
    "actions_taken": ["system_initialized"],
    "status": "ACTIVE"
}
with open("data/audit_chain.json", "w") as f:
    json.dump([genesis], f, indent=2)
print("  ✅ Audit chain reset to clean genesis block")
PYEOF

# Clear log files (keep files, empty content)
echo -n "" > logs/events.jsonl
echo -n "" > logs/threat_log.json
echo -n "" > logs/blocked_ips.json
[ -f logs/tamper_alerts.log ] && echo -n "" > logs/tamper_alerts.log
ok "Log files cleared (events.jsonl, threat_log.json, blocked_ips.json)"

# ─────────────────────────────────────────────
# 🚀 STARTUP CHECKLIST
# ─────────────────────────────────────────────
echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}║        🚀  OPEN 5 TERMINALS — IN THIS ORDER          ║${RESET}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════╝${RESET}"
echo ""
echo -e "${BOLD}  TERMINAL 1 — Node.js EHR Webapp (generates traffic)${RESET}"
echo -e "  ${CYAN}cd ~/sentiHealth/webapp && node app.js${RESET}"
echo -e "  ${YELLOW}→ Wait for: 'SentiHealth EHR server running on port 3000'${RESET}"
echo ""
echo -e "${BOLD}  TERMINAL 2 — Python AI Watchdog (core detection engine)${RESET}"
echo -e "  ${CYAN}cd ~/sentiHealth && source .venv/bin/activate && export SENTIHEALTH_TEST_MODE=1 && python3 live_sentinel.py${RESET}"
echo -e "  ${YELLOW}→ Wait for: 'TELEGRAM CONNECTED. Waiting for live web traffic...'${RESET}"
echo ""
echo -e "${BOLD}  TERMINAL 3 — Flask API Dashboard (backend API)${RESET}"
echo -e "  ${CYAN}cd ~/sentiHealth && source .venv/bin/activate && python3 dashboard.py${RESET}"
echo -e "  ${YELLOW}→ Wait for: '[DASHBOARD] Running at http://localhost:5001'${RESET}"
echo ""
echo -e "${BOLD}  TERMINAL 4 — React Frontend (Lovable UI with login)${RESET}"
echo -e "  ${CYAN}cd ~/sentiHealth/frontend && npm install && npm run dev${RESET}"
echo -e "  ${YELLOW}→ Open: http://localhost:8000${RESET}"
echo ""
echo -e "${BOLD}  TERMINAL 5 — Attack Simulator (run during demo)${RESET}"
echo -e "  ${CYAN}cd ~/sentiHealth && source .venv/bin/activate && python3 attack_scripts/exfiltration.py${RESET}"
echo -e "  ${YELLOW}→ Run this LAST to trigger threat detection${RESET}"
echo ""
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${BOLD}  ✅ VERIFICATION CHECKLIST${RESET}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""
echo -e "  1. Terminal 2 shows NO 'INTEGRITY ALERT' spam"
echo -e "  2. http://localhost:8000 → Login page loads (dark theme)"
echo -e "  3. Login with any Admin ID + any Security Key → dashboard"
echo -e "  4. Browser DevTools Console → zero CORS errors"
echo -e "  5. Run exfiltration.py → threats appear in Terminal 2"
echo -e "  6. Telegram receives 🔴 CRITICAL ALERT with SHAP chart"
echo -e "  7. Reply YES in Telegram → dashboard shows RESOLVED"
echo ""
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${BOLD}  🔄 ROLLBACK (if anything breaks)${RESET}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""
echo -e "  Frontend broken  → unzip ~/sentiHealth/frontend_backup.zip"
echo -e "  Audit chain bad  → cp data/audit_chain_backup.json data/audit_chain.json"
echo -e "  npm errors       → cd frontend && rm -rf node_modules && npm install"
echo -e "  Python errors    → source .venv/bin/activate && pip install -r requirements.txt"
echo ""
echo -e "${GREEN}${BOLD}  🛡️  SentinelHealth is ready for demo. Good luck! 🚀${RESET}"
echo ""
