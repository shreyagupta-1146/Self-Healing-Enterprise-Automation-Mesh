"""
SentinelNotifier — SentiHealth Secure Alert & Authorization (SSHA).

Self-hosted, zero-cloud replacement for Telegram/Aegis.

Delivery path (all on-prem):
  1. Server console  — always printed; physical-access out-of-band channel.
  2. logs/alert_queue.jsonl — persistent alert log; admin dashboard reads this.
  3. logs/ssha_challenges.json — FILE-BASED challenge registry shared between
     the live_sentinel process and the dashboard process.  The sentinel writes
     a challenge; the dashboard HTTP endpoint writes the admin's decision;
     the sentinel polls the file.  No threading.Event across processes.

Security properties:
  - Zero external cloud dependency — no Telegram, no SMTP, no SIP.
  - OTP and alert content never leave the hospital's own infrastructure.
  - Authorization challenges require an authenticated admin session.
  - Timeout is fail-safe: TIMEOUT counts as denial; no auto-approve on silence.
  - All alert events are written to the log for the audit chain.

Cross-process IPC:
  The sentinel and dashboard run as separate OS processes.  threading.Event is
  useless across process boundaries.  The shared file
  logs/ssha_challenges.json acts as a simple key-value store:
    { <incident_id>: { "decision": null | "YES" | "IGNORE" | ...,
                       "timestamp": ISO8601,
                       "prompt": str,
                       "status": "pending" | "resolved" | "expired" } }
  Writes are atomic (tmp-file + os.replace) so partial reads never corrupt it.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import secrets
import threading
import time
from datetime import datetime, timezone

# Ensure project root is on sys.path so _paths can be imported from any working directory.
_HERE = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_HERE)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from _paths import ALERT_QUEUE as _ALERT_LOG, CHALLENGES_FILE as _CHALLENGES_FILE, LOGS_DIR

from .base import Notifier

logger = logging.getLogger(__name__)

_CHALLENGES_LOCK = threading.Lock()   # serialises writes from within one process


# ---------------------------------------------------------------------------
# File-based challenge registry helpers
# ---------------------------------------------------------------------------

def _read_challenges() -> dict:
    """Read challenges file; return empty dict on missing / corrupt."""
    try:
        if os.path.exists(_CHALLENGES_FILE):
            with open(_CHALLENGES_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    return {}


def _write_challenges(data: dict) -> None:
    """Write challenges file atomically."""
    os.makedirs(LOGS_DIR, exist_ok=True)
    tmp = _CHALLENGES_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, _CHALLENGES_FILE)


# ---------------------------------------------------------------------------
# Public IPC API (called by dashboard.py)
# ---------------------------------------------------------------------------

def resolve_challenge(incident_id: str, decision: str, allow_expired: bool = False) -> bool:
    """
    Called by dashboard.py when an authenticated admin POSTs a decision.
    Writes the decision to the shared file so the sentinel process sees it.

    Set allow_expired=True to also resolve stasis (expired/timed-out) challenges
    retroactively — e.g. to generate forensics after auto-lockdown.

    Returns True if the challenge was found (pending or expired), False if unknown/stale.
    """
    with _CHALLENGES_LOCK:
        data = _read_challenges()
        ch = data.get(incident_id)
        if ch is None:
            return False
        status = ch.get("status")
        if status == "pending":
            pass  # always resolvable
        elif status == "expired" and allow_expired:
            pass  # retroactive resolution allowed
        else:
            return False
        ch["decision"] = decision.upper()
        ch["status"] = "resolved" if status == "pending" else "retroactive"
        ch["resolved_at"] = datetime.now(timezone.utc).isoformat()
        data[incident_id] = ch
        _write_challenges(data)
    return True


def list_pending() -> list[dict]:
    """Return summary of all unresolved authorization challenges for the admin panel."""
    data = _read_challenges()
    result = []
    for iid, ch in data.items():
        if ch.get("status") == "pending":
            result.append({
                "incident_id": iid,
                "timestamp": ch.get("timestamp", ""),
                "prompt_summary": (ch.get("prompt") or ""),
                "resolved": False,
                "timeout_sec": ch.get("timeout_sec", 90),
                "metadata": ch.get("metadata", {}),
            })
    return result


def list_stasis() -> list[dict]:
    """
    Return all expired/auto-locked challenges the admin can act on retroactively.
    Enriches each entry with IP, tier, score, and whether the IP is still blocked,
    falling back to threat_log timestamp-matching when challenge metadata is absent.
    """
    from _paths import THREAT_LOG, BLOCKED_IPS

    # ── currently blocked IPs ──────────────────────────────────────────────
    blocked_ips: set[str] = set()
    try:
        if os.path.exists(BLOCKED_IPS):
            with open(BLOCKED_IPS, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        entry = json.loads(line)
                        ip = entry.get("ip", "")
                        if ip:
                            blocked_ips.add(ip)
    except Exception:
        pass

    # ── auto-locked threat_log entries indexed by timestamp prefix ─────────
    # Key = first 16 chars of ISO timestamp (e.g. "2026-06-05T20:12")
    auto_locked_by_ts: dict[str, dict] = {}
    try:
        if os.path.exists(THREAT_LOG):
            with open(THREAT_LOG, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    entry = json.loads(line)
                    if entry.get("action") == "auto-locked":
                        ts_key = entry.get("timestamp", "")[:16]
                        if ts_key:
                            auto_locked_by_ts[ts_key] = entry
    except Exception:
        pass

    data = _read_challenges()
    result = []
    for iid, ch in data.items():
        if ch.get("status") != "expired":
            continue
        meta = ch.get("metadata") or {}
        ip    = meta.get("ip", "")
        tier  = meta.get("tier", "High")
        score = meta.get("score")
        reason = meta.get("reason", "")

        # Fallback: find matching auto-locked entry by timestamp proximity
        if not ip:
            ch_ts_key = ch.get("timestamp", "")[:16]
            fallback = auto_locked_by_ts.get(ch_ts_key)
            if fallback:
                ip    = fallback.get("ip", "")
                tier  = fallback.get("tier", tier)
                if fallback.get("raw_score") is not None:
                    score = fallback.get("raw_score")

        result.append({
            "incident_id":       iid,
            "timestamp":         ch.get("timestamp", ""),
            "prompt_summary":    ch.get("prompt") or "",
            "timeout_sec":       ch.get("timeout_sec", 90),
            "auto_locked_at":    ch.get("resolved_at", ""),
            "ip":                ip,
            "tier":              tier,
            "score":             score,
            "reason":            reason,
            "is_currently_blocked": ip in blocked_ips if ip else False,
            "metadata":          meta,
        })

    result.sort(key=lambda x: x["timestamp"], reverse=True)
    return result


# ---------------------------------------------------------------------------
# SentinelNotifier
# ---------------------------------------------------------------------------

class SentinelNotifier(Notifier):
    """
    SSHA Notifier — delivers alerts to the authenticated admin dashboard.

    Drop-in replacement for TelegramNotifier.  Same Notifier interface,
    zero external dependencies.
    """

    def __init__(self, cfg: dict | None = None):
        self._cfg = cfg or {}

    # -----------------------------------------------------------------------
    # Notifier interface — send_alert
    # -----------------------------------------------------------------------

    def send_alert(self, message: str, photo_path: str = None) -> bool:
        incident_id = secrets.token_hex(8)
        timestamp = datetime.now(timezone.utc).isoformat()

        entry = {
            "incident_id": incident_id,
            "timestamp": timestamp,
            "type": "alert",
            "summary": message[:200],
            "has_attachment": bool(photo_path),
        }

        _console_print("ALERT", incident_id, message)
        _write_log(_ALERT_LOG, entry)
        return True

    # -----------------------------------------------------------------------
    # Notifier interface — request_authorization
    # -----------------------------------------------------------------------

    def request_authorization(
        self,
        prompt: str | None,
        timeout_sec: int = 90,
        accept_ignore: bool = False,
        metadata: dict | None = None,
    ) -> str:
        incident_id = secrets.token_hex(8)
        timestamp = datetime.now(timezone.utc).isoformat()

        # Register challenge in the shared file (visible to dashboard process)
        with _CHALLENGES_LOCK:
            data = _read_challenges()
            data[incident_id] = {
                "status": "pending",
                "decision": None,
                "timestamp": timestamp,
                "prompt": (prompt or "High-tier threat — Admin decision required.")[:300],
                "timeout_sec": timeout_sec,
                "metadata": metadata or {},
            }
            _write_challenges(data)

        # Log the authorization request
        _write_log(_ALERT_LOG, {
            "incident_id": incident_id,
            "timestamp": timestamp,
            "type": "authorization_challenge",
            "summary": (prompt or "High-tier threat — Admin decision required.")[:200],
            "timeout_sec": timeout_sec,
            "status": "pending",
        })

        # Console notice (out-of-band, on-prem)
        _console_print(
            "AUTH REQUIRED",
            incident_id,
            prompt or "High-tier threat — Admin decision required.",
            extra=(
                f"  Dashboard: POST /api/alerts/{incident_id}/respond "
                '{"decision":"YES"}   to approve\n'
                f"  Waiting up to {timeout_sec}s for admin response...",
            ),
        )

        # Poll the shared file for the admin's decision
        deadline = time.time() + float(timeout_sec)
        decision = None
        while time.time() < deadline:
            time.sleep(0.5)
            try:
                data = _read_challenges()
                ch = data.get(incident_id, {})
                if ch.get("status") == "resolved" and ch.get("decision"):
                    decision = ch["decision"]
                    break
            except Exception:
                pass

        # Final cleanup — mark expired if no decision
        with _CHALLENGES_LOCK:
            data = _read_challenges()
            if incident_id in data:
                if not decision:
                    data[incident_id]["status"] = "expired"
                    data[incident_id]["decision"] = "TIMEOUT"
                    _write_challenges(data)

        if not decision:
            decision = "TIMEOUT"

        # Resolution log
        _write_log(_ALERT_LOG, {
            "incident_id": incident_id,
            "type": "authorization_resolution",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "decision": decision,
        })

        _console_print("AUTH RESOLVED", incident_id, f"Decision: {decision}")
        logger.info("[SSHA] Authorization resolved: %s -> %s", incident_id[:8], decision)
        return decision

    def send_summary(self, message: str) -> bool:
        return self.send_alert(message)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _console_print(tag: str, incident_id: str, message: str, extra=None) -> None:
    ts = datetime.now(timezone.utc).isoformat()[:19] + "Z"
    print(f"\n[SSHA {tag}] {ts} | ID:{incident_id[:8]}", flush=True)
    print(f"  {message}", flush=True)
    if extra:
        if isinstance(extra, (list, tuple)):
            for line in extra:
                print(f"  {line}", flush=True)
        else:
            print(f"  {extra}", flush=True)
    print(flush=True)


def _write_log(path: str, entry: dict) -> None:
    try:
        os.makedirs(os.path.dirname(path) or LOGS_DIR, exist_ok=True)
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception as e:
        logger.warning("[SSHA] Could not write to %s: %s", path, e)
