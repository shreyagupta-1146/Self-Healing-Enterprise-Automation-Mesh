"""
Context Fusion — Phase 2.5
===========================
Clinician-aware risk modulation for the SentiHealth scoring engine.

build_context():  Given a user_id, source_ip and VLAN, return a context dict
                  containing on-shift status, recent badge-entry, active emergency,
                  and proxy registration.  Data is loaded from config files when
                  present; otherwise safe defaults are returned.

apply_context_modifier(): Modulate a raw risk score up or down based on the
                  context dict.  Rules:
                    • Legitimate context (on_shift AND badge_entry_recent)
                      → multiply score by 0.60  (suppress false positive)
                    • Emergency active OR proxy registered
                      → multiply score by 0.75  (partial suppression)
                    • Contradictory context (on-roster but no badge + external VLAN)
                      → multiply score by 1.30  (internal-attacker escalation)
                    • No context / unknown → score unchanged

The context dict schema (all keys optional, all default to False/None):
  on_shift            : bool  — user is currently on their scheduled shift
  badge_entry_recent  : bool  — physical badge entry in the last 15 min
  emergency_active    : bool  — patient emergency active in the system
  proxy_registered    : bool  — the source IP is a registered clinical proxy
  external_vlan       : bool  — source IP is on an external / guest VLAN
  vlan                : str   — raw VLAN tag
  source_ip           : str   — source IP that was checked
  user_id             : str   — user identifier (pseudonymized before logging)
"""

from __future__ import annotations

import json
import os
import time
from typing import Any

# ---------------------------------------------------------------------------
# Roster / badge / proxy data paths (all optional — graceful fallback)
# ---------------------------------------------------------------------------

_BASE = os.path.dirname(os.path.abspath(__file__))
_ROSTER_PATH    = os.path.join(_BASE, 'config', 'staff_roster.json')
_BADGE_PATH     = os.path.join(_BASE, 'config', 'badge_events.json')
_PROXY_PATH     = os.path.join(_BASE, 'config', 'registered_proxies.json')
_EMERGENCY_PATH = os.path.join(_BASE, 'config', 'active_emergencies.json')

# Internal VLAN prefixes — anything else is treated as external
_INTERNAL_VLAN_PREFIXES = ('10.', '172.16.', '172.17.', '172.18.', '172.19.',
                           '172.20.', '172.21.', '172.22.', '172.23.', '172.24.',
                           '172.25.', '172.26.', '172.27.', '172.28.', '172.29.',
                           '172.30.', '172.31.', '192.168.', 'vlan_internal')


def _load_json(path: str) -> Any:
    try:
        if os.path.exists(path):
            with open(path, 'r') as f:
                return json.load(f)
    except Exception:
        pass
    return None


def _is_on_shift(user_id: str) -> bool:
    """Check staff_roster.json for active shift.  Roster format:
      [ {"user_id": "dr_sharma", "shift_start": "08:00", "shift_end": "20:00"}, ... ]
    """
    roster = _load_json(_ROSTER_PATH)
    if not roster:
        return False
    now_hour = time.localtime().tm_hour
    now_min  = time.localtime().tm_min
    now_mins = now_hour * 60 + now_min
    for entry in roster:
        if entry.get('user_id') != user_id:
            continue
        try:
            sh, sm = [int(x) for x in entry['shift_start'].split(':')]
            eh, em = [int(x) for x in entry['shift_end'].split(':')]
            start_mins = sh * 60 + sm
            end_mins   = eh * 60 + em
            if start_mins <= now_mins <= end_mins:
                return True
        except Exception:
            pass
    return False


def _badge_entry_recent(user_id: str, window_sec: int = 900) -> bool:
    """Check badge_events.json for a recent entry.  Format:
      [ {"user_id": "dr_sharma", "timestamp": 1749123456}, ... ]
    """
    events = _load_json(_BADGE_PATH)
    if not events:
        return False
    cutoff = time.time() - window_sec
    for ev in events:
        if ev.get('user_id') == user_id and float(ev.get('timestamp', 0)) >= cutoff:
            return True
    return False


def _proxy_registered(source_ip: str) -> bool:
    """Check if this IP is a known clinical proxy.  Format:
      [ "10.0.5.21", "192.168.100.3", ... ]
    """
    proxies = _load_json(_PROXY_PATH)
    if not proxies:
        return False
    return source_ip in proxies


def _emergency_active() -> bool:
    """Return True if any patient emergency is currently active.  Format:
      { "active": true, "case_id": "ER-2026-0042" }
    """
    data = _load_json(_EMERGENCY_PATH)
    if not data:
        return False
    return bool(data.get('active', False))


def _is_external_vlan(source_ip: str, vlan: str) -> bool:
    """Return True if the source appears to be on an external network."""
    if vlan and any(vlan.startswith(p) for p in _INTERNAL_VLAN_PREFIXES):
        return False
    if source_ip and any(source_ip.startswith(p) for p in ('10.', '172.', '192.168.')):
        return False
    return True


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_context(user_id: str, source_ip: str = '', vlan: str = 'unknown') -> dict:
    """Build and return a context dict for the given user + source.

    Returns a dict with the keys documented in the module docstring.
    All lookups are best-effort; failures silently return False defaults.
    """
    ctx: dict[str, Any] = {
        'user_id':           user_id,
        'source_ip':         source_ip,
        'vlan':              vlan,
        'on_shift':          False,
        'badge_entry_recent': False,
        'emergency_active':  False,
        'proxy_registered':  False,
        'external_vlan':     False,
    }
    try:
        ctx['on_shift']           = _is_on_shift(user_id)
        ctx['badge_entry_recent'] = _badge_entry_recent(user_id)
        ctx['proxy_registered']   = _proxy_registered(source_ip)
        ctx['emergency_active']   = _emergency_active()
        ctx['external_vlan']      = _is_external_vlan(source_ip, vlan)
    except Exception:
        pass
    return ctx


def apply_context_modifier(raw_score: float, context: dict | None) -> float:
    """Modulate raw_score using clinical context.

    See module docstring for the full rule table.
    Returns a float in [0.01, 0.99].
    """
    if context is None:
        return raw_score

    on_shift   = context.get('on_shift', False)
    badge      = context.get('badge_entry_recent', False)
    emergency  = context.get('emergency_active', False)
    proxy      = context.get('proxy_registered', False)
    external   = context.get('external_vlan', False)

    multiplier = 1.0

    if on_shift and badge:
        # Legitimate clinical access — suppress false positive
        multiplier = 0.60
    elif emergency or proxy:
        # Partial legitimate justification
        multiplier = 0.75
    elif on_shift and not badge and external:
        # On-roster but accessing from outside without badge — suspicious
        multiplier = 1.30

    return float(max(0.01, min(0.99, raw_score * multiplier)))
