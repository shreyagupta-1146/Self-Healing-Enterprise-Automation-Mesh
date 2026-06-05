"""
Mirage — Adaptive Deception Decision Engine.

Inserts a deception tier between detection and terminal lockdown.
Once a session is flagged with high confidence but BEFORE terminal block,
route it to a deception path that:
  1. Wastes attacker time/resources.
  2. Pollutes their stolen dataset (data poisoning of THEIR exfil).
  3. Embeds canary tokens — if a fake record surfaces later, breach is traced.
  4. Captures high-confidence labeled attack data for model retraining.

Non-negotiable patient-safety invariant (healthcare critical):
  A real clinician must NEVER receive fake medical data.
  In a Level 1 Trauma Center, wrong data can kill a patient.
  Mirage ALWAYS fails safe to real data when uncertain.
  The clinical_allowlist in config/deception_policy.json is consulted first;
  if any doubt exists, real data is served and the session is flagged only.

Legal guardrail:
  Deception stays inside owned systems only.
  No payload is EVER sent TO the attacker's machine.
  Defensive deception within your own infrastructure is legal (IT Act, CFAA).
  "Hacking back" is not — this boundary is enforced in decide().

Activation criteria (all must be true):
  - ML tier is Medium or High AND raw_score >= activation_threshold.
  - Session is NOT on the clinical_allowlist.
  - source_vlan is not "clinical" OR contradiction_flags are present
    (i.e. there's positive evidence this is NOT a real clinician).
  - deception_enabled == True in config/deception_policy.json.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Literal

logger = logging.getLogger(__name__)

_POLICY_PATH = os.path.join(os.path.dirname(__file__), "..", "config", "deception_policy.json")

DeceptionMode = Literal["none", "noise_only", "decoy", "full"]


@dataclass
class DeceptionVerdict:
    mode: DeceptionMode = "none"
    serve_decoy: bool = False
    apply_noise: bool = False
    apply_jitter: bool = False
    session_id: str = ""
    reason: str = ""
    canary_id: str = ""
    threat_tier: str = "Low"
    raw_score: float = 0.0
    logged_as_attack: bool = False


def _load_policy() -> dict:
    if not os.path.exists(_POLICY_PATH):
        return _default_policy()
    try:
        with open(_POLICY_PATH) as f:
            return json.load(f)
    except Exception as e:
        logger.warning(f"[Mirage] Could not load policy: {e}")
        return _default_policy()


def _default_policy() -> dict:
    return {
        "deception_enabled": True,
        "activation_threshold": 0.55,
        "full_decoy_threshold": 0.75,
        "clinical_allowlist": [],
        "safe_vlans": ["clinical"],
        "noise_epsilon": 2.0,
    }


# ---------------------------------------------------------------------------
# Main decision function
# ---------------------------------------------------------------------------

def decide(
    session_id: str,
    tier: str,
    raw_score: float,
    source_vlan: str = "unknown",
    user_id: str = "",
    context: dict | None = None,
    endpoint: str = "",
) -> DeceptionVerdict:
    """
    Decide the deception mode for an incoming request.

    Called by the webapp deception middleware for every request on a flagged
    session.  Returns immediately — never blocks.

    Patient-safety fail-safe:
      If the session is in the clinical_allowlist OR source_vlan == "clinical"
      AND there are no contradiction_flags, always return mode="none".
    """
    policy = _load_policy()
    verdict = DeceptionVerdict(
        session_id=session_id,
        threat_tier=tier,
        raw_score=raw_score,
    )

    if not policy.get("deception_enabled", True):
        verdict.reason = "deception_disabled_in_policy"
        return verdict

    # --- Patient-safety gate (most important check) ---
    allowlist: list[str] = policy.get("clinical_allowlist", [])
    contradiction_flags: list[str] = (context or {}).get("contradiction_flags", [])
    is_clinical_vlan = source_vlan in policy.get("safe_vlans", ["clinical"])

    if session_id in allowlist or user_id in allowlist:
        verdict.reason = "session_on_clinical_allowlist"
        return verdict

    if is_clinical_vlan and not contradiction_flags:
        # Looks like a real clinician on the clinical network — do not deceive.
        verdict.reason = "clinical_vlan_no_contradiction"
        return verdict

    # --- Activation threshold check ---
    threshold = float(policy.get("activation_threshold", 0.55))
    if tier == "Low" or raw_score < threshold:
        verdict.reason = f"below_threshold ({raw_score:.3f} < {threshold})"
        return verdict

    # --- Decide deception level ---
    full_threshold = float(policy.get("full_decoy_threshold", 0.75))

    if raw_score >= full_threshold:
        verdict.mode = "full"
        verdict.serve_decoy = True
        verdict.apply_noise = True
        verdict.apply_jitter = True
    elif raw_score >= threshold:
        verdict.mode = "noise_only"
        verdict.serve_decoy = False
        verdict.apply_noise = True
        verdict.apply_jitter = True

    # Assign canary ID for tracking (used by honey_data to embed in records)
    if verdict.serve_decoy:
        import secrets
        verdict.canary_id = f"canary_{secrets.token_hex(8)}"

    verdict.logged_as_attack = True
    verdict.reason = (
        f"tier={tier} score={raw_score:.3f} vlan={source_vlan} "
        f"contradictions={contradiction_flags}"
    )
    logger.info(
        f"[Mirage] session={session_id[:12]} mode={verdict.mode} "
        f"canary={verdict.canary_id or 'none'} reason={verdict.reason}"
    )
    return verdict
