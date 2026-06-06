"""
Mirage Feedback Loop — closes the deception → clean labels → model retraining cycle.

Any session that interacted with honey-data is attack traffic by definition.
This produces the cleanest possible labeled training data without any
human ambiguity — the deception environment IS the labeling oracle.

How it works:
  1. live_sentinel.py writes flagged sessions to logs/mirage_sessions.json.
  2. flush_mirage_labels() is called periodically (on sentinel shutdown or
     after a configurable interval) and converts every 'full' deception
     session into a confirmed attack entry in retraining/retraining_queue.json.
  3. The poisoning quarantine in review_queue.py / model_trainer.py checks
     these entries before training.

The entries are marked human_confirmed=True because the ground truth is
certain — any request that received decoy data was, by definition, an attack.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone

import sys as _sys
_HERE = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_HERE)
if _PROJECT_ROOT not in _sys.path:
    _sys.path.insert(0, _PROJECT_ROOT)
from _paths import MIRAGE_SESSIONS as _MIRAGE_SESSIONS_PATH, RETRAINING_QUEUE as _RETRAINING_QUEUE_PATH, RETRAINING_DIR

logger = logging.getLogger(__name__)


def flush_mirage_labels():
    """
    Convert all active 'full' deception sessions into confirmed attack labels
    and append them to the retraining queue.

    Called on sentinel shutdown (atexit) and after each high-tier incident is
    resolved, so the model sees the freshest attack signals promptly.
    """
    if not os.path.exists(_MIRAGE_SESSIONS_PATH):
        return

    try:
        with open(_MIRAGE_SESSIONS_PATH) as f:
            sessions: dict = json.load(f)
    except Exception as e:
        logger.error(f"[Feedback] Could not read mirage sessions: {e}")
        return

    os.makedirs(RETRAINING_DIR, exist_ok=True)
    queue: list[dict] = []
    if os.path.exists(_RETRAINING_QUEUE_PATH):
        try:
            with open(_RETRAINING_QUEUE_PATH) as f:
                queue = json.load(f)
        except Exception:
            queue = []

    existing_ids = {e.get("incident_id") for e in queue}
    added = 0

    for session_id, entry in sessions.items():
        if entry.get("mode") != "full":
            continue
        incident_id = f"mirage_{session_id}"
        if incident_id in existing_ids:
            continue
        queue.append({
            "incident_id": incident_id,
            "timestamp": entry.get("flagged_at", datetime.now(timezone.utc).isoformat()),
            "tier": entry.get("tier", "High"),
            "top_3_features": entry.get("top_features", []),
            "plain_english_explanation": (
                f"Mirage-confirmed attack. Session {session_id[:12]} "
                f"served decoy data (canary: {entry.get('canary_id', 'n/a')}). "
                f"Score: {entry.get('score', 0):.3f}."
            ),
            "human_confirmed": True,
            "source": "mirage_oracle",
            "canary_id": entry.get("canary_id", ""),
            "resolved_at": datetime.now(timezone.utc).isoformat(),
        })
        existing_ids.add(incident_id)
        added += 1

    if added:
        with open(_RETRAINING_QUEUE_PATH, "w") as f:
            json.dump(queue, f, indent=2)
        logger.info(f"[Feedback] Flushed {added} Mirage-confirmed attack label(s) to retraining queue")


def record_flagged_session(
    session_id: str,
    tier: str,
    score: float,
    mode: str,
    canary_id: str = "",
    top_features: list | None = None,
):
    """
    Write or update a session's Mirage status to logs/mirage_sessions.json.
    Called by live_sentinel.py whenever a session verdict is issued.
    """
    os.makedirs(os.path.dirname(_MIRAGE_SESSIONS_PATH), exist_ok=True)
    sessions: dict = {}
    if os.path.exists(_MIRAGE_SESSIONS_PATH):
        try:
            with open(_MIRAGE_SESSIONS_PATH) as f:
                sessions = json.load(f)
        except Exception:
            sessions = {}

    sessions[session_id] = {
        "tier": tier,
        "score": score,
        "mode": mode,
        "canary_id": canary_id,
        "top_features": top_features or [],
        "flagged_at": datetime.now(timezone.utc).isoformat(),
    }

    with open(_MIRAGE_SESSIONS_PATH, "w") as f:
        json.dump(sessions, f, indent=2)
