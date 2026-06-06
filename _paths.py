"""
_paths.py — single source of truth for all file-system paths in this project.

Every Python module imports from here instead of hardcoding relative strings.
This means scripts work correctly regardless of the current working directory
the user happens to be in when they launch them.

Usage
-----
    from _paths import PROJECT_ROOT, THREAT_LOG, LOGS_DIR, p

    # build an ad-hoc path:
    my_file = p("config", "custom.json")
"""

import os

# Absolute project root — the directory that contains THIS file.
PROJECT_ROOT: str = os.path.dirname(os.path.abspath(__file__))


def p(*parts: str) -> str:
    """Join *parts relative to PROJECT_ROOT and return an absolute path."""
    return os.path.join(PROJECT_ROOT, *parts)


# ---------------------------------------------------------------------------
# Well-known directories
# ---------------------------------------------------------------------------
LOGS_DIR        = p("logs")
DATA_DIR        = p("data")
CONFIG_DIR      = p("config")
MODELS_DIR      = p("models")
RETRAINING_DIR  = p("retraining")

# ---------------------------------------------------------------------------
# Log files
# ---------------------------------------------------------------------------
THREAT_LOG       = p("logs", "threat_log.json")
EVENTS_LOG       = p("logs", "events.jsonl")
BLOCKED_IPS      = p("logs", "blocked_ips.json")
LOCKED_ACCOUNTS  = p("logs", "locked_accounts.json")
NETWORK_ACTIONS  = p("logs", "network_actions.log")
INTEGRITY_ALERTS = p("logs", "integrity_alerts.log")
TAMPER_ALERTS    = p("logs", "tamper_alerts.log")
ALERT_QUEUE      = p("logs", "alert_queue.jsonl")
CHALLENGES_FILE  = p("logs", "ssha_challenges.json")
CANARY_LOG       = p("logs", "canary_registry.jsonl")
MIRAGE_SESSIONS  = p("logs", "mirage_sessions.json")

# ---------------------------------------------------------------------------
# Data files
# ---------------------------------------------------------------------------
AUDIT_CHAIN      = p("data", "audit_chain.json")
APP_DB           = p("data", "app.db")
SNAPSHOTS_DIR    = p("data", "snapshots")

# ---------------------------------------------------------------------------
# Config files
# ---------------------------------------------------------------------------
THRESHOLDS_FILE  = p("config", "thresholds.json")
CHAIN_KEY_FILE   = p("config", ".chain_key")

# ---------------------------------------------------------------------------
# Model files
# ---------------------------------------------------------------------------
MODEL_MANIFEST   = p("models", "model_manifest.json")

# ---------------------------------------------------------------------------
# Retraining
# ---------------------------------------------------------------------------
RETRAINING_QUEUE = p("retraining", "retraining_queue.json")

# ---------------------------------------------------------------------------
# Users DB (dashboard auth)
# ---------------------------------------------------------------------------
USERS_FILE       = p("data", "users.json")
