"""
Honey-data generator — synthetic patient records with embedded canary tokens.

Every decoy record contains a canary_token field.  If that token ever appears
in a data breach disclosure, threat-intel feed, or dark-web search, it proves:
  (a) the breach came from this specific SentiHealth deployment, and
  (b) the approximate timestamp of the exfiltration (canary minted at serve time).

All data is synthetic — no real patient information is used.
Names, DOBs, and record IDs are statistically realistic but entirely fictional.

Canary log: logs/canary_registry.jsonl
  Each issued canary is logged with timestamp, session_id, and endpoint.
  Periodically scan this log against threat-intel feeds (Phase 5+).
"""

from __future__ import annotations

import json
import logging
import os
import random
import secrets
import string
import time
from datetime import datetime, date, timedelta, timezone

logger = logging.getLogger(__name__)

_CANARY_LOG = os.path.join("logs", "canary_registry.jsonl")

# ---------------------------------------------------------------------------
# Synthetic name / data pools (no real PHI — purely fictional)
# ---------------------------------------------------------------------------

_FIRST_NAMES = [
    "Arjun", "Priya", "Ravi", "Sunita", "Vikram", "Meena", "Sanjay", "Lakshmi",
    "Rahul", "Kavya", "Amit", "Pooja", "Deepak", "Nisha", "Suresh", "Ananya",
]
_LAST_NAMES = [
    "Sharma", "Patel", "Gupta", "Singh", "Kumar", "Verma", "Joshi", "Mehta",
    "Reddy", "Iyer", "Nair", "Pillai", "Rao", "Bose", "Das", "Chatterjee",
]
_CONDITIONS = [
    "Hypertension", "Type 2 Diabetes", "Acute Appendicitis", "Fractured Femur",
    "Community-acquired Pneumonia", "Myocardial Infarction", "Asthma", "Dengue Fever",
]
_DEPARTMENTS = ["Emergency", "Cardiology", "Orthopedics", "Pulmonology", "General Medicine"]
_BLOOD_TYPES = ["A+", "A-", "B+", "B-", "O+", "O-", "AB+", "AB-"]


def _random_dob() -> str:
    age_days = random.randint(365 * 18, 365 * 85)
    dob = date.today() - timedelta(days=age_days)
    return dob.isoformat()


def _random_patient_id() -> str:
    return "DECOY-" + "".join(random.choices(string.ascii_uppercase + string.digits, k=8))


# ---------------------------------------------------------------------------
# Canary token management
# ---------------------------------------------------------------------------

def mint_canary(session_id: str, endpoint: str, canary_id: str = "") -> str:
    """
    Create and log a canary token.  Returns the canary string to embed in
    the decoy record.  Logs the issuance for later breach correlation.
    """
    if not canary_id:
        canary_id = f"canary_{secrets.token_hex(8)}"
    token = canary_id

    os.makedirs(os.path.dirname(_CANARY_LOG) or ".", exist_ok=True)
    entry = {
        "canary_id": token,
        "issued_at": datetime.now(timezone.utc).isoformat(),
        "session_id": session_id,
        "endpoint": endpoint,
    }
    with open(_CANARY_LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")

    logger.info(f"[HoneyData] Canary minted: {token} for session {session_id[:12]} @ {endpoint}")
    return token


def canary_triggered(token: str) -> bool:
    """
    Check if a canary has been seen in external intel (placeholder).
    In production, cross-reference with threat-intel APIs / OSINT feeds.
    """
    return False


# ---------------------------------------------------------------------------
# Decoy record generators
# ---------------------------------------------------------------------------

def generate_patient_record(canary_id: str = "", session_id: str = "") -> dict:
    """Return a single synthetic patient record with an embedded canary token."""
    first = random.choice(_FIRST_NAMES)
    last = random.choice(_LAST_NAMES)
    canary = canary_id or mint_canary(session_id, "/records/decoy")
    return {
        "id": _random_patient_id(),
        "name": f"{first} {last}",
        "dob": _random_dob(),
        "blood_type": random.choice(_BLOOD_TYPES),
        "department": random.choice(_DEPARTMENTS),
        "primary_condition": random.choice(_CONDITIONS),
        "admission_date": (date.today() - timedelta(days=random.randint(0, 30))).isoformat(),
        "attending_physician": f"Dr. {random.choice(_LAST_NAMES)}",
        "_canary": canary,
    }


def generate_patient_list(count: int = 10, canary_id: str = "", session_id: str = "") -> list[dict]:
    """Return a list of synthetic patients.  Each record carries the same canary."""
    canary = canary_id or mint_canary(session_id, "/patients/decoy")
    return [generate_patient_record(canary_id=canary, session_id=session_id) for _ in range(count)]


def generate_appointment_list(count: int = 5, canary_id: str = "", session_id: str = "") -> list[dict]:
    canary = canary_id or mint_canary(session_id, "/appointments/decoy")
    appointments = []
    for _ in range(count):
        dt = datetime.now(timezone.utc) + timedelta(days=random.randint(-7, 14))
        appointments.append({
            "id": "APT-" + secrets.token_hex(4).upper(),
            "patient": f"{random.choice(_FIRST_NAMES)} {random.choice(_LAST_NAMES)}",
            "doctor": f"Dr. {random.choice(_LAST_NAMES)}",
            "department": random.choice(_DEPARTMENTS),
            "datetime": dt.isoformat(),
            "reason": random.choice(_CONDITIONS),
            "_canary": canary,
        })
    return appointments
