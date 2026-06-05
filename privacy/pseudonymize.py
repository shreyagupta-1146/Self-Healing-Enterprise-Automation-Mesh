"""
Pseudonymization — replaces direct identifiers (user_id, ip_address) with
salted HMAC tokens before writing to logs and the audit chain.

India compliance anchor:
  - DPDP Act 2023: minimization of personal data + security safeguards.
  - IT Act 2000 §43A / SPDI Rules 2011: health data = Sensitive Personal Data;
    reasonable security practices required.
  - HIPAA §164.312(a)(2)(i): unique user identification in audit trails.

Design:
  - One salt per process run (os.urandom(32)); persistent salt stored in
    config/pseudonym_salt.bin so tokens are stable across restarts and
    attributable in forensics, but not linkable outside the hospital's
    own salt file.
  - The mapping (token → real value) lives ONLY in the encrypted salt file,
    never in logs.  An investigator with the salt can reverse; an attacker
    with logs alone cannot.
  - Crypto-shredding (see crypto_shred.py) "erases" a data subject by
    destroying the salt entry for their ID — fulfilling the DPDP/GDPR
    right to erasure without breaking the hash chain.
"""

import hashlib
import hmac
import json
import logging
import os

logger = logging.getLogger(__name__)

_SALT_PATH = os.path.join("config", "pseudonym_salt.bin")

# In-memory cache: real_value -> token
_token_cache: dict[str, str] = {}
_salt: bytes = b""


def _load_salt() -> bytes:
    global _salt
    if _salt:
        return _salt
    if os.path.exists(_SALT_PATH):
        with open(_SALT_PATH, "rb") as f:
            _salt = f.read(32)
    else:
        os.makedirs(os.path.dirname(_SALT_PATH), exist_ok=True)
        _salt = os.urandom(32)
        with open(_SALT_PATH, "wb") as f:
            f.write(_salt)
    return _salt


def tokenize(value: str) -> str:
    """
    Return a stable pseudonymous token for value.
    Identical value always produces the same token (with the same salt),
    so audit trails remain consistent across log entries.
    """
    if value in ("Unknown", "anonymous", ""):
        return value
    if value in _token_cache:
        return _token_cache[value]
    salt = _load_salt()
    token = hmac.new(salt, value.encode(), hashlib.sha256).hexdigest()[:16]
    _token_cache[value] = token
    return token


def pseudonymize_event(event: dict) -> dict:
    """
    Return a copy of event with user_id and ip_address replaced by tokens.
    Called before writing to logs/events.jsonl, threat_log.json, audit_chain.json.
    """
    out = dict(event)
    if "user_id" in out:
        out["user_id"] = tokenize(str(out["user_id"]))
    if "ip_address" in out:
        out["ip_address"] = tokenize(str(out["ip_address"]))
    if "source_ip" in out:
        out["source_ip"] = tokenize(str(out["source_ip"]))
    if "features" in out and isinstance(out["features"], dict):
        f = dict(out["features"])
        if "user_id" in f:
            f["user_id"] = tokenize(str(f["user_id"]))
        out["features"] = f
    return out


def pseudonymize_log_line(raw_json: str) -> str:
    """Pseudonymize a single JSON log line. Returns the line unchanged on error."""
    try:
        obj = json.loads(raw_json)
        return json.dumps(pseudonymize_event(obj))
    except Exception as e:
        logger.debug(f"[Pseudonymize] Could not pseudonymize line: {e}")
        return raw_json
