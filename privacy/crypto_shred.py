"""
Crypto-shredding — the answer to "right to erasure vs. immutable hash chain."

Problem:
  DPDP Act 2023, GDPR Art 17, and potentially HIPAA all include some form of
  erasure or correction rights.  Our audit_chain.json is a hash-chained ledger
  that CANNOT have entries deleted without breaking the chain.  A naive erasure
  would destroy forensic integrity.

Solution (crypto-shredding):
  - PHI-containing fields (e.g. the real user_id, patient name) are stored
    ONLY in the form of encrypted ciphertext appended to log entries, using a
    per-subject AES-256-GCM key held in config/shred_keystore.json.
  - The hash chain is computed over the *ciphertext* (or the pseudonymous token),
    never the plaintext — so the chain remains intact after erasure.
  - "Erasure" = delete the subject's key from the keystore.  The ciphertext in
    the chain becomes permanently unrecoverable, satisfying erasure rights, while
    the chain hash and the pseudonymous token remain for compliance audit.

Usage:
  # Store sensitive field when logging:
  ciphertext = encrypt_field(subject_id, plaintext_value)
  log_entry["user_display_name_enc"] = ciphertext.hex()

  # Retrieve (while key exists):
  plaintext = decrypt_field(subject_id, bytes.fromhex(log_entry["user_display_name_enc"]))

  # Erase subject (right to erasure):
  erase_subject(subject_id)
  # After this, decrypt_field raises KeyError — plaintext irrecoverable.

Compliance mapping:
  DPDP 2023 → right to erasure/correction of personal data.
  GDPR Art 17 → right to erasure ("right to be forgotten").
  HIPAA → limited erasure rights but PHI minimization still served.
  CERT-In log retention (180 days) → hash chain MUST be retained; only
    the plaintext field is shredded, not the audit record itself.
"""

import json
import logging
import os
import secrets

logger = logging.getLogger(__name__)

_KEYSTORE_PATH = os.path.join("config", "shred_keystore.json")

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    _CRYPTO_AVAILABLE = True
except ImportError:
    _CRYPTO_AVAILABLE = False
    logger.warning("[CryptoShred] cryptography not available — fields stored in plaintext")


# ---------------------------------------------------------------------------
# Keystore (maps subject_id → 32-byte AES key, hex-encoded)
# ---------------------------------------------------------------------------

def _load_keystore() -> dict:
    if not os.path.exists(_KEYSTORE_PATH):
        return {}
    try:
        with open(_KEYSTORE_PATH) as f:
            return json.load(f)
    except Exception:
        return {}


def _save_keystore(ks: dict):
    os.makedirs(os.path.dirname(_KEYSTORE_PATH) or ".", exist_ok=True)
    with open(_KEYSTORE_PATH, "w") as f:
        json.dump(ks, f, indent=2)


def _get_or_create_key(subject_id: str) -> bytes:
    ks = _load_keystore()
    if subject_id not in ks:
        ks[subject_id] = secrets.token_hex(32)
        _save_keystore(ks)
    return bytes.fromhex(ks[subject_id])


# ---------------------------------------------------------------------------
# Encrypt / Decrypt
# ---------------------------------------------------------------------------

def encrypt_field(subject_id: str, plaintext: str) -> bytes:
    """
    Encrypt plaintext for subject_id.
    Returns nonce(12) ‖ ciphertext bytes.
    If crypto unavailable, returns UTF-8 encoded plaintext (dev mode).
    """
    if not _CRYPTO_AVAILABLE:
        return plaintext.encode()
    key = _get_or_create_key(subject_id)
    nonce = secrets.token_bytes(12)
    aead = AESGCM(key)
    ciphertext = aead.encrypt(nonce, plaintext.encode(), subject_id.encode())
    return nonce + ciphertext


def decrypt_field(subject_id: str, ciphertext_bytes: bytes) -> str:
    """
    Decrypt a previously encrypted field.
    Raises KeyError if the subject has been erased (key destroyed).
    Raises ValueError on decryption failure (tampered ciphertext).
    """
    if not _CRYPTO_AVAILABLE:
        return ciphertext_bytes.decode()
    ks = _load_keystore()
    if subject_id not in ks:
        raise KeyError(f"Subject '{subject_id}' erased — plaintext irrecoverable")
    key = bytes.fromhex(ks[subject_id])
    nonce = ciphertext_bytes[:12]
    ct = ciphertext_bytes[12:]
    aead = AESGCM(key)
    try:
        return aead.decrypt(nonce, ct, subject_id.encode()).decode()
    except Exception as e:
        raise ValueError(f"Decryption failed for subject '{subject_id}': {e}") from e


# ---------------------------------------------------------------------------
# Erasure (right to erasure / right to be forgotten)
# ---------------------------------------------------------------------------

def erase_subject(subject_id: str) -> bool:
    """
    Destroy the encryption key for subject_id.
    After this call, all encrypted fields for this subject are permanently
    unrecoverable — the hash chain and pseudonymous tokens remain intact.
    Returns True if the key existed and was destroyed, False if not found.

    Compliance note (DPDP 2023 / GDPR Art 17 / CERT-In):
      The audit chain's structural integrity is preserved.  Only the
      plaintext of sensitive fields is lost.  The 180-day CERT-In log
      retention obligation is satisfied because the chain itself is retained.
    """
    ks = _load_keystore()
    if subject_id not in ks:
        logger.info(f"[CryptoShred] Subject '{subject_id}' not in keystore — nothing to erase")
        return False
    del ks[subject_id]
    _save_keystore(ks)
    logger.info(f"[CryptoShred] Key for subject '{subject_id}' destroyed — erasure complete")
    return True


def subject_exists(subject_id: str) -> bool:
    """Return True if the encryption key for subject_id is still present."""
    return subject_id in _load_keystore()


# ---------------------------------------------------------------------------
# Retention policy enforcement (CERT-In: 180 days)
# ---------------------------------------------------------------------------

def enforce_retention(log_path: str, max_days: int = 180):
    """
    Scan a JSONL log file and remove entries older than max_days.
    Retains the file structure; does NOT break the hash chain (chain entries
    are in audit_chain.json, not in the JSONL logs).

    Should be called periodically (e.g. nightly cron / sentinel restart).
    CERT-In Directions 2022: logs must be retained for at least 180 days.
    This function enforces the MAXIMUM, not the minimum — adjust max_days
    upward if your policy requires longer retention.
    """
    import time
    if not os.path.exists(log_path):
        return
    cutoff = time.time() - (max_days * 86400)
    kept = []
    removed = 0
    try:
        with open(log_path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    ts_str = obj.get("timestamp", "")
                    if ts_str:
                        from datetime import datetime, timezone
                        ts = datetime.fromisoformat(ts_str).timestamp()
                        if ts < cutoff:
                            removed += 1
                            continue
                except Exception:
                    pass
                kept.append(line)
        with open(log_path, "w") as f:
            f.write("\n".join(kept) + ("\n" if kept else ""))
        if removed:
            logger.info(f"[Retention] Removed {removed} entries older than {max_days}d from {log_path}")
    except Exception as e:
        logger.error(f"[Retention] Failed to enforce retention on {log_path}: {e}")
