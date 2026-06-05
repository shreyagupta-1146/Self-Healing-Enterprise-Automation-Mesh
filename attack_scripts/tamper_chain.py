"""
TAMPER DEMO SCRIPT — SentiHealth Audit Chain (v2 with HMAC)
============================================================
Three attack demos, each detected by a different security layer:

  Attack 1 — Hash flip      → detected by Layer 2 (hash chain linkage)
  Attack 2 — HMAC injection → detected by Layer 3 (HMAC content signature)
  Attack 3 — Block deletion → detected by Layer 1 (block_index continuity)

Usage:
  python attack_scripts/tamper_chain.py --seed     # seed 5 signed blocks first
  python attack_scripts/tamper_chain.py            # Attack 1: hash flip
  python attack_scripts/tamper_chain.py --inject   # Attack 2: inject valid-hash block
  python attack_scripts/tamper_chain.py --delete   # Attack 3: delete a block
  python attack_scripts/tamper_chain.py --restore  # restore the original chain
"""

import json
import sys
import os
import shutil
import hashlib
import hmac as _hmac
import random
from datetime import datetime, timezone
from uuid import uuid4

CHAIN_PATH = "data/audit_chain.json"
BACKUP_PATH = "data/audit_chain_backup.json"


def _load_secret() -> bytes:
    secret_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config', '.chain_key')
    if os.path.exists(secret_path):
        with open(secret_path, 'rb') as f:
            return f.read()
    raise SystemExit("❌ config/.chain_key not found. Start live_sentinel.py once first to generate it.")


def _block_hmac(entry: dict, secret: bytes) -> str:
    payload = {k: v for k, v in entry.items() if k not in ('entry_hash', 'block_hmac')}
    return _hmac.new(secret, json.dumps(payload, sort_keys=True).encode(), hashlib.sha256).hexdigest()


def _write(chain):
    tmp = CHAIN_PATH + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(chain, f, indent=2)
    os.replace(tmp, CHAIN_PATH)


def _backup():
    shutil.copy2(CHAIN_PATH, BACKUP_PATH)
    print(f"✅ Backup saved to {BACKUP_PATH}")


def seed():
    """Add 5 properly signed blocks so attack demos work immediately."""
    if not os.path.exists(CHAIN_PATH):
        print("❌ audit_chain.json not found. Run: python attack_scripts/tamper_chain.py --seed after starting live_sentinel once.")
        return

    secret = _load_secret()

    with open(CHAIN_PATH, 'r') as f:
        chain = json.load(f)

    tiers   = ['Low', 'Medium', 'High']
    actions = [['audit_log'], ['account_locked', 'ip_blocked'], ['ip_blocked', 'bandwidth_throttled']]

    for i in range(5):
        tier_idx = i % 3
        tier = tiers[tier_idx]
        prev_hash = chain[-1]['entry_hash']

        entry = {
            "block_index":   len(chain),
            "event_id":      f"SEED-{uuid4().hex[:8].upper()}",
            "timestamp":     datetime.now(timezone.utc).isoformat(),
            "tier":          tier,
            "prev_hash":     prev_hash,
            "actions_taken": actions[tier_idx],
            "status":        "SEEDED",
        }
        entry_str          = json.dumps(entry, sort_keys=True)
        entry["entry_hash"] = hashlib.sha256((prev_hash + entry_str).encode()).hexdigest()
        entry["block_hmac"] = _block_hmac(entry, secret)
        chain.append(entry)

    _write(chain)
    print(f"✅ Seeded 5 signed blocks → chain now has {len(chain)} blocks")
    print(f"   Now run the attack demos:")
    print(f"     python attack_scripts/tamper_chain.py")
    print(f"     python attack_scripts/tamper_chain.py --inject")
    print(f"     python attack_scripts/tamper_chain.py --delete")


def tamper_hash():
    """Attack 1: Flip one character of the last block's entry_hash.
    Detected by: Layer 2 (SHA-256 hash chain linkage)."""
    if not os.path.exists(CHAIN_PATH):
        print("❌ audit_chain.json not found. Run --seed first.")
        return
    with open(CHAIN_PATH, 'r') as f:
        chain = json.load(f)
    if len(chain) < 2:
        print("❌ Chain too short. Run: python attack_scripts/tamper_chain.py --seed")
        return
    _backup()

    original_hash = chain[-1]["entry_hash"]
    tampered_hash = original_hash[:-1] + ("0" if original_hash[-1] != "0" else "1")
    chain[-1]["entry_hash"] = tampered_hash
    _write(chain)

    print(f"\n🔴 ATTACK 1 — HASH FLIP at {datetime.now().strftime('%H:%M:%S')}")
    print(f"   Block modified: #{len(chain)-1} (last entry)")
    print(f"   Original hash:  {original_hash[:40]}...")
    print(f"   Tampered hash:  {tampered_hash[:40]}...")
    print(f"\n⏳ Watchdog (Layer 2) will detect HASH CHAIN BROKEN within 8 seconds.")
    print(f"   Dashboard blockchain badge → COMPROMISED")
    print(f"\n💡 Restore with: python attack_scripts/tamper_chain.py --restore")


def tamper_inject():
    """Attack 2: Inject a fake block with a VALID SHA-256 hash (no HMAC key).
    Old system: UNDETECTED. New system: caught by Layer 3 (HMAC signature)."""
    if not os.path.exists(CHAIN_PATH):
        print("❌ audit_chain.json not found. Run --seed first.")
        return
    with open(CHAIN_PATH, 'r') as f:
        chain = json.load(f)
    if len(chain) < 2:
        print("❌ Chain too short. Run: python attack_scripts/tamper_chain.py --seed")
        return
    _backup()

    prev_hash = chain[-1]["entry_hash"]
    fake_entry = {
        "block_index":   len(chain),
        "event_id":      "FAKE-COVER-UP-001",
        "timestamp":     datetime.now(timezone.utc).isoformat(),
        "tier":          "Low",
        "prev_hash":     prev_hash,
        "actions_taken": ["audit_log"],
        "status":        "LOGGED",
    }
    # Attacker computes a valid SHA-256 hash — no HMAC key available
    entry_str = json.dumps(fake_entry, sort_keys=True)
    fake_entry["entry_hash"] = hashlib.sha256((prev_hash + entry_str).encode()).hexdigest()
    # block_hmac deliberately omitted — attacker doesn't have SESSION_SECRET

    chain.append(fake_entry)
    _write(chain)

    print(f"\n🟠 ATTACK 2 — CONTENT INJECTION at {datetime.now().strftime('%H:%M:%S')}")
    print(f"   Injected block #{len(chain)-1} with a VALID SHA-256 hash (no HMAC key).")
    print(f"   Old system: would show INTACT (hash is valid ✓).")
    print(f"   New system: HMAC is missing → detected as COMPROMISED.")
    print(f"\n⏳ Watchdog (Layer 3) will detect HMAC SIGNATURE INVALID within 8 seconds.")
    print(f"   Dashboard blockchain badge → COMPROMISED")
    print(f"\n💡 Restore with: python attack_scripts/tamper_chain.py --restore")


def tamper_delete():
    """Attack 3: Delete block #2 to erase an event from the record.
    Detected by: Layer 1 (block_index continuity gap)."""
    if not os.path.exists(CHAIN_PATH):
        print("❌ audit_chain.json not found. Run --seed first.")
        return
    with open(CHAIN_PATH, 'r') as f:
        chain = json.load(f)
    if len(chain) < 4:
        print("❌ Chain too short. Run: python attack_scripts/tamper_chain.py --seed")
        return
    _backup()

    deleted_block = chain.pop(2)
    _write(chain)

    print(f"\n🟡 ATTACK 3 — BLOCK DELETION at {datetime.now().strftime('%H:%M:%S')}")
    print(f"   Deleted block #2 (event_id: {deleted_block.get('event_id','?')})")
    print(f"   Block index now jumps: 1 → 3 (gap at position 2).")
    print(f"\n⏳ Watchdog (Layer 1) will detect BLOCK INDEX MISMATCH within 8 seconds.")
    print(f"   Dashboard blockchain badge → COMPROMISED")
    print(f"\n💡 Restore with: python attack_scripts/tamper_chain.py --restore")


def restore():
    if not os.path.exists(BACKUP_PATH):
        print("❌ No backup found. Nothing to restore.")
        return
    shutil.copy2(BACKUP_PATH, CHAIN_PATH)
    os.remove(BACKUP_PATH)
    print(f"✅ Chain restored from backup at {datetime.now().strftime('%H:%M:%S')}")
    print(f"   Dashboard will show INTACT within 5 seconds.")


if __name__ == "__main__":
    if "--restore" in sys.argv:
        restore()
    elif "--inject" in sys.argv:
        tamper_inject()
    elif "--delete" in sys.argv:
        tamper_delete()
    elif "--seed" in sys.argv:
        seed()
    else:
        tamper_hash()
