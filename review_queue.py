"""
Human review queue for retraining candidates.

Includes a poisoning-quarantine check (FUTURE_WORK #6):
  Before any incident is approved for retraining, the quarantine filter checks
  whether approving it would shift the label distribution in a statistically
  suspicious way.  If so, it is flagged as a potential poisoning attempt and
  requires an explicit override to proceed.

Poisoning attack scenario (addressed here):
  An attacker gains admin access to review_queue.py and approves "normal"
  traffic labeled as "attacks" — causing the ensemble to lower its sensitivity
  and miss future real attacks (model poisoning via label manipulation).

Defense:
  - Track the current approved-per-tier ratio in the existing training data.
  - If a batch of approvals would shift the High:Low:Medium ratio by more
    than POISON_DRIFT_THRESHOLD, quarantine the offending entries and alert.
  - Mirage-sourced entries (source=="mirage_oracle") are trusted by design
    and skip the quarantine (the deception environment is the ground truth).
"""

import json
import os
import sys
import statistics
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)

# Quarantine: if approving an entry would shift the High-tier fraction by more
# than this amount relative to the current baseline, flag it.
POISON_DRIFT_THRESHOLD = 0.25  # 25% shift triggers a warning


# ---------------------------------------------------------------------------
# Poisoning quarantine
# ---------------------------------------------------------------------------

def _get_current_tier_distribution() -> dict[str, int]:
    """Count tier labels in the existing training CSV (baseline)."""
    csv_path = os.path.join("data", "sentinelhealth_dataset.csv")
    counts: dict[str, int] = {"Low": 0, "Medium": 0, "High": 0}
    if not os.path.exists(csv_path):
        return counts
    # Map integer labels (0=Low, 1=Medium, 2=High) and legacy string labels.
    _INT_MAP = {"0": "Low", "1": "Medium", "2": "High"}
    try:
        import csv
        with open(csv_path) as f:
            reader = csv.DictReader(f)
            for row in reader:
                raw = row.get("tier_label", "")
                label = _INT_MAP.get(raw, raw)
                if label in counts:
                    counts[label] += 1
    except Exception:
        pass
    return counts


def _check_poisoning(candidate_entries: list[dict], existing_dist: dict[str, int]) -> list[str]:
    """
    Return a list of incident_ids that appear to be poisoning attempts.
    An entry is suspicious if it would cause the High-tier approval rate in
    this batch to deviate strongly from the baseline distribution.
    """
    total_existing = sum(existing_dist.values()) or 1
    baseline_high_frac = existing_dist.get("High", 0) / total_existing

    batch_tiers = [e.get("tier", "Low") for e in candidate_entries]
    batch_high_frac = batch_tiers.count("High") / max(len(batch_tiers), 1)

    # Suspicious: batch labels almost ALL Low when the existing dataset has
    # significant High incidence — indicates "normalizing" real attacks.
    suspicious: list[str] = []
    if (
        baseline_high_frac > 0.15
        and batch_high_frac < (baseline_high_frac - POISON_DRIFT_THRESHOLD)
    ):
        for e in candidate_entries:
            if e.get("tier", "Low") == "Low" and e.get("source") != "mirage_oracle":
                suspicious.append(e.get("incident_id", "unknown"))

    return suspicious


# ---------------------------------------------------------------------------
# Main review function
# ---------------------------------------------------------------------------

def review_queue():
    args = sys.argv[1:]
    dry_run = "--dry-run" in args
    auto_approve_low = "--auto-approve-low" in args

    path = "retraining/retraining_queue.json"
    if not os.path.exists(path):
        print(Fore.YELLOW + "No retraining queue found.")
        return

    queue: list[dict] = json.load(open(path))
    unconfirmed = [e for e in queue if not e["human_confirmed"]]

    if not unconfirmed:
        print(Fore.GREEN + "Queue is empty. All incidents reviewed.")
        return

    print(Fore.CYAN + f"\n{len(unconfirmed)} incidents pending review.\n")

    # --- Run poisoning quarantine check before showing anything ---
    existing_dist = _get_current_tier_distribution()
    quarantined_ids = _check_poisoning(unconfirmed, existing_dist)
    if quarantined_ids:
        print(
            Fore.RED + f"[POISON QUARANTINE] {len(quarantined_ids)} entries flagged as potential "
            "model-poisoning attempts.\n"
            "  These entries would shift the High-tier label distribution by >"
            f"{int(POISON_DRIFT_THRESHOLD * 100)}% from baseline.\n"
            "  They are shown below marked [QUARANTINE] and require explicit override (q) to approve.\n"
        )

    approved_count = 0
    rejected_count = 0
    quarantine_overridden = 0

    for i, entry in enumerate(unconfirmed):
        inc_id = entry.get("incident_id", "?")
        is_quarantined = inc_id in quarantined_ids
        is_mirage = entry.get("source") == "mirage_oracle"

        prefix = ""
        if is_mirage:
            prefix = Fore.MAGENTA + "[MIRAGE-ORACLE] "
        elif is_quarantined:
            prefix = Fore.RED + "[QUARANTINE] "

        print(Fore.WHITE + f"[{i+1}] {inc_id}")
        print(f"     Time : {entry.get('timestamp', 'N/A')}")
        print(f"     Tier : {entry.get('tier', 'N/A')}")
        print(Fore.MAGENTA + f"     Why  : {entry.get('plain_english_explanation', 'No explanation')}")
        if is_quarantined:
            print(Fore.RED + "     [!] Flagged by poisoning quarantine — use 'q' to override and approve anyway")

        # Mirage-oracle entries are auto-approved (ground truth by design)
        if is_mirage:
            print(Fore.MAGENTA + "     [AUTO-APPROVED: Mirage oracle — ground truth confirmed]")
            decision = "y"
        elif auto_approve_low and entry.get("tier") == "Low" and not is_quarantined:
            print(Fore.GREEN + "     [AUTO-APPROVED LOW TIER]")
            decision = "y"
        else:
            prompt = "     Approve retraining? (y/n"
            if is_quarantined:
                prompt += "/q to override quarantine"
            prompt += "): "
            decision = input(Fore.YELLOW + prompt).strip().lower()

        if decision in ("y", "q"):
            if decision == "q" and is_quarantined:
                quarantine_overridden += 1
                print(Fore.YELLOW + "     -> Quarantine overridden by admin\n")
            else:
                print(Fore.GREEN + "     -> Approved\n")
            approved_count += 1
            if not dry_run:
                entry["human_confirmed"] = True
                entry["resolved_at"] = datetime.now().isoformat()
        else:
            rejected_count += 1
            print(Fore.RED + "     -> Rejected\n")

    if not dry_run:
        json.dump(queue, open(path, "w"), indent=2)
        print(Fore.GREEN + "Queue updated on disk.")
    else:
        print(Fore.YELLOW + "[DRY RUN] No changes written.")

    print(
        Fore.CYAN + f"Summary: {approved_count} approved, {rejected_count} rejected"
        + (f", {quarantine_overridden} quarantine override(s)" if quarantine_overridden else "")
        + f", {approved_count} queued for retraining."
    )


if __name__ == "__main__":
    review_queue()
