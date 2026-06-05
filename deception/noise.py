"""
Differential-privacy noise — defeats inference/aggregation attacks.

When an attacker queries aggregate statistics (patient counts, access counts,
average values), adding calibrated Laplacian noise makes their derived model
wrong while leaving individual authorized lookups unaffected.

Theory: (epsilon, 0)-differential privacy with the Laplace mechanism.
  Noise ~ Laplace(0, sensitivity / epsilon)
  Lower epsilon = more privacy (more noise).
  sensitivity = max change in query output from one record change (typically 1).

epsilon is read from config/deception_policy.json → noise_epsilon (default: 2.0).
A value of 2.0 is a reasonable balance for security metrics that don't need
clinical precision.  For display-only aggregate dashboards, epsilon=1.0 is fine.

Moving-target jitter:
  Randomizes response timing (uniform between [base_ms, base_ms + jitter_ms])
  so the attacker cannot fingerprint defenses by latency patterns.
"""

from __future__ import annotations

import json
import logging
import os
import random
import time
from typing import Union

logger = logging.getLogger(__name__)

_POLICY_PATH = os.path.join(os.path.dirname(__file__), "..", "config", "deception_policy.json")

Number = Union[int, float]


def _get_epsilon() -> float:
    try:
        with open(_POLICY_PATH) as f:
            return float(json.load(f).get("noise_epsilon", 2.0))
    except Exception:
        return 2.0


# ---------------------------------------------------------------------------
# Laplacian noise
# ---------------------------------------------------------------------------

def laplace_noise(sensitivity: float = 1.0, epsilon: float | None = None) -> float:
    """
    Sample from Laplace(0, sensitivity/epsilon).
    Positive epsilon required; higher = less noise.
    """
    eps = epsilon if epsilon is not None else _get_epsilon()
    if eps <= 0:
        return 0.0
    scale = sensitivity / eps
    return random.expovariate(1.0 / scale) * random.choice([-1, 1])


def add_noise_to_number(value: Number, sensitivity: float = 1.0) -> Number:
    """Add calibrated Laplacian noise to a numeric value."""
    noisy = value + laplace_noise(sensitivity)
    # Preserve int type if original was int (counts cannot be negative)
    if isinstance(value, int):
        return max(0, int(round(noisy)))
    return noisy


def add_noise_to_dict(data: dict, numeric_keys: list[str] | None = None) -> dict:
    """
    Return a copy of data with Laplacian noise added to the specified keys
    (or all numeric values if numeric_keys is None).
    """
    out = dict(data)
    for k, v in out.items():
        if numeric_keys and k not in numeric_keys:
            continue
        if isinstance(v, (int, float)):
            out[k] = add_noise_to_number(v)
    return out


def add_noise_to_list(items: list[dict], numeric_keys: list[str] | None = None) -> list[dict]:
    """Apply add_noise_to_dict to every element in a list."""
    return [add_noise_to_dict(item, numeric_keys) for item in items]


# ---------------------------------------------------------------------------
# Moving-target jitter (timing randomization)
# ---------------------------------------------------------------------------

def apply_jitter(base_ms: float = 50.0, jitter_ms: float = 200.0):
    """
    Sleep for a random duration to break timing-based fingerprinting.
    Called before returning a deceived response.
    """
    delay = (base_ms + random.uniform(0, jitter_ms)) / 1000.0
    time.sleep(delay)
