# sentiHealth

An autonomous, zero-cloud healthcare cybersecurity framework that leverages Machine Learning to detect threats in milliseconds and execute self-healing protocols with human-in-the-loop authorization.

## Architecture
```text
[Node.js EHR] → [events.jsonl] → [live_sentinel.py] → [ML Ensemble] → [Self-Healing Responder] → [Telegram Alert] / [audit_chain.json]
```

## Execution Code (Quickstart)

Open 4 separate terminal windows and run the following commands in order:

**Terminal 1 (Install & Start EHR Server):**
```bash
source setup.sh
cd webapp && node app.js
```

**Terminal 2 (Start Live Sentinel AI):**
```bash
source .venv/bin/activate
export SENTIHEALTH_TEST_MODE=1
python3 live_sentinel.py
```

**Terminal 3 (Start Live Dashboard):**
```bash
source .venv/bin/activate
python3 dashboard.py
```
*View the dashboard at `http://localhost:5001` in your browser.*

**Terminal 4 (Launch Cyberattack Simulation):**
```bash
source .venv/bin/activate
python3 attack_scripts/exfiltration.py
```

## Technologies Used
| Component | Technology |
| --- | --- |
| Core Agent | Python 3.10+ |
| ML Models | Scikit-Learn, XGBoost |
| Explainability | SHAP, Matplotlib |
| Target Server | Node.js, Express |
| Notifications | Telegram Bot API |
| Cryptography | SHA-256 HMAC |
| Live Dashboard | Flask |

## Security Architecture
- **Layer 1 (The Target):** Node.js server generates live network logs (`events.jsonl`).
- **Layer 2 (The Watchdog):** `live_sentinel.py` tails the logs and calculates feature vectors.
- **Layer 3 (The Brain):** A 5-model ML Ensemble scores the risk and assigns a Threat Tier.
- **Layer 4 (The Responder):** Executes self-healing (throttling, snapshots) and alerts admins via Telegram for High-tier authorization. Uses a Cryptographic Audit Ledger (SHA-256 hash-chained log — same cryptographic principle as blockchain) to prevent tampering.

## Limitations and Future Work
Please refer to `FUTURE_WORK.md` for a complete list of known limitations (like IP spoofing) and planned enhancements (like Hyperledger Fabric).
