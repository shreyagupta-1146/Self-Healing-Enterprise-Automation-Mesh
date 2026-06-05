# SentinelHealth — Complete Q&A Reference Document
**Project:** ML-Driven Threat Detection and Self-Healing Architecture for Healthcare Web Applications  
**Repository:** [UnisysUIP GitHub](https://github.com/UnisysUIP/2026-ML-Driven-Threat-Detection-and-Self-Healing-Architecture-for-Healthcare-Web-Applications)  
**Last Updated:** 2026-05-15

---

## Table of Contents
1. [What does SentinelHealth actually do?](#1-what-does-sentinelhealth-actually-do)
2. [How are synthetic datasets generated?](#2-how-are-synthetic-datasets-generated)
3. [How do the models calculate accuracy, precision, and F1 score?](#3-how-do-the-models-calculate-accuracy-precision-and-f1-score)
4. [What is `retraining_queue.json`?](#4-what-is-retraining_queuejson)
5. [Explain the `logs/` and `data/` folders](#5-explain-the-logs-and-data-folders)
6. [Why were only 5 features showing in SHAP when there are 8 ML features?](#6-why-were-only-5-features-showing-in-shap-when-there-are-8-ml-features)
7. [Why were 3 features showing flat/zero bars in the SHAP chart?](#7-why-were-3-features-showing-flatzero-bars-in-the-shap-chart)

---

## 1. What does SentinelHealth actually do?

SentinelHealth is an **autonomous cybersecurity monitoring framework** designed for healthcare web applications. It operates as a real-time threat detection and self-healing pipeline.

### Core Pipeline:
1. **Event Ingestion** — `live_sentinel.py` monitors `logs/events.jsonl` for incoming network/application events (login attempts, EHR access, data exports, etc.).
2. **ML Scoring** — Each event's features are fed into trained ML models (Random Forest, XGBoost, etc.) located in `models/`. The scoring matrix (`scoring_matrix.py`) computes a composite risk score.
3. **Tier Classification** — Based on the risk score, events are classified into:
   - **Low** (score < 0.4) → Logged to audit trail only
   - **Medium** (0.4–0.7) → Account locked, IP blocked, alert sent
   - **High** (> 0.7) → Bandwidth throttled, database snapshotted, human alerted via Telegram
4. **Self-Healing Response** — `self_healing_responder.py` automatically executes containment actions (IP blocking, DB snapshots, bandwidth throttling) and manages the restoration workflow for High-tier threats.
5. **SHAP Explainability** — For every High-tier threat, a SHAP bar chart is generated showing which features drove the model's decision, saved to `logs/shap_explanation_*.png`.
6. **Audit Chain** — Every action is cryptographically logged into `data/audit_chain.json` using SHA-256 hash chaining, ensuring tamper-proof forensic evidence.
7. **Telegram Alerting** — High-tier threats trigger real-time Telegram notifications via the `SentiHealth_Watchdog` bot.

---

## 2. How are synthetic datasets generated?

The system uses **programmatic synthetic data generation** — not real patient data. The datasets are created by Python scripts that simulate realistic healthcare network traffic patterns.

### How it works:
- **Normal traffic patterns** are modeled after typical hospital IT behavior: low failed logins (0–2), normal CPU usage (10–40%), standard EHR access rates (5–15/hour), minimal data exports.
- **Attack patterns** are modeled after known healthcare cyber attack signatures from MITRE ATT&CK and HHS breach reports:
  - **Exfiltration attacks**: High data export volumes (1500–3000 KB), elevated EHR access (120–200/hour), high lateral movement
  - **DDoS attacks**: CPU spikes (80–92%), memory spikes, high request rates
  - **Credential stuffing**: High failed logins (8–14), abnormal access times
- **The attack simulator** (`attack_scripts/exfiltration.py`) generates 3-phase attack bursts:
  - Phase 1 (Recon): Low indicators, subtle probing
  - Phase 2 (Escalation): Medium indicators, privilege escalation
  - Phase 3 (Exfiltration): High indicators across all features
- **Randomization** ensures variance: values are drawn from realistic ranges using `random.randint()` and `random.uniform()`, not static values.
- **Reference sources**: The feature distributions are inspired by real-world healthcare breach data from the HHS Breach Portal (2024–2025 statistics), NIST cybersecurity frameworks, and HIPAA security audit patterns.

### The 8 ML Features used:
| # | Feature | Description |
|---|---------|-------------|
| 1 | `failed_logins` | Count of failed authentication attempts |
| 2 | `cpu_usage` | Server CPU utilization (0.0–1.0) |
| 3 | `ehr_access_per_hour` | Electronic Health Record access frequency |
| 4 | `memory_spike` | Binary flag for abnormal memory usage |
| 5 | `data_export_volume_kb` | Volume of data being exported in KB |
| 6 | `lateral_movement_events` | Count of cross-system access attempts |
| 7 | `access_time_deviation` | Deviation from normal access hours (in hours) |
| 8 | `source_ip_reputation` | IP reputation score (0.0=malicious, 1.0=trusted) |

### Additional context metadata (non-ML, used for rule-based logic):
- `request_rate`, `attack_type`, `asset_type`, `emergency_status`, `user_id`, `role`

---

## 3. How do the models calculate accuracy, precision, and F1 score?

Yes — the formulas are implemented in the dedicated model training scripts inside the `models/` folder. The system uses **scikit-learn's built-in metrics**.

### Formulas:

**Accuracy:**
```
Accuracy = (True Positives + True Negatives) / Total Predictions
```

**Precision:**
```
Precision = True Positives / (True Positives + False Positives)
```
- Answers: "Of all events flagged as threats, how many actually were threats?"

**Recall (Sensitivity):**
```
Recall = True Positives / (True Positives + False Negatives)
```
- Answers: "Of all actual threats, how many did the model catch?"

**F1 Score:**
```
F1 = 2 × (Precision × Recall) / (Precision + Recall)
```
- The harmonic mean of precision and recall — balances both metrics.

### How they're computed in the codebase:
- During training, the dataset is split into training (80%) and test (20%) sets.
- After the model trains, predictions are run on the test set.
- `sklearn.metrics.classification_report()` computes precision, recall, F1, and accuracy for each class (Low, Medium, High).
- Results are logged to the console and saved alongside the model artifacts.

### Why F1 matters for healthcare:
In healthcare cybersecurity, **false negatives are dangerous** (a missed attack could leak PHI), but **false positives are costly** (locking out legitimate clinicians disrupts patient care). F1 balances both concerns.

---

## 4. What is `retraining_queue.json`?

`retraining_queue.json` (located in `retraining/`) is a **feedback loop buffer** for future model improvement.

### Purpose:
When a High-tier threat is **confirmed by a human admin** (via the Telegram approval flow), the event's full feature vector and outcome are appended to this file. This creates a curated dataset of **verified real-world threats** that can be used to retrain and fine-tune the ML models.

### Structure:
```json
{
  "event_id": "uuid",
  "timestamp": "ISO-8601",
  "features": { ... all 8 ML features ... },
  "confirmed_tier": "High",
  "admin_action": "approved",
  "source": "live_sentinel"
}
```

### Workflow:
1. Live Sentinel detects a High-tier threat
2. Admin reviews and approves/rejects via the self-healing responder
3. If approved → event is appended to `retraining_queue.json`
4. Future retraining pipeline (`model_retraining_pipeline.py` — planned) will:
   - Consume entries from this queue
   - Merge them with the original training data
   - Retrain all models with the enriched dataset
   - Deploy updated models to `models/`

### Why it matters:
This is the **continuous learning** component. Without it, the models would become stale as attack patterns evolve. The queue ensures the system adapts to new threat vectors observed in production.

---

## 5. Explain the `logs/` and `data/` folders

### `data/` — The Storage & Ledger Layer

This is the **persistent state** of the system. Think of it as the system's "brain."

| File | Role |
|------|------|
| `audit_chain.json` | **Immutable cryptographic ledger.** Every threat detection, response action, and status change is recorded as a hash-chained entry. Each entry contains: `event_id`, `timestamp`, `tier`, `prev_hash`, `actions_taken`, `status`, and `entry_hash`. The `entry_hash` is computed from the current data + `prev_hash`, creating a blockchain-like tamper-evident chain. If any entry is modified, `verify_chain_integrity()` in `self_healing_responder.py` will detect the broken chain and trigger a `HALTED_CORRUPTION` status. |
| `app.db` | SQLite database storing structured application state (user sessions, configuration, historical metrics). |

### `logs/` — The Forensic Evidence Store

This is the **real-time operational output**. Think of it as the system's "memory."

| File | Role |
|------|------|
| `events.jsonl` | **Live event stream.** Every incoming network event is appended here as a JSON line. This is what `live_sentinel.py` monitors in real-time. Each line contains the full event payload including all ML features. |
| `threat_log.json` | **Threat registry.** Aggregated list of all detected threats with their tier classification, risk scores, and SHAP insights. Used for dashboard display and reporting. |
| `blocked_ips.json` | **Active blocklist.** IPs currently blocked by the self-healing responder. Contains IP, block timestamp, reason, and expiry. |
| `shap_explanation_*.png` | **SHAP explainability charts.** One PNG per High-tier detection, showing the horizontal bar chart of all 8 feature contributions. Named with timestamp: `shap_explanation_YYYYMMDD_HHMMSS.png`. |
| `forensic_report_*.json` | **Detailed forensic reports.** Generated for confirmed High-tier threats after admin approval. Contains full event context, timeline, affected assets, and recommended remediation steps. |

### Key Difference:
- `data/` = **What happened** (immutable historical record, audit compliance)
- `logs/` = **What's happening** (operational evidence, real-time monitoring)

---

## 6. Why were only 5 features showing in SHAP when there are 8 ML features?

### The Problem:
The system uses **8 ML features** for threat scoring, but the SHAP explanation chart (`generate_shap_chart()` in `live_sentinel.py`) was only displaying 5 features.

### Root Cause:
The feature name list in `generate_shap_chart()` was **hardcoded** with only 5 entries:

```python
# BEFORE (Bug):
names = ['failed_logins', 'cpu_usage', 'ehr_access_per_hour', 'memory_spike', 'data_export_volume_kb']
```

The 3 missing features were:
- `lateral_movement_events`
- `access_time_deviation`
- `source_ip_reputation`

### The Fix (applied to `live_sentinel.py`):
```python
# AFTER (Fixed):
names = ['failed_logins', 'cpu_usage', 'ehr_access_per_hour', 'memory_spike',
         'data_export_volume_kb', 'lateral_movement_events', 'access_time_deviation',
         'source_ip_reputation']
```

Chart height was also increased from `figsize=(8, 4)` to `figsize=(8, 5)` to accommodate 8 bars without label overlap.

### Commit: `b40899c` — "fix: SHAP chart now shows all 8 ML features instead of 5"

---

## 7. Why were 3 features showing flat/zero bars in the SHAP chart?

### The Problem:
After fixing the SHAP chart to show all 8 features, the 3 new features (`lateral_movement_events`, `access_time_deviation`, `source_ip_reputation`) appeared in the chart but had **flat/invisible bars** — they showed 0 or near-zero values.

### Root Cause:
The attack simulator (`attack_scripts/exfiltration.py`) was **hardcoding these 3 features to static values** instead of varying them per attack phase:

```python
# BEFORE (Bug):
"lateral_movement_events": 0,       # Always zero
"access_time_deviation": 0.1,       # Tiny — invisible at scale
"source_ip_reputation": 0.5,        # Static — no variation
```

### The Fix (applied to `exfiltration.py`):
Now each attack phase generates **realistic, escalating values**:

| Feature | Phase 1 (Recon) | Phase 2 (Escalation) | Phase 3 (Exfiltration) |
|---------|:-:|:-:|:-:|
| `lateral_movement_events` | 0–2 | 3–7 | 8–15 |
| `access_time_deviation` | 0.1–1.0 | 1.5–3.0 | 3.5–6.0 |
| `source_ip_reputation` | 0.6–0.9 (good) | 0.25–0.5 (suspicious) | 0.02–0.15 (malicious) |

### Commit: `73e7b35` — "fix: exfiltration simulator now generates realistic values for all 8 ML features"

---

## Summary of All Code Changes Made

| File | Change | Commit |
|------|--------|--------|
| `live_sentinel.py` | SHAP chart: 5 → 8 features, chart height 4 → 5 | `b40899c` |
| `attack_scripts/exfiltration.py` | 3 features: static values → per-phase random ranges | `73e7b35` |

---

*Generated on 2026-05-15 as a comprehensive reference for the SentinelHealth project.*
