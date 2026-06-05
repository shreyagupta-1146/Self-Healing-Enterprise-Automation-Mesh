# Limitations and Future Work

While SentiHealth demonstrates a robust foundation for autonomous healthcare cybersecurity, this prototype acknowledges several architectural constraints that must be addressed before production deployment in a Level 1 Trauma Center.

## 1. Distributed Ledger Scalability
**Limitation:** The current cryptographic audit ledger (`audit_chain.json`) is maintained on a single node. While the synchronous HMAC and SHA-256 validation prevents silent log deletion, a root-level attacker could theoretically delete the entire JSON file.
**Future Work:** Migrate the ledger to a distributed blockchain framework like **Hyperledger Fabric**. This ensures that multiple nodes across different hospital subnets maintain consensus, making the audit trail truly immutable even if the central sentinel is compromised.

## 2. IP Spoofing Susceptibility
**Limitation:** The feature extraction engine groups anomalies by source IP. Sophisticated adversaries can spoof IP addresses or use botnets, diluting the per-IP velocity metrics.
**Future Work:** Implement IPv6 + MAC address cross-referencing at the switch level. Integrate session token fingerprinting to track malicious activity regardless of the reported IP address.

## 3. Cloud Dependency for Alerts
**Limitation:** The current system uses the Telegram API for human-in-the-loop authorization. This relies on external internet connectivity, violating strict "Zero-Cloud" and air-gap requirements.
**Future Work:** Replace the Telegram integration with an on-premises SMS gateway or a localized hospital pager system (e.g., Spok) to ensure alerts are delivered even if the hospital's external internet connection is severed during an attack.

## 4. Federated Threat Intelligence
**Limitation:** The ML models are trained locally and only learn from attacks against this specific hospital.
**Future Work:** Implement **Federated Learning**. This will allow multiple hospitals to share ML weight updates regarding new zero-day threats without ever sharing the underlying patient data (maintaining HIPAA compliance).

## 5. FHIR Integration
**Limitation:** The current web application is a mock Node.js server.
**Future Work:** Integrate with the **HL7 FHIR** standard to ensure the Sentinel can passively monitor real electronic health record databases (Epic, Cerner) seamlessly.

## 6. Adversarial Robustness
**Limitation:** The `review_queue.py` allows admins to inject new attack data into the retraining pipeline. If an attacker gains admin access, they could intentionally approve "normal" traffic as "attacks" (Model Poisoning).
**Future Work:** Implement adversarial ML robustness checks in the retraining pipeline to detect and discard poisoned training sets before they degrade the ensemble's accuracy.
