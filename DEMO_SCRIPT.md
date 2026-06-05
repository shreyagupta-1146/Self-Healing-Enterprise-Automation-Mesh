SENTIHEALTH LIVE DEMO SCRIPT
Total time: 8 minutes

[T=0:00] Terminal 1: source .venv/bin/activate && cd webapp && node app.js
         Say: "This is our mock hospital EHR server, now live on port 3000."

[T=0:30] Terminal 2: source .venv/bin/activate && python3 live_sentinel.py
         Say: "The AI watchdog is now active. It's watching every HTTP request in real time."

[T=1:00] Browser: Open http://localhost:5001
         Say: "This is our live threat dashboard. Currently all green — normal hospital traffic."

[T=1:30] Terminal 3: python3 attack_scripts/exfiltration.py
         Say: "We're now simulating a data exfiltration attack. Watch the dashboard."

[T=2:00] Point to Terminal 2 as it detects threat
         Say: "The sentinel detected anomalous volume from this IP. Risk score: 0.84. Tier: HIGH."

[T=2:30] Show Telegram notification on phone (pre-screenshotted as backup)
         Say: "The Chief Security Officer receives an instant Telegram alert."

[T=3:00] Show Terminal 2 receiving authorization and restoring system
         Say: "Authorization received. System is self-healing. Final status: RESTORED."

[T=3:30] Open logs/shap_explanation_<latest>.png
         Say: "Here's WHY the AI flagged this IP — the top factors were failed logins, CPU spike, and unusual EHR access rate."

[T=4:00] Run: python3 attack_scripts/brute_force.py
         Say: "Let's try a second attack type — credential stuffing."

[T=4:30] Show detection in Terminal 2
         Say: "Caught immediately. Different attack vector, same result."

[T=5:00] Run: python3 review_queue.py --auto-approve-low
         Say: "These attack patterns are now being fed back into our ML training queue."

[T=5:30] Run: python3 generate_report.py && open reports/incident_report_<latest>.html
         Say: "Here's the auto-generated forensic incident report. Ready for a HIPAA compliance audit."

[T=6:00] Show MODEL_METRICS.md in a text editor
         Say: "All 5 models validated on held-out data. Ensemble F1 score is highly precise."

[T=6:30] Q&A buffer / architecture diagram walkthrough

[T=8:00] End
