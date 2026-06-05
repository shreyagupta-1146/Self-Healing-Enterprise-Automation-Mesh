import json
import os
from datetime import datetime

os.makedirs("reports", exist_ok=True)

def generate_report():
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = f"reports/incident_report_{timestamp}.html"
    
    # Gather Data
    blockchain_status = "INTACT"
    if os.path.exists('logs/tamper_alerts.log'):
        with open('logs/tamper_alerts.log', 'r') as f:
            if f.read().strip():
                blockchain_status = "COMPROMISED"
                
    threats = []
    if os.path.exists('logs/threat_log.json'):
        with open('logs/threat_log.json', 'r') as f:
            threats = [json.loads(line) for line in f if line.strip()]
            
    blocked_ips = []
    if os.path.exists('logs/blocked_ips.json'):
        with open('logs/blocked_ips.json', 'r') as f:
            blocked_ips = [json.loads(line) for line in f if line.strip()]
            
    audit_chain = []
    if os.path.exists('data/audit_chain.json'):
        with open('data/audit_chain.json', 'r') as f:
            audit_chain = json.load(f)

    # Process Data for Chart
    tier_counts = {"Low": 0, "Medium": 0, "High": 0}
    for t in threats:
        if t['tier'] in tier_counts:
            tier_counts[t['tier']] += 1
            
    # Process Timeline
    timeline_html = ""
    for entry in audit_chain[-15:]:
        if 'timestamp' in entry:
            tier = entry.get('tier', 'N/A')
            status = entry.get('status', 'N/A')
            actions = ", ".join(entry.get('actions_taken', []))
            timeline_html += f"<li><strong>{entry['timestamp']}</strong>: Tier {tier} - Status: {status} - Actions: {actions}</li>"
            
    # HTML Template
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>SentiHealth Forensics Report</title>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f4f7f6; color: #333; line-height: 1.6; padding: 20px; }}
            .container {{ max-width: 900px; margin: auto; background: #fff; padding: 30px; border-radius: 8px; box-shadow: 0 4px 8px rgba(0,0,0,0.1); }}
            h1, h2, h3 {{ color: #2c3e50; border-bottom: 2px solid #ecf0f1; padding-bottom: 10px; }}
            .summary-box {{ background: #e8f4f8; padding: 20px; border-left: 5px solid #3498db; margin-bottom: 20px; }}
            .alert {{ color: #e74c3c; font-weight: bold; }}
            .success {{ color: #27ae60; font-weight: bold; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
            th, td {{ border: 1px solid #ddd; padding: 10px; text-align: left; }}
            th {{ background-color: #f8f9fa; }}
            .chart-container {{ width: 400px; margin: 20px auto; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🛡️ SentiHealth Automated Forensics & Incident Report</h1>
            <p><strong>Generated At:</strong> {datetime.now().isoformat()}</p>
            
            <div class="summary-box">
                <h2>Executive Summary</h2>
                <p>Total Threats Detected: <strong>{len(threats)}</strong></p>
                <p>Total IPs Blocked: <strong>{len(blocked_ips)}</strong></p>
                <p>Cryptographic Audit Ledger Integrity: 
                    <span class="{'success' if blockchain_status == 'INTACT' else 'alert'}">{blockchain_status}</span>
                </p>
            </div>
            
            <h2>Threat Tier Distribution</h2>
            <div class="chart-container">
                <canvas id="tierChart"></canvas>
            </div>
            
            <h2>Blocked IPs</h2>
            <table>
                <tr><th>Timestamp</th><th>IP Address</th></tr>
                {''.join([f"<tr><td>{ip['time']}</td><td>{ip['ip']}</td></tr>" for ip in blocked_ips[-10:]])}
            </table>
            
            <h2>Recent Incident Timeline (Audit Ledger)</h2>
            <ul>
                {timeline_html}
            </ul>
            
            <h2>Follow-up Recommendations</h2>
            <ul>
                <li>Review all High-tier threats in the Retraining Queue.</li>
                <li>Cross-reference blocked IPs with MAC addresses to prevent IP spoofing.</li>
                <li>Ensure the network firewall API keys have not expired.</li>
            </ul>
        </div>
        
        <script>
            const ctx = document.getElementById('tierChart');
            new Chart(ctx, {{
                type: 'pie',
                data: {{
                    labels: ['Low', 'Medium', 'High'],
                    datasets: [{{
                        data: [{tier_counts['Low']}, {tier_counts['Medium']}, {tier_counts['High']}],
                        backgroundColor: ['#2ecc71', '#f39c12', '#e74c3c']
                    }}]
                }}
            }});
        </script>
    </body>
    </html>
    """
    
    with open(report_path, "w") as f:
        f.write(html)
        
    print(f"[REPORT] Incident report saved to {report_path}")

if __name__ == "__main__":
    generate_report()
