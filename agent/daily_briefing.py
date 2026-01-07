import json
import logging
import schedule
import time
import os
import argparse
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - [INTEL_AGENT] - %(message)s')

class ThreatIntelAgent:
    def __init__(self, config_path):
        self.config = self._load_config(config_path)
        self.severity_threshold = 7.0  # CVSS Score Threshold

    def _load_config(self, path):
        # Handle path resolution for different running contexts
        if not os.path.exists(path):
            # Try looking one directory up if running from src/
            alt_path = path.replace("config/", "../config/") if "config/" in path else "../" + path
            if os.path.exists(alt_path):
                path = alt_path
            else:
                 # Fallback: Create default config in memory if file is missing (For Demo robustness)
                logging.warning(f"Config file not found at {path}. Using default config.")
                return {
                    "sources": [
                        {"name": "CISA Known Exploited Vulnerabilities", "priority": "CRITICAL"},
                        {"name": "NIST NVD", "priority": "HIGH"},
                        {"name": "Microsoft MSRC", "priority": "MEDIUM"}
                    ]
                }
        
        with open(path, 'r') as f:
            return json.load(f)

    def fetch_feeds(self):
        """
        Mocking the ingestion of RSS/JSON feeds from CISA, NVD, etc.
        """
        logging.info(f"Starting ingestion from {len(self.config['sources'])} sources...")
        
        # Simulated Findings
        mock_payloads = [
            {
                "source": "CISA Known Exploited Vulnerabilities",
                "cve_id": "CVE-2025-1001",
                "description": "Active exploitation of Citrix NetScaler zero-day.",
                "cvss_score": 9.8,
                "status": "Active Exploitation"
            },
            {
                "source": "NIST NVD",
                "cve_id": "CVE-2025-0045",
                "description": "Buffer overflow in minor open-source library.",
                "cvss_score": 4.5, # Should be filtered out
                "status": "Patch Available"
            },
            {
                "source": "Microsoft MSRC",
                "cve_id": "CVE-2025-2020",
                "description": "Remote Code Execution in Exchange Server OWA.",
                "cvss_score": 8.8,
                "status": "Patch Available"
            }
        ]
        return mock_payloads

    def analyze_risk(self, item):
        """
        Risk Decision Matrix:
        1. CVSS >= 7.0 (High/Critical)
        2. Source Priority = CRITICAL (e.g. CISA KEV)
        """
        if item['cvss_score'] >= self.severity_threshold:
            return True, "CVSS Criticality (>7.0)"

        for source_cfg in self.config['sources']:
            if source_cfg['name'] == item['source']:
                if source_cfg['priority'] in ['CRITICAL', 'HIGH']:
                    return True, f"Source Priority ({source_cfg['priority']})"
        
        return False, "Noise"

    def run_cycle(self):
        """Main execution logic for a single scan cycle."""
        logging.info("--- Starting Threat Scan Cycle ---")
        items = self.fetch_feeds()
        critical_findings = []

        for item in items:
            is_critical, reason = self.analyze_risk(item)
            if is_critical:
                logging.info(f"MATCH: {item['cve_id']} flagged due to {reason}")
                critical_findings.append(item)
            else:
                logging.debug(f"DROP: {item['cve_id']} below threshold.")

        self.send_email_alert(critical_findings)
        logging.info("--- Cycle Complete ---")

    def send_email_alert(self, findings):
        """
        Sends an HTML-formatted email summary to the Security Leadership team.
        """
        if not findings:
            logging.info("No critical findings. Skipping email.")
            return

        sender_email = os.getenv("SMTP_USER", "agent@internal-security.local")
        receiver_email = os.getenv("ALERT_EMAIL", "ciso@company.com")

        # Build Email Content
        msg = MIMEMultipart()
        msg['Subject'] = f"🚨 Threat Intel Briefing: {len(findings)} Critical Items - {datetime.now().strftime('%Y-%m-%d')}"
        msg['From'] = sender_email
        msg['To'] = receiver_email

        body_html = f"""
        <h2>Daily Executive Threat Briefing</h2>
        <p><b>Date:</b> {datetime.now().strftime('%Y-%m-%d')}</p>
        <p>The following items matched our <b>High Risk</b> criteria (CVSS > 7.0 or Active Exploitation):</p>
        <hr>
        """

        for item in findings:
            body_html += f"""
            <div style='margin-bottom: 20px; padding: 10px; border-left: 5px solid #d9534f; background-color: #f9f9f9;'>
                <h3 style='margin: 0; color: #d9534f;'>{item['cve_id']} (CVSS {item['cvss_score']})</h3>
                <p><b>Source:</b> {item['source']}<br>
                <b>Impact:</b> {item['description']}<br>
                <b>Status:</b> {item['status']}</p>
            </div>
            """

        msg.attach(MIMEText(body_html, 'html'))

        try:
            # Mocking the actual send for the portfolio demo
            logging.info(f"📧 EMAIL SENT to {receiver_email} with {len(findings)} items.")
            # print(f"\n--- [DEMO OUTPUT] Email Body Generated ---\n{body_html}\n------------------------------------------")
        except Exception as e:
            logging.error(f"Failed to send email: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AI Threat Intel Agent")
    parser.add_argument("--config", default="config/settings.json", help="Path to config file")
    parser.add_argument("--run-once", action="store_true", help="Run a single scan and exit (for CI/CD)")
    args = parser.parse_args()

    agent = ThreatIntelAgent(args.config)

    if args.run_once:
        agent.run_cycle()
    else:
        logging.info("Starting Scheduler (Runs daily at 08:00)...")
        schedule.every().day.at("08:00").do(agent.run_cycle)
        
        # Also run immediately on startup for demo purposes
        agent.run_cycle() 
        
        while True:
            schedule.run_pending()
            time.sleep(1)
