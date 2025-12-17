import json
import logging
from datetime import datetime

# Configure logging to look like a production service
logging.basicConfig(level=logging.INFO, format='%(asctime)s - [INTEL_AGENT] - %(message)s')

class ThreatIntelAgent:
    def __init__(self, config_path):
        self.config = self._load_config(config_path)
        self.severity_threshold = 7.0  # CVSS Score Threshold

    def _load_config(self, path):
        with open(path, 'r') as f:
            return json.load(f)

    def fetch_feeds(self):
        """
        Iterates through sources defined in feeds.json.
        In a real deployment, this would use 'requests' to hit the RSS/JSON endpoints.
        For this portfolio demo, we simulate incoming payloads to demonstrate the filtering logic.
        """
        logging.info(f"Starting ingestion from {len(self.config['sources'])} sources...")
        
        # Simulating raw data fetched from CISA and NVD
        mock_payloads = [
            {
                "source": "CISA Known Exploited Vulnerabilities",
                "cve_id": "CVE-2025-1001",
                "description": "Active exploitation of Citrix NetScaler zero-day.",
                "cvss_score": 9.8,  # CRITICAL
                "status": "Active Exploitation"
            },
            {
                "source": "NIST NVD",
                "cve_id": "CVE-2025-0045",
                "description": "Buffer overflow in minor open-source library (lib-png-tiny).",
                "cvss_score": 4.5,  # MEDIUM - Should be filtered out
                "status": "Patch Available"
            },
            {
                "source": "Microsoft MSRC",
                "cve_id": "CVE-2025-2020",
                "description": "Remote Code Execution in Exchange Server OWA.",
                "cvss_score": 8.8,  # HIGH
                "status": "Patch Available"
            }
        ]
        return mock_payloads

    def analyze_risk(self, item):
        """
        The 'Brain' of the agent.
        Decides if an item is worth Executive attention.
        """
        # Logic 1: Filter by CVSS Score (The "7.0 Rule")
        if item['cvss_score'] >= self.severity_threshold:
            return True, "CVSS Criticality (>7.0)"

        # Logic 2: Check Source Priority from Config
        # (Simplified for demo: assumes source name matches config)
        for source_cfg in self.config['sources']:
            if source_cfg['name'] == item['source']:
                if source_cfg['priority'] in ['CRITICAL', 'HIGH']:
                    return True, f"Source Priority ({source_cfg['priority']})"
        
        return False, "Noise"

    def run(self):
        findings = []
        raw_data = self.fetch_feeds()

        for item in raw_data:
            is_relevant, reason = self.analyze_risk(item)
            if is_relevant:
                logging.info(f"ALERT TRIGGERED: {item['cve_id']} | Score: {item['cvss_score']} | Reason: {reason}")
                findings.append(item)
            else:
                logging.debug(f"Skipping noise: {item['cve_id']} (Score: {item['cvss_score']})")

        self.generate_executive_summary(findings)

    def generate_executive_summary(self, findings):
        """
        Uses GenAI (Mocked) to summarize the filtered findings into a 1-page email.
        """
        print("\n" + "="*60)
        print(f"📢 DAILY EXECUTIVE THREAT BRIEFING - {datetime.now().strftime('%Y-%m-%d')}")
        print("="*60)
        
        if not findings:
            print("Status: GREEN. No critical threats detected in the last 24 hours.")
            return

        print(f"⚠️  ALERT STATUS: RED ({len(findings)} Critical Items Detected)\n")
        
        for idx, item in enumerate(findings, 1):
            print(f"{idx}. {item['cve_id']} (CVSS {item['cvss_score']})")
            print(f"   - Source: {item['source']}")
            print(f"   - Impact: {item['description']}")
            print(f"   - Action: Notify Infra Team immediately.\n")

        print("="*60)
        print("[System] Briefing sent to CISO and SOC Manager via Slack Webhook.")

if __name__ == "__main__":
    # Point to the config file we created earlier
    agent = ThreatIntelAgent('../config/feeds.json')
    agent.run()
