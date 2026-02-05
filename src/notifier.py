import os
import requests
from dotenv import load_dotenv

load_dotenv()
SLACK_URL = os.getenv("SLACK_WEBHOOK_URL")

def send_slack_alert(threat):
    """
    Dispatch a formatted Slack alert.
    Supports both v2.0 ThreatIntel objects and legacy dictionaries.
    """
    if not SLACK_URL or "hooks.slack.com" not in SLACK_URL:
        # Silently fail if no webhook is configured (avoids crashing the agent)
        return

    # 1. Normalize Data (Handle Class vs Dict)
    if hasattr(threat, 'cve_id'): 
        # It's a v2.0 ThreatIntel Object
        cve_id = threat.cve_id
        product = threat.product
        desc = threat.description
        url = threat.url
        severity = threat.severity.upper()
    else: 
        # It's a legacy Dictionary
        cve_id = threat.get('id', 'Unknown')
        product = threat.get('tech', 'Unknown')
        desc = threat.get('description', '')
        url = threat.get('url', '#')
        severity = "HIGH"

    # 2. Define Color based on Severity
    color_map = {
        "CRITICAL": "#DC2626", # Red
        "HIGH": "#EA580C",     # Orange
        "MEDIUM": "#CA8A04",   # Yellow
        "LOW": "#16A34A"       # Green
    }
    color = color_map.get(severity, "#555555")

    # 3. Build Block Kit Payload
    payload = {
        "attachments": [
            {
                "color": color,
                "blocks": [
                    {
                        "type": "header",
                        "text": {"type": "plain_text", "text": f"🚨 {severity}: {cve_id}", "emoji": True}
                    },
                    {
                        "type": "section",
                        "fields": [
                            {"type": "mrkdwn", "text": f"*Product:*\n{product}"},
                            {"type": "mrkdwn", "text": f"*Severity:*\n{severity}"}
                        ]
                    },
                    {
                        "type": "section",
                        "text": {"type": "mrkdwn", "text": f"_{desc[:200]}..._"}
                    },
                    {
                        "type": "actions",
                        "elements": [
                            {"type": "button", "text": {"type": "plain_text", "text": "View Intel Report"}, "url": url, "style": "danger"}
                        ]
                    }
                ]
            }
        ]
    }

    try:
        requests.post(SLACK_URL, json=payload, timeout=5)
        # We don't print here to keep the CLI clean; let the agent handle logging
    except Exception as e:
        print(f"❌ Slack Delivery Failed: {e}")
