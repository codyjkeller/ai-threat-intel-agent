import os
import requests
import logging
from typing import Union, Dict, Any

# We use lazy import inside function to avoid circular dependency if needed, 
# but for type hinting we can use 'Any' or import class if structure allows.

logger = logging.getLogger(__name__)

def send_slack_alert(threat: Any) -> bool:
    """
    Dispatch a formatted Slack alert.
    Returns True if sent successfully, False otherwise.
    """
    slack_url = os.getenv("SLACK_WEBHOOK_URL")
    
    if not slack_url or "hooks.slack.com" not in slack_url:
        # Debug level so logs aren't spammed if not configured
        logger.debug("Slack Webhook not configured. Skipping alert.")
        return False

    # 1. Normalize Data (Handle Class vs Legacy Dict)
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
                        "text": {"type": "plain_text", "text": f"{severity}: {cve_id}", "emoji": False}
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
        requests.post(slack_url, json=payload, timeout=5)
        return True
    except requests.RequestException as e:
        logger.error(f"Slack Delivery Failed: {e}")
        return False
