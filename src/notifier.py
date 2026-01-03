import os
import requests
from dotenv import load_dotenv

load_dotenv()
SLACK_URL = os.getenv("SLACK_WEBHOOK_URL")

def send_slack_alert(cve_data):
    if not SLACK_URL or "hooks.slack.com" not in SLACK_URL:
        return

    payload = {
        "blocks": [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": f"🚨 Critical Alert: {cve_data['id']}", "emoji": True}
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Tech:*\n{cve_data['tech'].upper()}"},
                    {"type": "mrkdwn", "text": "*Severity:*\nHigh / Critical"}
                ]
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*{cve_data['description'][:150]}...*"}
            },
            {
                "type": "actions",
                "elements": [
                    {"type": "button", "text": {"type": "plain_text", "text": "View Official Report"}, "url": cve_data['url'], "style": "danger"}
                ]
            }
        ]
    }

    try:
        requests.post(SLACK_URL, json=payload)
        print(f"✅ Slack alert sent for {cve_data['id']}")
    except Exception as e:
        print(f"❌ Slack Error: {e}")
