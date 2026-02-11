import os
import logging
import sys
from typing import List
from dotenv import load_dotenv

# Local Modules
from feeds import FeedAggregator, ThreatIntel
from notifier import send_slack_alert

# Configure Enterprise Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [THREAT_INTEL] - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

# Load Environment Variables
load_dotenv()
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OTX_API_KEY = os.getenv("OTX_API_KEY")

def generate_ai_briefing(threats: List[ThreatIntel]) -> str:
    """
    Generates a BLUF (Bottom Line Up Front) executive summary using OpenAI.
    """
    # Convert object list to text summary for the LLM
    threat_text = "\n".join([f"- [{t.severity}] {t.cve_id}: {t.title} ({t.product})" for t in threats[:10]])

    if OPENAI_API_KEY:
        try:
            from openai import OpenAI
            client = OpenAI(api_key=OPENAI_API_KEY)

            prompt = f"""
            Role: You are a Cyber Threat Intelligence Analyst advising a F500 CISO.
            Task: Synthesize a "Bottom Line Up Front" (BLUF) briefing for the active threats listed below.
             
            Constraints:
            1. Start with a single "Strategic Impact" sentence.
            2. List top 3 "Actionable Steps" for Security Operations.
            3. Tone: Professional, Urgent, Concise.
             
            Threat Data:
            {threat_text}
            """

            logger.info("Generating Executive Summary via OpenAI...")
            response = client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.3
            )
            return response.choices[0].message.content
        except Exception as e:
            logger.error(f"AI Generation failed: {e}. Reverting to fallback.")

    # Fallback
    return (
        f"**EXECUTIVE THREAT BRIEFING**\n\n"
        f"The system has aggregated **{len(threats)} active threats** from CISA and AlienVault sources. "
        f"Critical attention is required for **{threats[0].product}** regarding {threats[0].cve_id}."
    )

def main():
    logger.info("Starting AI Threat Intelligence Agent v2.0")
    logger.info("Target: Multi-Source Aggregation")

    # 1. Aggregation
    aggregator = FeedAggregator(otx_key=OTX_API_KEY)
    all_threats = aggregator.collect_all()

    if not all_threats:
        logger.info("No active threats reported by any feed provider.")
        return

    # 2. Sort by Severity (Criticals First)
    severity_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    all_threats.sort(key=lambda x: severity_rank.get(x.severity, 99))

    logger.info(f"Processed {len(all_threats)} records from {len(aggregator.feeds)} sources.")

    # 3. Process Threats & Alert
    alerts_sent = 0
    print("\n" + "="*60)
    print(f"{'SEVERITY':<12} | {'SOURCE':<15} | {'CVE ID':<18} | {'PRODUCT'}")
    print("-" * 60)

    for t in all_threats[:15]: # Process top 15
        # Clean Output Table
        print(f"{t.severity:<12} | {t.source_id[:15]:<15} | {t.cve_id:<18} | {t.product}")
        
        # Dispatch Alert for Critical/High
        if t.severity in ["CRITICAL", "HIGH"]:
            if send_slack_alert(t):
                alerts_sent += 1

    print("="*60 + "\n")

    if alerts_sent > 0:
        logger.info(f"Dispatched {alerts_sent} Slack alerts for High/Critical threats.")
    else:
        logger.info("No alerts sent (No High/Critical threats or Slack not configured).")

    # 4. Generate AI Briefing
    briefing = generate_ai_briefing(all_threats)
    print("\n--- EXECUTIVE BRIEFING (GENERATED) ---\n")
    print(briefing)
    print("\n--------------------------------------\n")

if __name__ == "__main__":
    main()
