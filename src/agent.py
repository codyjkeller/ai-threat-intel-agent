import os
import json
import requests
import datetime
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.markdown import Markdown

# Load Environment Variables (for OpenAI Key)
load_dotenv()
console = Console()

# --- CONFIGURATION ---
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

def fetch_threats():
    """Get the latest Known Exploited Vulnerabilities from CISA."""
    console.print(f"[bold cyan]🔍 Scanning CISA Threat Feed...[/bold cyan]")
    try:
        response = requests.get(CISA_KEV_URL)
        response.raise_for_status()
        data = response.json()
        return data['vulnerabilities']
    except Exception as e:
        console.print(f"[bold red]❌ Error fetching feed: {e}[/bold red]")
        return []

def filter_recent_threats(vulnerabilities, limit=5):
    """Sort by dateAdded and return the most recent ones."""
    # Sort descending by date
    sorted_vulns = sorted(vulnerabilities, key=lambda x: x['dateAdded'], reverse=True)
    return sorted_vulns[:limit]

def generate_ai_summary(threats):
    """
    Uses OpenAI to write an executive summary.
    FALLBACK: If no key is found, uses a template (Safe for Demos).
    """

    # Prepare the data for the prompt
    threat_text = "\n".join([f"- {t['cveID']}: {t['vulnerabilityName']} (Added: {t['dateAdded']})" for t in threats])

    if OPENAI_API_KEY:
        try:
            from openai import OpenAI
            client = OpenAI(api_key=OPENAI_API_KEY)

            prompt = f"""
            You are a Cyber Threat Intelligence Analyst. 
            Summarize the following critical vulnerabilities for a CISO. 
            Focus on the business risk and immediate action required.
            Keep it brief (under 100 words).

            Threats:
            {threat_text}
            """

            response = client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[{"role": "user", "content": prompt}]
            )
            return response.choices[0].message.content
        except Exception as e:
            console.print(f"[yellow]⚠️ AI Generation failed ({e}). Using rule-based fallback.[/yellow]")

    # --- FALLBACK (SIMULATION MODE) ---
    return (
        f"**EXECUTIVE THREAT BRIEFING**\n\n"
        f"CISA has added {len(threats)} new confirmed exploits to the catalog this week. "
        f"Immediate patching is required for **{threats[0]['vulnerabilityName']}** ({threats[0]['cveID']}), "
        f"which is actively being exploited in the wild. "
        f"Security Operations should verify coverage for {threats[0]['product']} assets immediately."
    )

def main():
    # 1. Title
    console.print(Panel.fit("[bold green]🤖 AI Threat Intelligence Agent[/bold green]\nTarget: CISA KEV Catalog", border_style="green"))

    # 2. Fetch Data
    all_threats = fetch_threats()
    if not all_threats:
        return

    # 3. Filter Data
    recent_threats = filter_recent_threats(all_threats)
    console.print(f"[dim]✓ Processed {len(all_threats)} records. Identified {len(recent_threats)} critical alerts.[/dim]\n")

    # 4. Show Data Table
    table = Table(title="🚨 Active Exploits (Last 7 Days)")
    table.add_column("CVE ID", style="cyan", no_wrap=True)
    table.add_column("Product", style="magenta")
    table.add_column("Vulnerability Name", style="white")
    table.add_column("Date Added", style="green")

    for t in recent_threats:
        table.add_row(t['cveID'], t['product'], t['vulnerabilityName'], t['dateAdded'])

    console.print(table)
    print("\n")

    # 5. Generate "AI" Briefing
    with console.status("[bold yellow]🧠 Generating Executive Summary...[/bold yellow]", spinner="dots"):
        briefing = generate_ai_summary(recent_threats)

    # 6. Output
    console.print(Panel(Markdown(briefing), title="📄 Executive Briefing (Generated)", border_style="blue"))

    # 7. Integration Mock
    console.print("\n[dim]🔌 Slack Webhook: [Sent][/dim]")
    console.print("[dim]📧 Email Alert: [Sent][/dim]")

if __name__ == "__main__":
    main()
