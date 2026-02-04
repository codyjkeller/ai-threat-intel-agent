import os
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.markdown import Markdown

# Import our new Enterprise modules
from feeds import FeedAggregator, ThreatIntel

# Load Environment Variables
load_dotenv()
console = Console()
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OTX_API_KEY = os.getenv("OTX_API_KEY") # New Env Var support

def generate_ai_briefing(threats: list[ThreatIntel]):
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

            with console.status("[bold yellow]🧠 Generating Executive Summary...[/bold yellow]", spinner="dots"):
                response = client.chat.completions.create(
                    model="gpt-3.5-turbo",
                    messages=[{"role": "user", "content": prompt}],
                    temperature=0.3
                )
            return response.choices[0].message.content
        except Exception as e:
            console.print(f"[yellow]⚠️ AI Generation failed ({e}). Using rule-based fallback.[/yellow]")

    # Fallback
    return (
        f"**EXECUTIVE THREAT BRIEFING**\n\n"
        f"The system has aggregated **{len(threats)} active threats** from CISA and AlienVault sources. "
        f"Critical attention is required for **{threats[0].product}** regarding {threats[0].cve_id}."
    )

def main():
    # 1. Header
    console.print(Panel.fit("[bold green]🤖 AI Threat Intelligence Agent v2.0[/bold green]\nTarget: Multi-Source Aggregation", border_style="green"))

    # 2. Aggregation (The New Professional Way)
    aggregator = FeedAggregator(otx_key=OTX_API_KEY)
    all_threats = aggregator.collect_all()

    if not all_threats:
        console.print("[green]✅ No active threats reported by any feed provider.[/green]")
        return

    # 3. Sort by Severity (Criticals First)
    # Simple sort logic: CRITICAL > HIGH > MEDIUM
    severity_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    all_threats.sort(key=lambda x: severity_rank.get(x.severity, 99))

    console.print(f"\n[dim]✓ Processed {len(all_threats)} records from {len(aggregator.feeds)} sources.[/dim]\n")

    # 4. Display Data Table
    table = Table(title="🚨 Active Enterprise Threats")
    table.add_column("Severity", style="bold red")
    table.add_column("Source", style="cyan")
    table.add_column("CVE / ID", style="white")
    table.add_column("Product", style="magenta")
    table.add_column("Description", style="dim")

    for t in all_threats[:10]: # Show top 10
        table.add_row(t.severity, t.source_id, t.cve_id, t.product, t.description[:50]+"...")

    console.print(table)
    print("\n")

    # 5. Generate AI Briefing
    briefing = generate_ai_briefing(all_threats)
    console.print(Panel(Markdown(briefing), title="📄 Executive Briefing (Generated)", border_style="blue"))

if __name__ == "__main__":
    main()
