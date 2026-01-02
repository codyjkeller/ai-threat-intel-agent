import os
import feedparser
import pandas as pd
from datetime import datetime
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table
from langchain_openai import ChatOpenAI
from langchain.schema import HumanMessage, SystemMessage

# Load environment variables (looks for .env locally)
load_dotenv()

# Configuration
RSS_FEEDS = [
    "https://feeds.feedburner.com/TheHackersNews",  # The Hacker News
    "https://www.cisa.gov/uscert/ncas/alerts.xml",   # CISA Alerts
    "https://www.bleepingcomputer.com/feed/"         # BleepingComputer
]

WATCHLIST = ["Kubernetes", "AWS", "Python", "Ransomware", "Zero-Day", "Supply Chain"]

console = Console()

class ThreatIntelAgent:
    def __init__(self):
        # We use a try-except block here so the script doesn't crash 
        # if a recruiter runs it without an API key.
        try:
            api_key = os.getenv("OPENAI_API_KEY")
            if not api_key or "placeholder" in api_key:
                console.print("[yellow]⚠️  Warning: No valid OPENAI_API_KEY found in .env file.[/yellow]")
                console.print("[yellow]   The agent will run in 'Demo Mode' (fetching feeds only).[/yellow]")
                self.llm = None
            else:
                self.llm = ChatOpenAI(model_name="gpt-4", temperature=0)
                console.print("[bold green]🤖 AI Threat Intel Agent Initialized[/bold green]")
        except Exception as e:
            console.print(f"[red]Error initializing AI: {e}[/red]")
            self.llm = None

    def fetch_threats(self):
        """Fetches latest articles from RSS feeds."""
        articles = []
        console.print(f"📡 Scanning {len(RSS_FEEDS)} threat intelligence feeds...")
        
        for url in RSS_FEEDS:
            try:
                feed = feedparser.parse(url)
                for entry in feed.entries[:5]:
                    articles.append({
                        "title": entry.title,
                        "link": entry.link,
                        "summary": entry.summary if 'summary' in entry else entry.title,
                        "source": feed.feed.title if 'title' in feed.feed else "Unknown"
                    })
            except Exception as e:
                console.print(f"[red]❌ Error fetching {url}: {e}[/red]")
        
        console.print(f"✅ Collected {len(articles)} raw intelligence items.")
        return articles

    def analyze_threats(self, articles):
        """Uses LLM to score and summarize threats."""
        analyzed_data = []

        if not self.llm:
            console.print("[dim]   (Skipping AI analysis - Demo Mode)[/dim]")
            # Return raw data for the table so the script still 'works' visually
            return [{
                "Source": a['source'],
                "Title": a['title'],
                "Risk Score": "N/A", 
                "Relevant": "Check Manually",
                "Summary": "AI Analysis Disabled (Missing Key)",
                "Link": a['link']
            } for a in articles]

        console.print("🧠 Analyzing threats against Watchlist...")
        
        system_prompt = """
        You are a Senior Threat Intelligence Analyst. 
        Analyze the provided security news article.
        1. Assign a 'Risk Score' (1-10) based on urgency.
        2. Determine if it is relevant to: {watchlist}.
        3. Provide a 1-sentence 'Executive Summary'.
        Output format: Risk_Score | Is_Relevant (Yes/No) | Executive_Summary
        """

        for article in articles:
            try:
                user_message = f"Title: {article['title']}\nSummary: {article['summary']}"
                messages = [
                    SystemMessage(content=system_prompt.format(watchlist=WATCHLIST)),
                    HumanMessage(content=user_message)
                ]
                
                response = self.llm.invoke(messages)
                content = response.content.strip()
                
                parts = content.split('|')
                if len(parts) >= 3:
                    risk = parts[0].strip()
                    rel = parts[1].strip()
                    summ = parts[2].strip()
                else:
                    risk, rel, summ = "N/A", "Unknown", content

                analyzed_data.append({
                    "Source": article['source'],
                    "Title": article['title'],
                    "Risk Score": risk,
                    "Relevant": rel,
                    "Summary": summ,
                    "Link": article['link']
                })
                print(f"   > Analyzed: {article['title'][:30]}...")

            except Exception as e:
                print(f"Error: {e}")

        return analyzed_data

    def generate_report(self, data):
        """Outputs a rich table and saves a CSV."""
        df = pd.DataFrame(data)
        
        table = Table(title="🛡️ Daily Threat Intelligence Briefing")
        table.add_column("Risk", style="red bold")
        table.add_column("Relevant?", style="cyan")
        table.add_column("Title", style="white")
        table.add_column("Executive Summary", style="green")

        for row in data:
            # Show everything in demo mode, or filter in AI mode
            if self.llm is None or row['Relevant'] == "Yes" or row['Risk Score'] in ['8', '9', '10']:
                table.add_row(
                    str(row['Risk Score']),
                    row['Relevant'],
                    row['Title'][:40] + "...",
                    row['Summary']
                )

        console.print(table)
        
        filename = f"threat_report_{datetime.now().strftime('%Y-%m-%d')}.csv"
        df.to_csv(filename, index=False)
        console.print(f"\n💾 Report saved to: [bold underline]{filename}[/bold underline]")

if __name__ == "__main__":
    agent = ThreatIntelAgent()
    raw_intel = agent.fetch_threats()
    if raw_intel:
        insights = agent.analyze_threats(raw_intel)
        agent.generate_report(insights)
