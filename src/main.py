import os
from dotenv import load_dotenv
from rich.console import Console
from cve_monitor import CVEMonitor
from notifier import send_slack_alert
# Note: If you want to keep RSS feeds, you can import your old classes here, 
# but for this "Product" version, we are focusing on the NVD/Slack workflow.

# Load env vars
load_dotenv()
console = Console()

# 1. Configuration - Define your tech stack here
WATCHLIST = ["Kubernetes", "AWS", "Python", "React", "PostgreSQL", "Java"]

def main():
    console.print("[bold blue]🛡️  Starting AI Threat & Vulnerability Monitor...[/bold blue]")

    # 2. Run NVD Check (The "Professional" Part)
    # This calls the new module you created in cve_monitor.py
    monitor = CVEMonitor(WATCHLIST)
    raw_cves = monitor.fetch_latest_cves()
    
    if raw_cves:
        # Filter down to only what matters
        threats = monitor.filter_relevant_cves(raw_cves)
        
        if threats:
            console.print(f"[red]🚨 Detected {len(threats)} Critical Vulnerabilities matching stack![/red]")
            for t in threats:
                console.print(f"   - {t['id']} ({t['tech']}): {t['description'][:50]}...")
                
                # 3. Fire the Slack Alert
                # This calls the new module in notifier.py
                send_slack_alert(t)
        else:
            console.print("[green]✅ No immediate NVD threats found for your stack today.[/green]")
    else:
        console.print("[yellow]⚠️  No data returned from NVD (or no new CVEs in last 24h).[/yellow]")

if __name__ == "__main__":
    main()
