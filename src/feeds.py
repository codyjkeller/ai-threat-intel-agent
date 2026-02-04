import requests
from abc import ABC, abstractmethod
from typing import List, Optional
from dataclasses import dataclass, asdict
from rich.console import Console
from datetime import datetime

console = Console()

# --- 1. The Enterprise Data Model ---
# We use @dataclass to enforce a strict schema for all threats, 
# no matter which messy API they came from.
@dataclass
class ThreatIntel:
    source_id: str
    cve_id: str
    title: str
    product: str
    description: str
    severity: str  # Normalized: CRITICAL, HIGH, MEDIUM, LOW
    url: str
    date_added: str

# --- 2. The Abstract Interface (The Contract) ---
class ThreatFeed(ABC):
    @abstractmethod
    def fetch(self) -> List[ThreatIntel]:
        """Fetch and normalize threats from this specific source."""
        pass

# --- 3. Implementation: CISA KEV ---
class CisaKevFeed(ThreatFeed):
    URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    def fetch(self) -> List[ThreatIntel]:
        console.print(f"[cyan]📡 Polling CISA KEV Feed...[/cyan]")
        try:
            resp = requests.get(self.URL, timeout=10)
            resp.raise_for_status()
            data = resp.json()
            
            results = []
            # We treat CISA KEV as the "Gold Standard" for Critical
            for item in data.get('vulnerabilities', [])[:15]: # Limit for performance
                results.append(ThreatIntel(
                    source_id="CISA_KEV",
                    cve_id=item.get('cveID'),
                    title=item.get('vulnerabilityName'),
                    product=item.get('product'),
                    description=item.get('shortDescription'),
                    severity="CRITICAL", 
                    url=f"https://nvd.nist.gov/vuln/detail/{item.get('cveID')}",
                    date_added=item.get('dateAdded')
                ))
            return results
        except Exception as e:
            console.print(f"[bold red]❌ CISA Feed Error: {e}[/bold red]")
            return []

# --- 4. Implementation: AlienVault OTX (The New Skeleton) ---
class AlienVaultOtxFeed(ThreatFeed):
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.base_url = "https://otx.alienvault.com/api/v1/pulses/subscribed"

    def fetch(self) -> List[ThreatIntel]:
        console.print(f"[cyan]👽 Polling AlienVault OTX (Skeleton)...[/cyan]")
        
        # Real logic would go here. For now, we simulate to prove the architecture.
        if not self.api_key:
            return self._simulate_data()

        # TODO: Implement actual OTX API call
        # headers = {'X-OTX-API-KEY': self.api_key}
        # resp = requests.get(self.base_url, headers=headers)
        return []

    def _simulate_data(self) -> List[ThreatIntel]:
        """Mock data to demonstrate multi-feed aggregation."""
        return [
            ThreatIntel(
                source_id="ALIEN_VAULT",
                cve_id="OTX-2025-ALERT",
                title="Threat Actor Activity: APT29 Financial Targeting",
                product="Banking Infrastructure",
                description="AlienVault OTX has detected increased signaling against SWIFT endpoints.",
                severity="HIGH",
                url="https://otx.alienvault.com/pulse/123456",
                date_added=datetime.now().strftime("%Y-%m-%d")
            )
        ]

# --- 5. The Factory (Aggregator) ---
class FeedAggregator:
    def __init__(self, otx_key: Optional[str] = None):
        self.feeds: List[ThreatFeed] = [
            CisaKevFeed(),
            AlienVaultOtxFeed(api_key=otx_key)
        ]

    def collect_all(self) -> List[ThreatIntel]:
        """Iterates through all registered feeds and aggregates findings."""
        all_threats = []
        for feed in self.feeds:
            # We catch errors per feed so one bad API doesn't crash the whole agent
            try:
                threats = feed.fetch()
                all_threats.extend(threats)
            except Exception as e:
                console.print(f"[red]⚠️ Failed to fetch from {feed.__class__.__name__}: {e}[/red]")
        return all_threats
