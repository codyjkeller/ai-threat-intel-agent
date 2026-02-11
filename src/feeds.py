import requests
import logging
from abc import ABC, abstractmethod
from typing import List, Optional
from dataclasses import dataclass
from datetime import datetime

logger = logging.getLogger(__name__)

# --- 1. The Enterprise Data Model ---
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

# --- 2. The Abstract Interface ---
class ThreatFeed(ABC):
    @abstractmethod
    def fetch(self) -> List[ThreatIntel]:
        """Fetch and normalize threats from this specific source."""
        pass

# --- 3. Implementation: CISA KEV ---
class CisaKevFeed(ThreatFeed):
    URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    def fetch(self) -> List[ThreatIntel]:
        logger.info("Polling CISA KEV Feed...")
        try:
            resp = requests.get(self.URL, timeout=10)
            resp.raise_for_status()
            data = resp.json()
            
            results = []
            # CISA KEV is the "Gold Standard" for Critical Action
            for item in data.get('vulnerabilities', [])[:15]: 
                results.append(ThreatIntel(
                    source_id="CISA_KEV",
                    cve_id=item.get('cveID', 'Unknown'),
                    title=item.get('vulnerabilityName', 'Unknown'),
                    product=item.get('product', 'Unknown'),
                    description=item.get('shortDescription', ''),
                    severity="CRITICAL", 
                    url=f"https://nvd.nist.gov/vuln/detail/{item.get('cveID')}",
                    date_added=item.get('dateAdded', '')
                ))
            return results
        except requests.RequestException as e:
            logger.error(f"CISA Feed Network Error: {e}")
            return []
        except Exception as e:
            logger.error(f"CISA Feed Parsing Error: {e}")
            return []

# --- 4. Implementation: AlienVault OTX ---
class AlienVaultOtxFeed(ThreatFeed):
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.base_url = "https://otx.alienvault.com/api/v1/pulses/subscribed"

    def fetch(self) -> List[ThreatIntel]:
        logger.info("Polling AlienVault OTX...")
        
        # Simulation Mode if no key provided
        if not self.api_key:
            logger.warning("No OTX API Key provided. Running in Simulation Mode.")
            return self._simulate_data()

        # TODO: Implement actual OTX API call in next sprint
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
            try:
                threats = feed.fetch()
                all_threats.extend(threats)
            except Exception as e:
                # Isolate failures so one bad feed doesn't crash the agent
                logger.error(f"Failed to fetch from {feed.__class__.__name__}: {e}")
        return all_threats
