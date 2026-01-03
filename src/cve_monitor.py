import requests
from datetime import datetime, timedelta

# NVD API Configuration
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

class CVEMonitor:
    def __init__(self, tech_stack):
        self.tech_stack = tech_stack

    def fetch_latest_cves(self):
        """Fetches CVEs published in the last 24 hours."""
        now = datetime.now()
        yesterday = now - timedelta(days=1)
        
        params = {
            "pubStartDate": yesterday.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "pubEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "resultsPerPage": 20
        }

        try:
            print(f"📡 Querying NVD for CVEs (Last 24h)...")
            response = requests.get(NVD_API_URL, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get("vulnerabilities", [])
                print(f"✅ Found {len(vulnerabilities)} new CVEs.")
                return vulnerabilities
            else:
                print(f"❌ NVD API Error: {response.status_code}")
                return []
        except Exception as e:
            print(f"❌ Connection Error: {e}")
            return []

    def filter_relevant_cves(self, vulnerabilities):
        """Simple keyword matching against tech stack."""
        matches = []
        for item in vulnerabilities:
            cve = item['cve']
            # Safely get description
            descriptions = cve.get('descriptions', [])
            desc = descriptions[0]['value'] if descriptions else "No description available"
            cve_id = cve.get('id', 'Unknown ID')
            
            for tech in self.tech_stack:
                if tech.lower() in desc.lower():
                    matches.append({
                        "id": cve_id,
                        "tech": tech,
                        "description": desc,
                        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                    })
                    break 
        
        return matches
