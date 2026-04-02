"""Seed data for topics, products, and feed sources."""

from src.models.database import SessionLocal, Topic, Product, FeedSource


def seed_topics(db):
    topics = [
        # Security
        {"slug": "vulnerabilities", "name": "Vulnerabilities & CVEs", "description": "Critical and high-severity CVEs from NVD and CISA KEV.", "category": "security"},
        {"slug": "ransomware", "name": "Ransomware & Malware", "description": "Ransomware campaigns, malware families, and IOCs.", "category": "security"},
        {"slug": "zero-day", "name": "Zero-Day Exploits", "description": "Actively exploited zero-day vulnerabilities.", "category": "security"},
        {"slug": "cloud-security", "name": "Cloud Security", "description": "Cloud misconfigurations, breaches, and advisories.", "category": "security"},
        {"slug": "identity-access", "name": "Identity & Access", "description": "MFA bypasses, credential stuffing, SSO vulnerabilities.", "category": "security"},
        {"slug": "supply-chain", "name": "Supply Chain Attacks", "description": "Software supply chain compromises and dependency risks.", "category": "security"},
        {"slug": "nation-state", "name": "Nation-State Threats", "description": "APT campaigns and government-attributed cyber operations.", "category": "security"},
        {"slug": "data-breaches", "name": "Data Breaches", "description": "Notable data breaches and incident disclosures.", "category": "security"},
        # Privacy
        {"slug": "us-privacy-law", "name": "US Privacy Legislation", "description": "State and federal privacy bills, CCPA/CPRA updates, and enforcement actions.", "category": "privacy"},
        {"slug": "gdpr", "name": "GDPR & International Privacy", "description": "EU/UK GDPR enforcement, fines, and regulatory guidance.", "category": "privacy"},
        {"slug": "ai-regulation", "name": "AI Regulation", "description": "AI governance legislation, EU AI Act, and US executive orders.", "category": "privacy"},
        # Compliance
        {"slug": "fedramp-govcloud", "name": "FedRAMP & GovCloud", "description": "FedRAMP authorization updates and government cloud security.", "category": "compliance"},
        {"slug": "frameworks", "name": "Frameworks & Standards", "description": "NIST, ISO, SOC 2, CJIS, and framework updates.", "category": "compliance"},
    ]
    for t in topics:
        exists = db.query(Topic).filter(Topic.slug == t["slug"]).first()
        if not exists:
            db.add(Topic(**t))


def seed_products(db):
    products = [
        # Cloud Providers
        {"slug": "aws", "name": "Amazon Web Services", "vendor": "Amazon", "category": "cloud", "advisory_url": "https://aws.amazon.com/security/security-bulletins/rss/feed/"},
        {"slug": "azure", "name": "Microsoft Azure", "vendor": "Microsoft", "category": "cloud", "advisory_url": "https://api.msrc.microsoft.com/cvrf/v3.0/updates"},
        {"slug": "gcp", "name": "Google Cloud Platform", "vendor": "Google", "category": "cloud", "advisory_url": "https://cloud.google.com/feeds/google-cloud-security-bulletins.xml"},
        # Identity
        {"slug": "okta", "name": "Okta", "vendor": "Okta", "category": "identity", "advisory_url": "https://trust.okta.com/"},
        {"slug": "entra-id", "name": "Microsoft Entra ID", "vendor": "Microsoft", "category": "identity"},
        {"slug": "duo", "name": "Cisco Duo", "vendor": "Cisco", "category": "identity"},
        # Endpoint / EDR
        {"slug": "crowdstrike", "name": "CrowdStrike Falcon", "vendor": "CrowdStrike", "category": "endpoint"},
        {"slug": "sentinelone", "name": "SentinelOne", "vendor": "SentinelOne", "category": "endpoint"},
        {"slug": "defender", "name": "Microsoft Defender", "vendor": "Microsoft", "category": "endpoint"},
        # Network
        {"slug": "palo-alto", "name": "Palo Alto Networks", "vendor": "Palo Alto", "category": "network", "advisory_url": "https://security.paloaltonetworks.com/rss.xml"},
        {"slug": "fortinet", "name": "Fortinet FortiGate", "vendor": "Fortinet", "category": "network"},
        {"slug": "cisco", "name": "Cisco (Networking)", "vendor": "Cisco", "category": "network"},
        # Collaboration
        {"slug": "microsoft-365", "name": "Microsoft 365", "vendor": "Microsoft", "category": "collaboration"},
        {"slug": "google-workspace", "name": "Google Workspace", "vendor": "Google", "category": "collaboration"},
        {"slug": "slack", "name": "Slack", "vendor": "Salesforce", "category": "collaboration"},
        {"slug": "zoom", "name": "Zoom", "vendor": "Zoom", "category": "collaboration"},
        # DevOps / Code
        {"slug": "github", "name": "GitHub", "vendor": "Microsoft", "category": "devops"},
        {"slug": "gitlab", "name": "GitLab", "vendor": "GitLab", "category": "devops"},
        # SaaS / Business
        {"slug": "salesforce", "name": "Salesforce", "vendor": "Salesforce", "category": "saas"},
        {"slug": "servicenow", "name": "ServiceNow", "vendor": "ServiceNow", "category": "saas"},
        {"slug": "atlassian", "name": "Atlassian (Jira/Confluence)", "vendor": "Atlassian", "category": "saas"},
    ]
    for p in products:
        exists = db.query(Product).filter(Product.slug == p["slug"]).first()
        if not exists:
            db.add(Product(**p))


def seed_feed_sources(db):
    sources = [
        {"name": "CISA Known Exploited Vulnerabilities", "source_type": "cisa_kev", "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "topic_slug": "vulnerabilities"},
        {"name": "NVD CVE Feed", "source_type": "nvd", "url": "https://services.nvd.nist.gov/rest/json/cves/2.0", "topic_slug": "vulnerabilities"},
        {"name": "CISA Alerts RSS", "source_type": "rss", "url": "https://www.cisa.gov/news.xml", "topic_slug": "nation-state"},
        {"name": "Krebs on Security", "source_type": "rss", "url": "https://krebsonsecurity.com/feed/", "topic_slug": "data-breaches"},
        {"name": "Bleeping Computer", "source_type": "rss", "url": "https://www.bleepingcomputer.com/feed/", "topic_slug": "ransomware"},
        {"name": "The Record by Recorded Future", "source_type": "rss", "url": "https://therecord.media/feed", "topic_slug": "nation-state"},
        {"name": "IAPP Privacy News", "source_type": "rss", "url": "https://iapp.org/rss/", "topic_slug": "us-privacy-law"},
        {"name": "GCP Security Bulletins", "source_type": "rss", "url": "https://cloud.google.com/feeds/google-cloud-security-bulletins.xml", "product_slug": "gcp"},
        {"name": "Palo Alto Security Advisories", "source_type": "rss", "url": "https://security.paloaltonetworks.com/rss.xml", "product_slug": "palo-alto"},
    ]
    for s in sources:
        exists = db.query(FeedSource).filter(FeedSource.url == s["url"]).first()
        if not exists:
            db.add(FeedSource(**s))


def run_seed():
    db = SessionLocal()
    try:
        seed_topics(db)
        seed_products(db)
        seed_feed_sources(db)
        db.commit()
        print("Seed data loaded.")
    finally:
        db.close()


if __name__ == "__main__":
    from src.models.database import init_db
    init_db()
    run_seed()
