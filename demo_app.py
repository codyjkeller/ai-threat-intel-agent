import streamlit as st
import pandas as pd
import json
import os
import time
import requests
import feedparser
import re
import uuid
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional

# ==========================================
# 1. ENTERPRISE CONFIGURATION
# ==========================================
SYSTEM_VERSION = "v5.0.0-Fortress"
PAGE_CONFIG = {
    "page_title": "Guardian AI | Threat Intelligence",
    "page_icon": "🛡️",
    "layout": "wide",
    "initial_sidebar_state": "expanded"
}

# File Paths
FILES = {
    "INVENTORY": "inventory.json",
    "ALERTS": "alerts.json",
    "TRIAGE": "triage_history.json",
    "AUDIT": "audit_log.json"
}

# External Feeds
FEEDS = {
    "CISA_KEV": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "NIST_RSS": "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss-analyst.xml"
}

# Logging Setup
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("GuardianAI")

# ==========================================
# 2. PERSISTENCE LAYER (The Database)
# ==========================================
class DatabaseManager:
    """
    Handles all data I/O with ACID-like safety properties.
    Includes Schema Migration and Auto-Seeding.
    """
    
    @staticmethod
    def _seed_defaults() -> Dict:
        """Returns a robust default inventory if the file is missing/corrupt."""
        return {
            "assets": [
                {"id": "sys-1", "name": "nginx", "version": "1.18.0", "description": "Public Web Server", "added_by": "System", "date_added": datetime.now().strftime("%Y-%m-%d")},
                {"id": "sys-2", "name": "apache", "version": "2.4", "description": "Legacy App Server", "added_by": "System", "date_added": datetime.now().strftime("%Y-%m-%d")},
                {"id": "sys-3", "name": "ios", "version": "16.5", "description": "Mobile Fleet", "added_by": "System", "date_added": datetime.now().strftime("%Y-%m-%d")},
                {"id": "sys-4", "name": "windows", "version": "Server 2019", "description": "Domain Controllers", "added_by": "System", "date_added": datetime.now().strftime("%Y-%m-%d")},
            ],
            "threshold_cvss": 7.0,
            "lookback_days": 365,
            "slack_webhook": "",
            "slack_channel": "#security-alerts",
            "slack_bot_name": "Guardian AI"
        }

    @staticmethod
    def load_inventory() -> Dict:
        """Loads inventory with schema validation."""
        data = DatabaseManager._seed_defaults()
        
        # 1. Try Secrets (Cloud Mode)
        if "inventory" in st.secrets:
            # Merge secrets into defaults
            secret_data = dict(st.secrets["inventory"])
            data.update(secret_data)
            return DatabaseManager._migrate_schema(data)

        # 2. Try Disk
        if os.path.exists(FILES["INVENTORY"]):
            try:
                with open(FILES["INVENTORY"], "r") as f:
                    disk_data = json.load(f)
                    if disk_data: # Ensure not empty
                        data = disk_data
            except Exception as e:
                logger.error(f"Inventory Load Error: {e}")
        
        # 3. Migrate & Return
        return DatabaseManager._migrate_schema(data)

    @staticmethod
    def _migrate_schema(data: Dict) -> Dict:
        """CRITICAL FIX: repairs 'str' assets to 'dict' objects."""
        clean_assets = []
        raw_assets = data.get("assets", [])
        
        for item in raw_assets:
            if isinstance(item, str):
                # Upgrade String -> Object
                clean_assets.append({
                    "id": str(uuid.uuid4())[:8],
                    "name": item,
                    "version": "All",
                    "description": "Legacy Import",
                    "added_by": "Auto-Migration",
                    "date_added": datetime.now().strftime("%Y-%m-%d")
                })
            elif isinstance(item, dict):
                # Validate Object
                if "name" in item:
                    if "id" not in item: item["id"] = str(uuid.uuid4())[:8]
                    clean_assets.append(item)
        
        data["assets"] = clean_assets
        return data

    @staticmethod
    def save_inventory(data: Dict):
        """Persist to Session State + Disk."""
        st.session_state["inventory_cache"] = data
        try:
            with open(FILES["INVENTORY"], "w") as f:
                json.dump(data, f, indent=4)
        except Exception:
            pass # Cloud read-only filesystem handling

    @staticmethod
    def load_alerts() -> List[Dict]:
        if os.path.exists(FILES["ALERTS"]):
            try:
                with open(FILES["ALERTS"], "r") as f:
                    return json.load(f)
            except: return []
        return []

    @staticmethod
    def save_alerts(data: List[Dict]):
        st.session_state["alerts_cache"] = data
        try:
            with open(FILES["ALERTS"], "w") as f:
                json.dump(data, f, indent=4)
        except: pass

    @staticmethod
    def load_triage() -> List[Dict]:
        if os.path.exists(FILES["TRIAGE"]):
            try:
                with open(FILES["TRIAGE"], "r") as f: return json.load(f)
            except: return []
        return []

    @staticmethod
    def save_triage(data: List[Dict]):
        try:
            with open(FILES["TRIAGE"], "w") as f: json.dump(data, f, indent=4)
        except: pass

# ==========================================
# 3. INTELLIGENCE ENGINE (The Brain)
# ==========================================
class ThreatIntelEngine:
    """Handles Fetching, Parsing, and Normalizing."""

    @staticmethod
    def normalize_severity(sev_str: Any) -> str:
        s = str(sev_str).upper().strip()
        if "CRIT" in s: return "CRITICAL"
        if "HIGH" in s: return "HIGH"
        if "MED" in s: return "MEDIUM"
        return "LOW"

    @staticmethod
    def extract_cvss(title: str, severity: str) -> float:
        match = re.search(r'\(([\d\.]+)', title)
        if match: return float(match.group(1))
        
        # Heuristics
        mapping = {"CRITICAL": 9.8, "HIGH": 7.5, "MEDIUM": 5.4, "LOW": 3.0}
        return mapping.get(severity, 0.0)

    @staticmethod
    def check_asset_match(description: str, assets: List[Dict]) -> Optional[str]:
        """Case-insensitive fuzzy match."""
        desc_lower = description.lower()
        for asset in assets:
            name = asset.get("name", "###").lower() # '###' prevents empty string match
            if name in desc_lower:
                return asset.get("name")
        return None

    @staticmethod
    def run_ingestion(inventory: Dict, existing_alerts: List[Dict]) -> int:
        """
        Main Loop:
        1. Fetch Feeds
        2. Match against Inventory
        3. Normalize Data
        4. Update Database
        """
        assets = inventory.get("assets", [])
        new_count = 0
        lookback = inventory.get("lookback_days", 365)
        cutoff = datetime.now() - timedelta(days=lookback)
        
        # --- SUB-FUNCTION: UPSERT ---
        def process_finding(cve, asset, desc, sev, cvss, source, url, date_str):
            nonlocal new_count
            # Date Check
            try:
                if datetime.strptime(date_str, "%Y-%m-%d") < cutoff: return
            except: pass # Keep if date parse fails (safety)

            # Normalization
            s_norm = ThreatIntelEngine.normalize_severity(sev)
            if not url: url = f"https://nvd.nist.gov/vuln/detail/{cve}"

            # Check Duplicates
            match = next((a for a in existing_alerts if a['cve'] == cve), None)
            if match:
                if source not in match['source']:
                    match['source'] += f", {source}"
            else:
                new_alert = {
                    "id": str(uuid.uuid4()),
                    "cve": cve,
                    "affected_asset": asset,
                    "description": desc,
                    "severity": s_norm,
                    "cvss": float(cvss),
                    "source": source,
                    "url": url,
                    "date": date_str,
                    "status": "Active"
                }
                existing_alerts.append(new_alert)
                new_count += 1
                
                # Trigger Notification
                NotificationManager.dispatch(new_alert, inventory)

        # --- FEED 1: CISA KEV ---
        try:
            r = requests.get(FEEDS["CISA_KEV"], timeout=10)
            if r.status_code == 200:
                for v in r.json().get("vulnerabilities", []):
                    match = ThreatIntelEngine.check_asset_match(v.get('product', ''), assets)
                    if match:
                        process_finding(
                            v['cveID'], match, v['shortDescription'], 
                            "CRITICAL", 9.8, "CISA KEV", "", v['dateAdded']
                        )
        except Exception as e:
            logger.error(f"CISA Feed Failed: {e}")

        # --- FEED 2: NIST RSS ---
        try:
            feed = feedparser.parse(FEEDS["NIST_RSS"])
            for entry in feed.entries:
                match = ThreatIntelEngine.check_asset_match(entry.summary, assets)
                if match:
                    sev_raw = "MEDIUM"
                    t_up = entry.title.upper()
                    if "HIGH" in t_up: sev_raw = "HIGH"
                    if "CRITICAL" in t_up: sev_raw = "CRITICAL"
                    
                    score = ThreatIntelEngine.extract_cvss(entry.title, sev_raw)
                    cve = entry.title.split()[0]
                    date_str = datetime.now().strftime("%Y-%m-%d")
                    
                    process_finding(
                        cve, match, entry.summary[:300]+"...", 
                        sev_raw, score, "NIST NVD", entry.link, date_str
                    )
        except Exception as e:
            logger.error(f"NIST Feed Failed: {e}")

        # Save results
        DatabaseManager.save_alerts(existing_alerts)
        return new_count

# ==========================================
# 4. NOTIFICATION LAYER
# ==========================================
class NotificationManager:
    @staticmethod
    def dispatch(alert: Dict, inventory: Dict):
        webhook = inventory.get("slack_webhook")
        if not webhook: return 

        # Filter Logic
        policy = inventory.get("slack_min_severity", "High+")
        sev_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        policy_rank = {"Critical Only": 4, "High+": 3, "Medium+": 2, "All": 1}
        
        if sev_rank.get(alert['severity'], 1) >= policy_rank.get(policy, 3):
            NotificationManager._send_slack(webhook, alert, inventory)

    @staticmethod
    def _send_slack(webhook: str, alert: Dict, inv: Dict):
        color = "#DC2626" if "CRIT" in alert['severity'] else "#EA580C"
        payload = {
            "username": inv.get("slack_bot_name", "Guardian AI"),
            "channel": inv.get("slack_channel", "#security-alerts"),
            "attachments": [{
                "color": color,
                "title": f"🚨 {alert['severity']}: {alert['affected_asset'].upper()}",
                "text": alert['description'],
                "fields": [
                    {"title": "CVE", "value": alert['cve'], "short": True},
                    {"title": "CVSS", "value": str(alert['cvss']), "short": True}
                ],
                "footer": "Guardian AI | Threat Intel"
            }]
        }
        try: requests.post(webhook, json=payload, timeout=3)
        except: pass

# ==========================================
# 5. UI COMPONENTS & CSS
# ==========================================
def inject_css():
    st.markdown("""
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
        html, body, [class*="css"] { font-family: 'Inter', sans-serif; color: #0F172A; }
        
        /* Sidebar */
        section[data-testid="stSidebar"] { background-color: #F8FAFC; border-right: 1px solid #E2E8F0; }
        
        /* Cards */
        div[data-testid="stMetric"] { 
            background-color: #FFFFFF; 
            border: 1px solid #E2E8F0; 
            border-radius: 8px; 
            padding: 16px; 
            box-shadow: 0 1px 2px 0 rgba(0, 0, 0, 0.05); 
        }
        
        /* Navy Buttons */
        div.stButton > button {
            background-color: #0F172A !important;
            color: white !important;
            border-radius: 6px !important;
            font-weight: 600 !important;
            border: none !important;
            height: 2.6rem !important;
        }
        div.stButton > button:hover { background-color: #334155 !important; }
        
        /* Badges */
        .badge { padding: 4px 8px; border-radius: 4px; font-weight: 700; font-size: 0.75em; margin-right: 6px; }
        .crit { background: #FEF2F2; color: #991B1B; border: 1px solid #FCA5A5; }
        .high { background: #FFF7ED; color: #9A3412; border: 1px solid #FDBA74; }
        .med { background: #FEFCE8; color: #854D0E; border: 1px solid #FDE047; }
        .low { background: #F0FDF4; color: #166534; border: 1px solid #86EFAC; }
    </style>
    """, unsafe_allow_html=True)

# ==========================================
# 6. MAIN APPLICATION EXECUTION
# ==========================================
def main():
    st.set_page_config(**PAGE_CONFIG)
    inject_css()

    # --- SESSION STATE INIT ---
    if "authenticated" not in st.session_state: st.session_state.authenticated = False
    
    # 1. LOGIN SCREEN
    if not st.session_state.authenticated:
        c1, c2, c3 = st.columns([1, 1, 1])
        with c2:
            st.markdown("<br><br><h1 style='text-align: center;'>🛡️ Guardian AI</h1>", unsafe_allow_html=True)
            st.markdown("<p style='text-align: center; color: #64748B;'>Enterprise Threat Intelligence</p>", unsafe_allow_html=True)
            if st.button("Sign In with SSO", use_container_width=True):
                time.sleep(0.5); st.session_state.authenticated = True; st.rerun()
        return

    # 2. LOAD DATA (With Auto-Repair)
    if "inventory_cache" not in st.session_state:
        st.session_state.inventory_cache = DatabaseManager.load_inventory()
    if "alerts_cache" not in st.session_state:
        st.session_state.alerts_cache = DatabaseManager.load_alerts()
    if "triage_cache" not in st.session_state:
        st.session_state.triage_cache = DatabaseManager.load_triage()

    inventory = st.session_state.inventory_cache
    alerts = st.session_state.alerts_cache
    triage = st.session_state.triage_cache

    # 3. SIDEBAR
    with st.sidebar:
        st.title("Guardian AI")
        st.caption(SYSTEM_VERSION)
        st.markdown("---")
        nav = st.radio("Menu", ["Dashboard", "Asset Inventory", "Settings"], label_visibility="collapsed")
        
        st.markdown("---")
        st.markdown("**System Status**")
        st.caption("✅ Engine Online")
        st.caption(f"📦 Assets: {len(inventory.get('assets', []))}")
        st.caption(f"👁️ Lookback: {inventory.get('lookback_days')} days")
        
        st.markdown("---")
        refresh = st.selectbox("Live Mode", ["Off", "30 Seconds", "5 Minutes"], index=0)
        if st.button("Log Out"): st.session_state.authenticated = False; st.rerun()

    # ----------------------------------------------------
    # TAB: DASHBOARD
    # ----------------------------------------------------
    if nav == "Dashboard":
        c1, c2 = st.columns([3, 1])
        with c1: st.title("Risk Dashboard")
        with c2:
            if st.button("🔄 Refresh Intelligence"):
                with st.spinner("Syncing Feeds..."):
                    n = ThreatIntelEngine.run_ingestion(inventory, alerts)
                    st.toast(f"Sync Complete: {n} new threats found.")
                    time.sleep(1); st.rerun()

        # FILTERING ENGINE
        triaged_cves = {t['cve'] for t in triage}
        active_alerts = [a for a in alerts if a['cve'] not in triaged_cves]

        # Metrics
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Monitored Assets", len(inventory.get("assets", [])))
        m2.metric("Active Threats", len(active_alerts))
        m3.metric("Criticals", len([a for a in active_alerts if a['severity'] == "CRITICAL"]))
        m4.metric("Triaged", len(triage))

        st.divider()

        # Filters
        with st.expander("🔎 Filter & Analyze", expanded=True):
            f1, f2, f3 = st.columns(3)
            with f1: 
                selected_sev = st.multiselect("Severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW"], default=["CRITICAL", "HIGH"])
            with f2: 
                sort_by = st.selectbox("Sort By", ["Risk Score", "Recency", "Asset Name"])
            with f3: 
                min_cvss = st.slider("CVSS Threshold", 0.0, 10.0, 0.0)

        # APPLY FILTERS (Pandas)
        if active_alerts:
            df = pd.DataFrame(active_alerts)
            df['filter_sev'] = df['severity'].str.upper()
            
            mask = (df['filter_sev'].isin(selected_sev)) & (df['cvss'] >= min_cvss)
            df_filtered = df[mask].copy()
            
            if "Risk" in sort_by: df_filtered = df_filtered.sort_values(by="cvss", ascending=False)
            elif "Recency" in sort_by: df_filtered = df_filtered.sort_values(by="date", ascending=False)
            
            display_list = df_filtered.to_dict('records')
        else:
            display_list = []

        # RENDER FEED
        t1, t2 = st.tabs([f"🔥 Active Threats ({len(display_list)})", "✅ Triage Log"])
        
        with t1:
            if not display_list:
                if active_alerts: st.info(f"Filters hidden {len(active_alerts)} alerts. Clear filters to see all.")
                else: st.success("No active threats found matching your assets.")
            
            for row in display_list:
                s = row['severity']
                cls = "crit" if s == "CRITICAL" else "high" if s == "HIGH" else "med" if s == "MEDIUM" else "low"
                
                with st.container():
                    c_main, c_act = st.columns([4, 1.5])
                    with c_main:
                        st.markdown(f"#### {row['affected_asset'].upper()} | {row['cve']}")
                        st.markdown(f"<span class='badge {cls}'>{s}</span><span class='badge {cls}'>CVSS {row['cvss']}</span>", unsafe_allow_html=True)
                        st.write(row['description'])
                        st.caption(f"Detected: {row['date']} | Source: {row['source']}")
                        st.markdown(f"[🔗 Read Report]({row['url']})", unsafe_allow_html=True)
                    
                    with c_act:
                        st.write("**Triage**")
                        key_base = row['cve']
                        with st.form(key=f"trg_{key_base}"):
                            dec = st.selectbox("Action", ["Select...", "True Positive", "False Positive", "Mitigated"], label_visibility="collapsed")
                            note = st.text_input("Note", placeholder="Reasoning...")
                            if st.form_submit_button("Confirm"):
                                if dec != "Select...":
                                    t_rec = row.copy()
                                    t_rec.update({"decision": dec, "notes": note, "triaged_at": str(datetime.now())})
                                    triage.append(t_rec)
                                    DatabaseManager.save_triage(triage)
                                    st.toast("Triaged!"); time.sleep(0.5); st.rerun()
                    st.divider()

        with t2:
            if not triage: st.info("No history.")
            for t in reversed(triage):
                with st.expander(f"{t['decision']}: {t['cve']} ({t['affected_asset']})"):
                    st.write(f"Note: {t.get('notes')}")
                    if st.button("Undo", key=f"undo_{t['cve']}"):
                        triage.remove(t)
                        DatabaseManager.save_triage(triage)
                        st.rerun()

    # ----------------------------------------------------
    # TAB: ASSET MANAGEMENT (Full Featured)
    # ----------------------------------------------------
    elif nav == "Asset Inventory":
        st.title("Asset Management")
        
        with st.expander("➕ Register New Asset", expanded=True):
            with st.form("add_asset"):
                c1, c2, c3 = st.columns(3)
                n = c1.text_input("Software Name", placeholder="nginx")
                v = c2.text_input("Version", placeholder="1.21")
                o = c3.text_input("Owner/Context", placeholder="DevOps")
                if st.form_submit_button("Add Asset"):
                    if n:
                        new_asset = {
                            "id": str(uuid.uuid4())[:8],
                            "name": n,
                            "version": v or "All",
                            "description": o,
                            "added_by": "Admin",
                            "date_added": datetime.now().strftime("%Y-%m-%d")
                        }
                        inventory["assets"].append(new_asset)
                        DatabaseManager.save_inventory(inventory)
                        st.success(f"Added {n}")
                        st.rerun()

        if inventory["assets"]:
            # Display as nice dataframe
            df = pd.DataFrame(inventory["assets"])
            cols = ["name", "version", "description", "added_by", "date_added"]
            # Filter available cols just in case
            df_show = df[[c for c in cols if c in df.columns]]
            
            st.dataframe(
                df_show, 
                use_container_width=True,
                column_config={"name": "Software", "version": "Version", "description": "Context"}
            )
            
            # Deletion
            st.markdown("### Actions")
            to_del = st.selectbox("Select Asset to Remove", ["Select..."] + [a['name'] for a in inventory["assets"]])
            if to_del != "Select..." and st.button(f"🗑️ Delete {to_del}"):
                inventory["assets"] = [a for a in inventory["assets"] if a['name'] != to_del]
                DatabaseManager.save_inventory(inventory)
                st.rerun()
        else:
            st.info("Inventory is empty. Add assets to start monitoring.")

    # ----------------------------------------------------
    # TAB: SETTINGS
    # ----------------------------------------------------
    elif nav == "Settings":
        st.title("System Configuration")
        
        st.subheader("Data Management")
        if st.button("🗑️ Flush & Re-Seed Database (Hard Reset)", type="primary"):
            st.session_state.clear()
            if os.path.exists(FILES["ALERTS"]): os.remove(FILES["ALERTS"])
            if os.path.exists(FILES["TRIAGE"]): os.remove(FILES["TRIAGE"])
            if os.path.exists(FILES["INVENTORY"]): os.remove(FILES["INVENTORY"])
            st.toast("System Reset & Seeded.")
            time.sleep(1); st.rerun()

        st.divider()
        st.subheader("Integrations")
        with st.form("slack_conf"):
            c1, c2 = st.columns(2)
            webhook = c1.text_input("Slack Webhook URL", value=inventory.get("slack_webhook", ""), type="password")
            channel = c2.text_input("Channel", value=inventory.get("slack_channel", "#security-alerts"))
            c3, c4 = st.columns(2)
            bot = c3.text_input("Bot Name", value=inventory.get("slack_bot_name", "Guardian AI"))
            pol = c4.selectbox("Notification Policy", ["Critical Only", "High+", "Medium+", "All"], index=1)
            
            if st.form_submit_button("Save Integration"):
                inventory.update({
                    "slack_webhook": webhook, "slack_channel": channel,
                    "slack_bot_name": bot, "slack_min_severity": pol
                })
                DatabaseManager.save_inventory(inventory)
                st.success("Configuration Saved")

        if inventory.get("slack_webhook"):
            if st.button("Send Test Notification"):
                payload = {"text": "✅ **Guardian AI:** Connection established."}
                requests.post(inventory["slack_webhook"], json=payload)
                st.toast("Test Sent!")

    # Auto Refresh
    if refresh != "Off":
        secs = {"30 Seconds": 30, "5 Minutes": 300}.get(refresh, 300)
        time.sleep(secs)
        st.rerun()

if __name__ == "__main__":
    main()
