import streamlit as st
import pandas as pd
import json
import os
import time
import requests
import feedparser
import re
import uuid
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional

# ==========================================
# 1. CONFIGURATION & CONSTANTS
# ==========================================
PAGE_CONFIG = {
    "page_title": "Guardian AI | Threat Intelligence",
    "page_icon": "🛡️",
    "layout": "wide",
    "initial_sidebar_state": "expanded"
}

FILES = {
    "INVENTORY": "inventory.json",
    "ALERTS": "alerts.json",
    "TRIAGE": "triage_history.json",
    "AUDIT": "audit_log.json"
}

FEEDS = {
    "CISA": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "NIST": "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss-analyst.xml"
}

# ==========================================
# 2. CORE CLASSES (The Engine)
# ==========================================

class DataManager:
    """Handles all File I/O, Session State, and Data Sanitization."""
    
    @staticmethod
    def load_json(filepath: str, default: Any) -> Any:
        """Robust JSON loader."""
        if filepath == FILES["INVENTORY"] and "inventory" in st.secrets:
            return dict(st.secrets["inventory"])
        if not os.path.exists(filepath): 
            return default
        try:
            with open(filepath, "r") as f:
                return json.load(f)
        except json.JSONDecodeError:
            return default

    @staticmethod
    def save_json(filepath: str, data: Any):
        """Writes to disk and updates Session State cache."""
        cache_key = f"cache_{filepath}"
        st.session_state[cache_key] = data
        try:
            with open(filepath, "w") as f:
                json.dump(data, f, indent=4)
        except Exception as e:
            print(f"Warning: Write failed (Cloud Mode?): {e}")

    @staticmethod
    def sanitize_inventory(inventory: Dict) -> Dict:
        """CRITICAL FIX: Converts legacy strings to objects to prevent crashes."""
        raw_assets = inventory.get("assets", [])
        clean_assets = []
        
        for item in raw_assets:
            if isinstance(item, str):
                # Upgrade legacy string to object
                clean_assets.append({
                    "id": str(uuid.uuid4())[:8],
                    "name": item,
                    "version": "All",
                    "description": "Legacy Import",
                    "added_by": "System",
                    "date_added": datetime.now().strftime("%Y-%m-%d")
                })
            elif isinstance(item, dict):
                # Ensure 'name' exists
                if "name" in item:
                    clean_assets.append(item)
        
        inventory["assets"] = clean_assets
        return inventory

    @staticmethod
    def get_inventory() -> Dict:
        if "cache_inventory" not in st.session_state:
            raw = DataManager.load_json(FILES["INVENTORY"], {"assets": [], "threshold": 7.0})
            st.session_state["cache_inventory"] = DataManager.sanitize_inventory(raw)
        return st.session_state["cache_inventory"]

    @staticmethod
    def get_alerts() -> List[Dict]:
        if "cache_alerts" not in st.session_state:
            st.session_state["cache_alerts"] = DataManager.load_json(FILES["ALERTS"], [])
        return st.session_state["cache_alerts"]

    @staticmethod
    def get_triage() -> List[Dict]:
        if "cache_triage" not in st.session_state:
            st.session_state["cache_triage"] = DataManager.load_json(FILES["TRIAGE"], [])
        return st.session_state["cache_triage"]

    @staticmethod
    def log_audit(action: str, user: str, details: str):
        log_entry = {
            "id": str(uuid.uuid4())[:8],
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "user": user,
            "action": action,
            "details": details
        }
        logs = DataManager.load_json(FILES["AUDIT"], [])
        logs.insert(0, log_entry)
        DataManager.save_json(FILES["AUDIT"], logs[:1000])

class ThreatEngine:
    """Handles logic for fetching, parsing, and normalizing threat data."""
    
    @staticmethod
    def normalize_severity(sev_str: str) -> str:
        s = str(sev_str).upper().strip()
        if "CRIT" in s: return "CRITICAL"
        if "HIGH" in s: return "HIGH"
        if "MED" in s: return "MEDIUM"
        return "LOW"

    @staticmethod
    def extract_cvss(title: str, severity: str) -> float:
        match = re.search(r'\(([\d\.]+)', title)
        if match: return float(match.group(1))
        mapping = {"CRITICAL": 9.8, "HIGH": 7.5, "MEDIUM": 5.4, "LOW": 3.0}
        return mapping.get(severity, 0.0)

    @staticmethod
    def check_asset_match(description: str, assets: List[Dict]) -> Optional[str]:
        desc_lower = description.lower()
        for asset in assets:
            # Safe access to 'name' ensured by sanitize_inventory
            name = asset.get("name", "").lower()
            if name and name in desc_lower:
                return asset.get("name")
        return None

    @staticmethod
    def run_ingestion(lookback_days: int) -> int:
        inventory = DataManager.get_inventory()
        existing_alerts = DataManager.get_alerts()
        assets = inventory.get("assets", [])
        
        new_count = 0
        cutoff_date = datetime.now() - timedelta(days=lookback_days)
        
        def upsert_alert(cve, asset, desc, sev, cvss, source, url, date_str):
            nonlocal new_count
            try:
                if datetime.strptime(date_str, "%Y-%m-%d") < cutoff_date: return
            except: pass

            sev = ThreatEngine.normalize_severity(sev)
            if not url: url = f"https://nvd.nist.gov/vuln/detail/{cve}"

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
                    "severity": sev,
                    "cvss": float(cvss),
                    "source": source,
                    "url": url,
                    "date": date_str,
                    "status": "Active"
                }
                existing_alerts.append(new_alert)
                new_count += 1
                SlackIntegration.check_and_notify(new_alert, inventory)

        try:
            r = requests.get(FEEDS["CISA"], timeout=10)
            if r.status_code == 200:
                data = r.json()
                for item in data.get("vulnerabilities", []):
                    match = ThreatEngine.check_asset_match(item.get('product', ''), assets)
                    if match:
                        upsert_alert(item['cveID'], match, item['shortDescription'], "CRITICAL", 9.8, "CISA KEV", "", item['dateAdded'])
        except Exception as e:
            print(f"CISA Error: {e}")

        try:
            feed = feedparser.parse(FEEDS["NIST"])
            for entry in feed.entries:
                match = ThreatEngine.check_asset_match(entry.summary, assets)
                if match:
                    sev_raw = "MEDIUM"
                    if "HIGH" in entry.title.upper(): sev_raw = "HIGH"
                    if "CRITICAL" in entry.title.upper(): sev_raw = "CRITICAL"
                    score = ThreatEngine.extract_cvss(entry.title, sev_raw)
                    cve = entry.title.split()[0]
                    date_str = datetime.now().strftime("%Y-%m-%d")
                    upsert_alert(cve, match, entry.summary[:250]+"...", sev_raw, score, "NIST NVD", entry.link, date_str)
        except Exception as e:
            print(f"NIST Error: {e}")

        DataManager.save_json(FILES["ALERTS"], existing_alerts)
        DataManager.log_audit("FEED_REFRESH", "System", f"Ingested {new_count} new alerts")
        return new_count

class SlackIntegration:
    @staticmethod
    def send_notification(payload: Dict, webhook: str):
        if not webhook: return
        try:
            requests.post(webhook, json=payload, timeout=5)
        except Exception: pass

    @staticmethod
    def check_and_notify(alert: Dict, inventory: Dict):
        webhook = inventory.get("slack_webhook")
        if not webhook: return
        policy = inventory.get("slack_min_severity", "High+")
        sev_map = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        policy_map = {"Critical Only": 4, "High+": 3, "Medium+": 2, "All": 1}
        
        if sev_map.get(alert['severity'], 1) >= policy_map.get(policy, 3):
            color = "#DC2626" if "CRIT" in alert['severity'] else "#EA580C"
            payload = {
                "username": inventory.get("slack_bot_name", "Guardian AI"),
                "channel": inventory.get("slack_channel", "#security-alerts"),
                "attachments": [{
                    "color": color,
                    "title": f"🚨 {alert['severity']}: {alert['affected_asset'].upper()}",
                    "title_link": alert.get('url'),
                    "text": alert['description'],
                    "fields": [{"title": "CVE", "value": alert['cve'], "short": True}, {"title": "CVSS", "value": str(alert['cvss']), "short": True}]
                }]
            }
            SlackIntegration.send_notification(payload, webhook)

# ==========================================
# 3. UI RENDERING
# ==========================================

def render_css():
    st.markdown("""
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
        html, body, [class*="css"] { font-family: 'Inter', sans-serif; background-color: #F8FAFC; color: #0F172A; }
        h1, h2, h3 { font-weight: 700; color: #1E293B; }
        div[data-testid="stMetric"] { background-color: white; border: 1px solid #E2E8F0; border-radius: 8px; padding: 15px; box-shadow: 0 1px 3px rgba(0,0,0,0.05); }
        div.stButton > button { background-color: #0F172A; color: white; border-radius: 6px; font-weight: 600; border: none; height: 2.6rem; }
        div.stButton > button:hover { background-color: #334155; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1); }
        .badge { padding: 4px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 700; display: inline-block; margin-right: 6px; }
        .b-crit { background: #FEF2F2; color: #991B1B; border: 1px solid #FECACA; }
        .b-high { background: #FFF7ED; color: #9A3412; border: 1px solid #FED7AA; }
        .b-med  { background: #FEFCE8; color: #854D0E; border: 1px solid #FEF08A; }
        .b-low  { background: #F0FDF4; color: #166534; border: 1px solid #BBF7D0; }
    </style>
    """, unsafe_allow_html=True)

def render_sidebar():
    with st.sidebar:
        st.title("Guardian AI")
        st.caption("v4.1.0-SelfHealing")
        st.markdown("---")
        nav = st.radio("Navigation", ["Dashboard", "Asset Management", "Settings", "Audit Logs"], label_visibility="collapsed")
        st.markdown("---")
        st.markdown("**User:** Admin")
        refresh = st.selectbox("Auto-Refresh", ["Off", "30 Seconds", "5 Minutes"], index=0)
        if st.button("Log Out"):
            st.session_state.authenticated = False
            st.rerun()
        return nav, refresh

# ==========================================
# 4. MAIN APP LOGIC
# ==========================================

def main():
    st.set_page_config(**PAGE_CONFIG)
    render_css()

    if "authenticated" not in st.session_state: st.session_state.authenticated = False
    if not st.session_state.authenticated:
        _, c2, _ = st.columns([1, 1, 1])
        with c2:
            st.markdown("<br><br><br>", unsafe_allow_html=True)
            st.title("🛡️ Guardian AI")
            if st.button("Sign In with SSO", use_container_width=True):
                st.session_state.authenticated = True
                st.rerun()
        return

    nav_selection, refresh_rate = render_sidebar()
    inventory = DataManager.get_inventory()
    alerts = DataManager.get_alerts()
    triage = DataManager.get_triage()
    
    triaged_ids = {t['cve'] for t in triage}
    active_alerts = [a for a in alerts if a['cve'] not in triaged_ids]

    if nav_selection == "Dashboard":
        c1, c2 = st.columns([3, 1])
        with c1: st.title("Risk Dashboard")
        with c2:
            if st.button("🔄 Refresh Intelligence"):
                with st.spinner("Syncing Feeds..."):
                    count = ThreatEngine.run_ingestion(inventory.get("lookback_days", 90))
                    st.toast(f"Sync Complete. {count} new findings.")
                    time.sleep(1); st.rerun()

        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Assets", len(inventory.get("assets", [])))
        col2.metric("Active Threats", len(active_alerts))
        col3.metric("Critical", len([a for a in active_alerts if a['severity'] == "CRITICAL"]))
        col4.metric("Triaged", len(triage))

        st.divider()
        with st.expander("🔎 Filter & Analyze", expanded=True):
            f1, f2, f3 = st.columns(3)
            with f1: selected_sev = st.multiselect("Severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW"], default=["CRITICAL", "HIGH"])
            with f2: sort_option = st.selectbox("Sort By", ["Risk Score (CVSS)", "Recency", "Asset Name"])
            with f3: min_cvss = st.slider("Min CVSS", 0.0, 10.0, 0.0)

        if active_alerts:
            df = pd.DataFrame(active_alerts)
            df['filter_sev'] = df['severity'].str.upper()
            mask = (df['filter_sev'].isin(selected_sev)) & (df['cvss'] >= min_cvss)
            df_filtered = df[mask].copy()
            
            if "Risk" in sort_option: df_filtered = df_filtered.sort_values(by="cvss", ascending=False)
            elif "Recency" in sort_option: df_filtered = df_filtered.sort_values(by="date", ascending=False)
            elif "Asset" in sort_option: df_filtered = df_filtered.sort_values(by="affected_asset", ascending=True)
            display_alerts = df_filtered.to_dict('records')
        else:
            display_alerts = []

        t1, t2 = st.tabs([f"🔥 Active Threats ({len(display_alerts)})", "✅ Triage History"])
        with t1:
            if not display_alerts:
                if active_alerts: st.info(f"Filters active. {len(active_alerts)} threats hidden.")
                else: st.success("No active threats detected.")
            
            for alert in display_alerts:
                s = alert['severity']
                b_cls = "b-crit" if s == "CRITICAL" else "b-high" if s == "HIGH" else "b-med" if s == "MEDIUM" else "b-low"
                with st.container():
                    c_main, c_act = st.columns([4, 1.5])
                    with c_main:
                        st.markdown(f"#### {alert['affected_asset'].upper()} | {alert['cve']}")
                        st.markdown(f"<span class='badge {b_cls}'>{s}</span><span class='badge {b_cls}'>CVSS {alert['cvss']}</span>", unsafe_allow_html=True)
                        st.write(alert['description'])
                        st.caption(f"📅 Detected: {alert['date']} | Source: {alert['source']}")
                        st.markdown(f"[🔗 Intelligence Report]({alert['url']})", unsafe_allow_html=True)
                    with c_act:
                        st.write("**Action**")
                        key_base = alert['cve']
                        with st.form(key=f"triage_{key_base}"):
                            decision = st.selectbox("Decision", ["Select...", "True Positive", "False Positive", "Mitigated"], label_visibility="collapsed")
                            notes = st.text_input("Notes", placeholder="Reasoning...")
                            if st.form_submit_button("Confirm Triage"):
                                if decision != "Select...":
                                    triage_record = alert.copy()
                                    triage_record.update({"decision": decision, "notes": notes, "triaged_at": datetime.now().strftime("%Y-%m-%d %H:%M"), "triaged_by": "Admin"})
                                    triage.append(triage_record)
                                    DataManager.save_json(FILES["TRIAGE"], triage)
                                    DataManager.log_audit("TRIAGE", "Admin", f"Triaged {alert['cve']} as {decision}")
                                    st.toast("Alert moved to history."); time.sleep(0.5); st.rerun()
                    st.divider()

        with t2:
            if not triage: st.info("No history.")
            else:
                for item in reversed(triage):
                    with st.expander(f"{item['decision']}: {item['cve']} ({item['affected_asset']})"):
                        st.write(f"**Notes:** {item.get('notes', 'N/A')}")
                        if st.button("Undo Decision", key=f"undo_{item['cve']}"):
                            triage.remove(item)
                            DataManager.save_json(FILES["TRIAGE"], triage)
                            st.rerun()

    elif nav_selection == "Asset Management":
        st.title("Asset Management")
        with st.expander("➕ Register New Asset", expanded=True):
            with st.form("new_asset_form"):
                c1, c2, c3 = st.columns(3)
                name = c1.text_input("Software Name", placeholder="e.g. nginx")
                version = c2.text_input("Version", placeholder="1.21.0")
                owner = c3.text_input("Owner", placeholder="DevOps Team")
                if st.form_submit_button("Add Asset"):
                    if name:
                        inventory["assets"].append({"id": str(uuid.uuid4())[:8], "name": name, "version": version or "All", "description": owner, "added_by": "Admin", "date_added": datetime.now().strftime("%Y-%m-%d")})
                        DataManager.save_json(FILES["INVENTORY"], inventory)
                        st.success(f"Added {name}"); st.rerun()

        if inventory["assets"]:
            asset_df = pd.DataFrame(inventory["assets"])
            st.dataframe(asset_df[["name", "version", "description", "added_by", "date_added"]], use_container_width=True)
            to_delete = st.selectbox("Remove Asset", ["Select..."] + [a["name"] for a in inventory["assets"]])
            if to_delete != "Select..." and st.button(f"🗑️ Delete {to_delete}"):
                inventory["assets"] = [a for a in inventory["assets"] if a["name"] != to_delete]
                DataManager.save_json(FILES["INVENTORY"], inventory)
                st.rerun()
        else: st.info("Inventory empty.")

    elif nav_selection == "Settings":
        st.title("System Configuration")
        t1, t2 = st.tabs(["General", "Integrations"])
        with t1:
            st.subheader("Data Retention")
            days = st.selectbox("Lookback Period", [30, 90, 365, 730], index=1)
            if days != inventory.get("lookback_days"):
                inventory["lookback_days"] = days
                DataManager.save_json(FILES["INVENTORY"], inventory)
                st.toast("Saved")
            st.markdown("---")
            if st.button("🗑️ Flush All Data (Reset)", type="primary"):
                st.session_state.clear()
                for f in [FILES["ALERTS"], FILES["TRIAGE"]]:
                    if os.path.exists(f): os.remove(f)
                st.rerun()
        with t2:
            st.subheader("Slack Configuration")
            with st.form("slack_settings"):
                c1, c2 = st.columns(2)
                webhook = c1.text_input("Webhook URL", value=inventory.get("slack_webhook", ""), type="password")
                channel = c2.text_input("Channel", value=inventory.get("slack_channel", "#security-alerts"))
                c3, c4 = st.columns(2)
                bot_name = c3.text_input("Bot Name", value=inventory.get("slack_bot_name", "Guardian AI"))
                min_sev = c4.selectbox("Policy", ["Critical Only", "High+", "Medium+", "All"], index=1)
                if st.form_submit_button("Save Integration"):
                    inventory.update({"slack_webhook": webhook, "slack_channel": channel, "slack_bot_name": bot_name, "slack_min_severity": min_sev})
                    DataManager.save_json(FILES["INVENTORY"], inventory)
                    st.success("Saved")
            if inventory.get("slack_webhook") and st.button("Send Test Notification"):
                SlackIntegration.send_notification({"text": "✅ Connection Test"}, inventory["slack_webhook"])
                st.toast("Sent!")

    elif nav_selection == "Audit Logs":
        st.title("Audit Logs")
        logs = DataManager.load_json(FILES["AUDIT"], [])
        if logs: st.dataframe(pd.DataFrame(logs), use_container_width=True)
        else: st.info("No logs.")

    if refresh_rate != "Off":
        secs = {"30 Seconds": 30, "5 Minutes": 300}.get(refresh_rate, 300)
        time.sleep(secs)
        st.rerun()

if __name__ == "__main__":
    main()
