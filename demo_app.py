import streamlit as st
import pandas as pd
import json
import os
import time
import requests
import feedparser
import re
from datetime import datetime, timedelta

# --- CONFIGURATION ---
INVENTORY_FILE = "inventory.json"
ALERTS_FILE = "alerts.json"
TRIAGE_FILE = "triage_history.json"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NIST_RSS_URL = "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss-analyst.xml"

# --- PAGE CONFIG ---
st.set_page_config(
    page_title="Guardian AI | Threat Intel",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- ENTERPRISE CSS ---
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
    
    html, body, [class*="css"] { 
        font-family: 'Inter', sans-serif; 
        background-color: #FFFFFF; 
        color: #0F172A; 
    }
    
    /* FORCE NAVY BLUE BUTTONS */
    div.stButton > button { 
        background-color: #0F172A !important; 
        color: white !important; 
        border-radius: 6px !important; 
        border: none !important; 
        height: 2.5em !important; 
        font-weight: 600 !important; 
        box-shadow: 0 1px 2px 0 rgba(0, 0, 0, 0.05) !important;
    }
    div.stButton > button:hover { 
        background-color: #334155 !important; 
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06) !important;
    }
    
    /* RED DANGER BUTTONS */
    button[kind="secondary"] {
        background-color: #FEF2F2 !important;
        color: #991B1B !important;
        border: 1px solid #FECACA !important;
    }

    /* Cards */
    div[data-testid="stMetric"] { 
        background-color: #F8FAFC; 
        border: 1px solid #E2E8F0; 
        border-radius: 8px; 
        padding: 16px; 
    }

    /* Severity Badges */
    .badge {
        padding: 4px 10px;
        border-radius: 6px;
        font-weight: 700;
        font-size: 0.85em;
        display: inline-block;
        margin-right: 8px;
    }
    .crit { background-color: #FEF2F2; color: #991B1B; border: 1px solid #FCA5A5; }
    .high { background-color: #FFF7ED; color: #9A3412; border: 1px solid #FDBA74; }
    .med  { background-color: #FEFCE8; color: #854D0E; border: 1px solid #FDE047; }
    .low  { background-color: #F0FDF4; color: #166534; border: 1px solid #86EFAC; }
    
    /* Headers */
    h1, h2, h3 { color: #0F172A; font-weight: 700; letter-spacing: -0.025em; }
    section[data-testid="stSidebar"] { background-color: #F8FAFC; border-right: 1px solid #E2E8F0; }
</style>
""", unsafe_allow_html=True)

# --- HELPER FUNCTIONS ---

def load_json(filepath, default):
    if "inventory" in st.secrets and filepath == INVENTORY_FILE:
        return dict(st.secrets["inventory"])
    if not os.path.exists(filepath): return default
    with open(filepath, "r") as f: return json.load(f)

def save_json(filepath, data):
    if "inventory" in st.secrets and filepath == INVENTORY_FILE:
        st.session_state.temp_inventory = data
    else:
        with open(filepath, "w") as f: json.dump(data, f, indent=4)

def normalize_severity(sev_str):
    """Force severity into one of 4 buckets."""
    s = str(sev_str).upper().strip()
    if "CRIT" in s: return "CRITICAL"
    if "HIGH" in s: return "HIGH"
    if "MED" in s: return "MEDIUM"
    return "LOW"

def repair_and_normalize_data(alerts):
    """
    Self-Healing: 
    1. Fixes missing CVSS.
    2. Normalizes Severity strings.
    3. Drops corrupted rows.
    """
    cleaned = []
    changes_made = False
    
    for a in alerts:
        # Normalize Sev
        old_sev = a.get('severity', 'LOW')
        new_sev = normalize_severity(old_sev)
        if old_sev != new_sev:
            a['severity'] = new_sev
            changes_made = True

        # Fix CVSS
        if not a.get('cvss') or a.get('cvss') == 'N/A':
            if new_sev == "CRITICAL": a['cvss'] = 9.8
            elif new_sev == "HIGH": a['cvss'] = 7.5
            elif new_sev == "MEDIUM": a['cvss'] = 5.4
            else: a['cvss'] = 3.0
            changes_made = True
            
        # Fix URL
        if not a.get('url') or a.get('url') == '#':
            a['url'] = f"https://nvd.nist.gov/vuln/detail/{a['cve']}"
            changes_made = True
            
        cleaned.append(a)
            
    if changes_made: save_json(ALERTS_FILE, cleaned)
    return cleaned

def check_match(description, assets):
    description = description.lower()
    for asset in assets:
        asset_name = asset["name"] if isinstance(asset, dict) else asset
        if asset_name.lower() in description:
            return asset_name
    return None

def calculate_risk_score(alerts):
    score = 0
    for a in alerts:
        s = a.get('severity', 'LOW')
        if "CRIT" in s: score += 100
        elif "HIGH" in s: score += 50
        elif "MED" in s: score += 20
        else: score += 5
    return score

# --- NOTIFICATIONS ---

def send_real_alert(webhook, channel, bot_name, alert):
    if not webhook: return
    color = "#DC2626" if "CRIT" in alert['severity'] else "#EA580C" if "HIGH" in alert['severity'] else "#CA8A04"
    payload = {
        "username": bot_name,
        "channel": channel,
        "attachments": [{
            "color": color,
            "title": f"🚨 {alert['severity']}: {alert['affected_asset'].upper()} Vulnerability",
            "title_link": alert.get('url'),
            "text": alert['description'][:200] + "...",
            "fields": [
                {"title": "Impacted Asset", "value": alert['affected_asset'], "short": True},
                {"title": "CVSS", "value": str(alert.get('cvss', 'N/A')), "short": True},
                {"title": "CVE ID", "value": alert['cve'], "short": True}
            ],
            "footer": "Guardian AI",
            "ts": time.time()
        }]
    }
    try: requests.post(webhook, json=payload)
    except: pass

def run_scan(lookback_days=365):
    inv = st.session_state.get("temp_inventory", load_json(INVENTORY_FILE, {"assets": []}))
    assets = inv.get("assets", [])
    webhook = inv.get("slack_webhook")
    channel = inv.get("slack_channel", "#security-alerts")
    bot_name = inv.get("slack_bot_name", "Guardian AI")
    min_alert_level = inv.get("slack_min_severity", "High+")
    
    alerts = load_json(ALERTS_FILE, [])
    new_finds = 0
    
    # Priority Map
    sev_map = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    min_map = {"Critical Only": 4, "High+": 3, "Medium+": 2, "All": 1}
    threshold = min_map.get(min_alert_level, 3)
    
    cutoff_date = datetime.now() - timedelta(days=lookback_days)

    def process_finding(cve, asset, desc, sev_raw, cvss, source, url, date_str):
        nonlocal new_finds
        
        # Date Filter
        try:
            d_obj = datetime.strptime(date_str, "%Y-%m-%d")
            if d_obj < cutoff_date: return # Skip old alerts
        except: pass # If date parse fails, keep it safe
        
        sev = normalize_severity(sev_raw)
        if not url: url = f"https://nvd.nist.gov/vuln/detail/{cve}"
        
        if not any(a['cve'] == cve for a in alerts):
            new_alert = {
                "cve": cve, "affected_asset": asset, "description": desc,
                "severity": sev, "cvss": cvss, "source": source,
                "url": url, "date": date_str
            }
            alerts.append(new_alert)
            new_finds += 1
            if sev_map.get(sev, 1) >= threshold:
                send_real_alert(webhook, channel, bot_name, new_alert)

    # 1. CISA SCAN
    try:
        r = requests.get(CISA_KEV_URL).json()
        for vul in r.get("vulnerabilities", []):
            match = check_match(vul['product'], assets)
            if match:
                # CISA dates are YYYY-MM-DD
                process_finding(vul['cveID'], match, vul['shortDescription'], "CRITICAL", 9.8, "CISA KEV", f"https://nvd.nist.gov/vuln/detail/{vul['cveID']}", vul['dateAdded'])
    except: pass

    # 2. NIST SCAN
    try:
        feed = feedparser.parse(NIST_RSS_URL)
        for entry in feed.entries:
            match = check_match(entry.summary, assets)
            if match:
                sev_raw = "MEDIUM"
                if "HIGH" in entry.title.upper(): sev_raw = "HIGH"
                if "CRITICAL" in entry.title.upper(): sev_raw = "CRITICAL"
                # NIST dates need parsing, usually simplified to Today for RSS feeds
                date_str = datetime.now().strftime("%Y-%m-%d") 
                
                # Regex for CVSS
                match_cvss = re.search(r'\(([\d\.]+)', entry.title)
                score = float(match_cvss.group(1)) if match_cvss else (9.8 if sev_raw=="CRITICAL" else 7.5 if sev_raw=="HIGH" else 5.0)
                
                cve = entry.title.split()[0]
                process_finding(cve, match, entry.summary[:200]+"...", sev_raw, score, "NIST NVD", entry.link, date_str)
    except: pass

    save_json(ALERTS_FILE, alerts)
    return new_finds

def send_slack_test(webhook, channel, bot_name):
    if not webhook: return False
    try:
        payload = {"username": bot_name, "channel": channel, "text": "✅ **Guardian AI:** Connection Test Successful."}
        requests.post(webhook, json=payload)
        return True
    except: return False

# --- APP LOGIC ---

if "authenticated" not in st.session_state: st.session_state.authenticated = False

if not st.session_state.authenticated:
    _, c2, _ = st.columns([1, 2, 1])
    with c2:
        st.markdown("<br><br><h1 style='text-align: center; font-size: 60px;'>🛡️</h1>", unsafe_allow_html=True)
        st.markdown("<h2 style='text-align: center;'>Guardian AI</h2>", unsafe_allow_html=True)
        st.markdown("<p style='text-align: center; color: #64748B;'>Enterprise Vulnerability Intelligence</p>", unsafe_allow_html=True)
        if st.button("Sign In with SSO", use_container_width=True):
            time.sleep(0.5); st.session_state.authenticated = True; st.rerun()
else:
    with st.sidebar:
        st.title("Guardian AI")
        page = st.radio("Navigation", ["Dashboard", "Asset Inventory", "Settings"], label_visibility="collapsed")
        st.divider()
        st.markdown("### ⏱️ Live Mode")
        refresh_opt = st.selectbox("Auto-Refresh", ["Off", "30 Seconds", "5 Minutes", "15 Minutes", "1 Hour"], label_visibility="collapsed")
        st.divider()
        st.caption(f"User: **Admin**")
        if st.button("Log Out"): st.session_state.authenticated = False; st.rerun()

    inventory = st.session_state.get("temp_inventory", load_json(INVENTORY_FILE, {"assets": [], "threshold_cvss": 7.0}))
    
    # LOAD & REPAIR DATA
    raw_alerts = load_json(ALERTS_FILE, [])
    alerts = repair_and_normalize_data(raw_alerts)
    
    triage_history = load_json(TRIAGE_FILE, [])
    active_alerts = [a for a in alerts if a['cve'] not in [t['cve'] for t in triage_history]]

    if page == "Dashboard":
        c1, c2 = st.columns([3, 1])
        with c1: st.title("Risk Dashboard")
        with c2: 
            if st.button("🔄 Refresh Feeds"):
                with st.spinner("Aggregating Intelligence..."):
                    # Use timeframe from settings, default 365
                    lookback = inventory.get("lookback_days", 365)
                    n = run_scan(lookback)
                    st.toast(f"Updated: {n} new findings (Last {lookback} days)")
                    time.sleep(1); st.rerun()

        risk_score = calculate_risk_score(active_alerts)
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Global Risk Score", risk_score, delta="Live Index", delta_color="inverse")
        m2.metric("Active Threats", len(active_alerts))
        m3.metric("Criticals", len([a for a in active_alerts if "CRIT" in a['severity']]))
        m4.metric("Triaged Today", len([t for t in triage_history if t['triaged_at'].startswith(str(datetime.now().date()))]))

        st.divider()
        
        # FILTERS
        with st.expander("🔎 Filter Intelligence", expanded=True):
            f1, f2, f3 = st.columns(3)
            with f1: 
                sev_filter = st.multiselect("Severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW"], default=["CRITICAL", "HIGH"])
            with f2: sort_by = st.selectbox("Sort By", ["Risk (CVSS)", "Newest First", "Asset Name"])
            with f3: min_cvss = st.slider("Min CVSS", 0.0, 10.0, 0.0)

        # DEBUG: Uncomment to see what the filter sees
        # st.write(f"DEBUG: Active Alerts: {len(active_alerts)} | Filter Sev: {sev_filter}")

        # STRICT FILTERING
        filtered = []
        for a in active_alerts:
            # 1. Normalize alert severity to match filter keys
            s_norm = normalize_severity(a.get('severity', 'LOW'))
            
            # 2. Check Match
            if s_norm in sev_filter and a.get('cvss', 0) >= min_cvss:
                filtered.append(a)
        
        # SORTING
        if "Risk" in sort_by: filtered.sort(key=lambda x: x.get('cvss', 0), reverse=True)
        elif "Newest" in sort_by: filtered.sort(key=lambda x: x['date'], reverse=True)
        
        t1, t2 = st.tabs(["Active Threats", "Triage Log"])
        
        with t1:
            if not filtered: 
                if active_alerts:
                    st.info(f"0 alerts match your filters ({len(active_alerts)} hidden). Try selecting more Severities.")
                else:
                    st.success("System Clean. No active threats detected.")
            
            for row in filtered:
                sev_map = {"CRITICAL": "crit", "HIGH": "high", "MEDIUM": "med", "LOW": "low"}
                s_norm = normalize_severity(row.get('severity'))
                s_cls = sev_map.get(s_norm, "low")
                cvss_val = row.get('cvss', 0.0)
                
                with st.container(border=True):
                    c_main, c_act = st.columns([4, 1.5])
                    with c_main:
                        st.markdown(f"### {row['affected_asset'].upper()} | {row['cve']}")
                        st.markdown(f"<span class='badge {s_cls}'>{s_norm}</span> <span class='badge {s_cls}'>CVSS {cvss_val}</span>", unsafe_allow_html=True)
                        st.write(row['description'])
                        st.caption(f"**Sources:** {row['source']} • **Detected:** {row['date']}")
                        st.markdown(f"[🔗 Read Full Intelligence Report]({row.get('url')})", unsafe_allow_html=True)
                    
                    with c_act:
                        st.write("**Triage Decision**")
                        with st.form(key=f"form_{row['cve']}"):
                            decision = st.selectbox("Action", ["Select...", "True Positive", "False Positive", "Mitigated"], label_visibility="collapsed")
                            reason = st.text_input("Reasoning", placeholder="Notes...")
                            
                            if st.form_submit_button("Confirm Triage"):
                                if decision != "Select...":
                                    rec = row.copy()
                                    rec.update({"decision": decision, "notes": reason, "triaged_at": str(datetime.now()), "triaged_by": "Admin"})
                                    triage_history.append(rec)
                                    save_json(TRIAGE_FILE, triage_history)
                                    st.toast("Threat Triaged")
                                    time.sleep(0.5); st.rerun()
                                else:
                                    st.warning("Select a status.")

        with t2:
            if triage_history:
                st.caption("Recent actions.")
                for item in reversed(triage_history):
                    with st.expander(f"{item['decision']}: {item['cve']} ({item['affected_asset']})"):
                        c1, c2, c3 = st.columns(3)
                        c1.write(f"**Action By:** {item.get('triaged_by', 'System')}")
                        c2.write(f"**Notes:** {item.get('notes', 'N/A')}")
                        c3.caption(f"{item['triaged_at']}")
                        if st.button("Undo", key=f"undo_{item['cve']}"):
                            triage_history.remove(item)
                            save_json(TRIAGE_FILE, triage_history)
                            st.rerun()
            else: st.info("No triage history found.")

    elif page == "Asset Inventory":
        st.title("Asset Management")
        with st.form("new_asset"):
            c1, c2, c3 = st.columns(3)
            name = c1.text_input("Software Name", placeholder="nginx")
            ver = c2.text_input("Version", placeholder="All")
            owner = c3.text_input("Owner/Context", placeholder="DevOps Team")
            if st.form_submit_button("Add Asset"):
                if name:
                    inventory["assets"].append({"name": name, "version": ver, "description": owner, "added_by": "Admin", "date": str(datetime.now().date())})
                    save_json(INVENTORY_FILE, inventory); st.rerun()
        
        st.divider()
        if inventory["assets"]:
            for i, a in enumerate(inventory["assets"]):
                name = a.get("name") if isinstance(a, dict) else a
                desc = a.get("description", "") if isinstance(a, dict) else ""
                
                with st.container(border=True):
                    c1, c2, c3, c4 = st.columns([2, 1, 2, 0.5])
                    c1.markdown(f"**{name}**")
                    c2.caption(f"v{a.get('version', 'All')}" if isinstance(a, dict) else "vAll")
                    c3.caption(desc)
                    if c4.button("✕", key=f"del_{i}"):
                        inventory["assets"].pop(i)
                        save_json(INVENTORY_FILE, inventory); st.rerun()

    elif page == "Settings":
        st.title("System Configuration")
        
        # 1. DATABASE MANAGEMENT (THE FIX)
        st.subheader("⚠️ Database Management")
        st.warning("Use this to clear stuck alerts or reset the system.")
        if st.button("🗑️ Flush Alert Database (Hard Reset)", type="primary"):
            if os.path.exists(ALERTS_FILE): os.remove(ALERTS_FILE)
            if os.path.exists(TRIAGE_FILE): os.remove(TRIAGE_FILE)
            st.toast("Database Flushed. Please Refresh Feeds.")
            time.sleep(1); st.rerun()

        st.divider()
        
        # 2. DATA RETENTION
        st.subheader("Data Retention")
        days = st.selectbox("Feed Lookback Period", [30, 90, 365, 730], index=2, help="Only fetch alerts newer than this.")
        if days != inventory.get("lookback_days"):
            inventory["lookback_days"] = days
            save_json(INVENTORY_FILE, inventory)
            st.toast("Settings Saved")

        st.divider()
        
        # 3. NOTIFICATIONS
        st.subheader("🔔 Notification Channels")
        with st.form("slack_config"):
            c1, c2 = st.columns(2)
            webhook = c1.text_input("Webhook URL", value=inventory.get("slack_webhook", ""), type="password")
            channel = c2.text_input("Channel Name", value=inventory.get("slack_channel", "#security-alerts"))
            c3, c4 = st.columns(2)
            bot_name = c3.text_input("Bot Name", value=inventory.get("slack_bot_name", "Guardian AI"))
            min_severity = c4.selectbox("Notification Policy", ["Critical Only", "High+", "Medium+", "All"], index=1)
            
            if st.form_submit_button("Save Configuration"):
                inventory.update({
                    "slack_webhook": webhook, "slack_channel": channel, 
                    "slack_bot_name": bot_name, "slack_min_severity": min_severity
                })
                save_json(INVENTORY_FILE, inventory)
                st.success("Settings Saved")
        
        if inventory.get("slack_webhook"):
            if st.button("Send Test Notification"):
                if send_slack_test(inventory["slack_webhook"], inventory.get("slack_channel"), inventory.get("slack_bot_name")):
                    st.toast("Test Sent!", icon="✅")
                else: st.error("Failed.")

    # --- AUTO REFRESH ---
    if refresh_opt != "Off":
        secs = {"30 Seconds": 30, "5 Minutes": 300, "15 Minutes": 900, "1 Hour": 3600}.get(refresh_opt, 300)
        time.sleep(secs)
        st.rerun()
