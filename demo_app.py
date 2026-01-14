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
    
    /* NAVY BUTTONS */
    div.stButton > button { 
        background-color: #0F172A !important; 
        color: white !important; 
        border-radius: 6px !important; 
        border: none !important; 
        height: 2.5em !important; 
        font-weight: 600 !important; 
    }
    
    /* SEVERITY BADGES */
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
    
    section[data-testid="stSidebar"] { background-color: #F8FAFC; border-right: 1px solid #E2E8F0; }
</style>
""", unsafe_allow_html=True)

# --- HELPER FUNCTIONS ---

def load_json(filepath, default):
    if "inventory" in st.secrets and filepath == INVENTORY_FILE:
        return dict(st.secrets["inventory"])
    if not os.path.exists(filepath): return default
    try:
        with open(filepath, "r") as f: return json.load(f)
    except: return default

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
    """Self-Healing: Fixes missing CVSS and normalizes Severity."""
    cleaned = []
    changes_made = False
    
    for a in alerts:
        old_sev = a.get('severity', 'LOW')
        new_sev = normalize_severity(old_sev)
        
        # Repair Score
        score = a.get('cvss')
        if not score or score == 'N/A' or score == 0.0:
            if new_sev == "CRITICAL": a['cvss'] = 9.8
            elif new_sev == "HIGH": a['cvss'] = 7.5
            elif new_sev == "MEDIUM": a['cvss'] = 5.4
            else: a['cvss'] = 3.0
            changes_made = True
        
        # Repair URL
        if not a.get('url') or a.get('url') == '#':
            a['url'] = f"https://nvd.nist.gov/vuln/detail/{a['cve']}"
            changes_made = True
            
        a['severity'] = new_sev
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
        s = normalize_severity(a.get('severity', 'LOW'))
        if s == "CRITICAL": score += 100
        elif s == "HIGH": score += 50
        elif s == "MEDIUM": score += 20
        else: score += 5
    return score

# --- NOTIFICATIONS ---

def send_real_alert(webhook, channel, bot_name, alert):
    if not webhook: return
    color = "#DC2626" if "CRIT" in alert['severity'] else "#EA580C"
    payload = {
        "username": bot_name, "channel": channel,
        "attachments": [{
            "color": color,
            "title": f"🚨 {alert['severity']}: {alert['affected_asset'].upper()}",
            "title_link": alert.get('url'),
            "text": alert['description'][:200] + "...",
            "fields": [
                {"title": "CVE", "value": alert['cve'], "short": True},
                {"title": "CVSS", "value": str(alert.get('cvss')), "short": True}
            ],
            "footer": "Guardian AI",
            "ts": time.time()
        }]
    }
    try: requests.post(webhook, json=payload)
    except: pass

def run_scan(lookback_days=90):
    inv = st.session_state.get("temp_inventory", load_json(INVENTORY_FILE, {"assets": []}))
    assets = inv.get("assets", [])
    webhook = inv.get("slack_webhook")
    channel = inv.get("slack_channel", "#security-alerts")
    bot_name = inv.get("slack_bot_name", "Guardian AI")
    
    alerts = load_json(ALERTS_FILE, [])
    new_finds = 0
    cutoff = datetime.now() - timedelta(days=lookback_days)

    def add_alert(cve, asset, desc, sev, cvss, source, url, date_str):
        nonlocal new_finds
        # 1. Date Filter
        try:
            if datetime.strptime(date_str, "%Y-%m-%d") < cutoff: return
        except: pass
        
        # 2. Strict Normalization
        s_norm = normalize_severity(sev)
        if not url: url = f"https://nvd.nist.gov/vuln/detail/{cve}"
        
        if not any(a['cve'] == cve for a in alerts):
            new_alert = {
                "cve": cve, "affected_asset": asset, "description": desc,
                "severity": s_norm, "cvss": cvss, "source": source,
                "url": url, "date": date_str
            }
            alerts.append(new_alert)
            new_finds += 1
            if s_norm in ["CRITICAL", "HIGH"]:
                send_real_alert(webhook, channel, bot_name, new_alert)

    # CISA KEV
    try:
        r = requests.get(CISA_KEV_URL).json()
        for vul in r.get("vulnerabilities", []):
            match = check_match(vul['product'], assets)
            if match:
                add_alert(vul['cveID'], match, vul['shortDescription'], "CRITICAL", 9.8, "CISA KEV", "", vul['dateAdded'])
    except: pass

    # NIST RSS
    try:
        feed = feedparser.parse(NIST_RSS_URL)
        for entry in feed.entries:
            match = check_match(entry.summary, assets)
            if match:
                sev = "MEDIUM"
                if "HIGH" in entry.title.upper(): sev = "HIGH"
                if "CRITICAL" in entry.title.upper(): sev = "CRITICAL"
                
                match_cvss = re.search(r'\(([\d\.]+)', entry.title)
                score = float(match_cvss.group(1)) if match_cvss else (9.8 if sev=="CRITICAL" else 7.5)
                
                cve = entry.title.split()[0]
                date = datetime.now().strftime("%Y-%m-%d")
                add_alert(cve, match, entry.summary[:200]+"...", sev, score, "NIST NVD", entry.link, date)
    except: pass

    save_json(ALERTS_FILE, alerts)
    return new_finds

def send_slack_test(webhook, channel, bot_name):
    if not webhook: return False
    try:
        requests.post(webhook, json={"username": bot_name, "channel": channel, "text": "✅ **Guardian AI:** Test Successful."})
        return True
    except: return False

# --- APP LOGIC ---

if "authenticated" not in st.session_state: st.session_state.authenticated = False

if not st.session_state.authenticated:
    _, c2, _ = st.columns([1, 2, 1])
    with c2:
        st.markdown("<br><br><h1 style='text-align: center; font-size: 60px;'>🛡️</h1>", unsafe_allow_html=True)
        st.markdown("<h2 style='text-align: center;'>Guardian AI</h2>", unsafe_allow_html=True)
        if st.button("Sign In with SSO", use_container_width=True):
            time.sleep(0.5); st.session_state.authenticated = True; st.rerun()
else:
    with st.sidebar:
        st.title("Guardian AI")
        page = st.radio("Navigation", ["Dashboard", "Asset Inventory", "Settings"], label_visibility="collapsed")
        st.divider()
        st.markdown("### ⏱️ Live Mode")
        refresh_opt = st.selectbox("Auto-Refresh", ["Off", "30 Seconds", "5 Minutes", "1 Hour"], label_visibility="collapsed")
        st.divider()
        st.caption(f"v3.0.0-Stable") # VERIFY THIS APPEARS
        if st.button("Log Out"): st.session_state.authenticated = False; st.rerun()

    inventory = st.session_state.get("temp_inventory", load_json(INVENTORY_FILE, {"assets": [], "threshold_cvss": 7.0}))
    
    # LOAD & REPAIR
    raw_alerts = load_json(ALERTS_FILE, [])
    alerts = repair_and_normalize_data(raw_alerts)
    triage_history = load_json(TRIAGE_FILE, [])
    active_alerts = [a for a in alerts if a['cve'] not in [t['cve'] for t in triage_history]]

    if page == "Dashboard":
        c1, c2 = st.columns([3, 1])
        with c1: st.title("Risk Dashboard")
        with c2: 
            if st.button("🔄 Refresh Feeds"):
                with st.spinner("Scanning..."):
                    lb = inventory.get("lookback_days", 90)
                    n = run_scan(lb)
                    st.toast(f"Found {n} new threats (Last {lb} days)")
                    time.sleep(1); st.rerun()

        risk_score = calculate_risk_score(active_alerts)
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Risk Score", risk_score, delta="Live Index", delta_color="inverse")
        m2.metric("Active Threats", len(active_alerts))
        m3.metric("Criticals", len([a for a in active_alerts if a['severity'] == "CRITICAL"]))
        m4.metric("Triaged Today", len([t for t in triage_history if t['triaged_at'].startswith(str(datetime.now().date()))]))

        st.divider()
        
        with st.expander("🔎 Filter Intelligence", expanded=True):
            f1, f2, f3 = st.columns(3)
            with f1: 
                sev_filter = st.multiselect("Severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW"], default=["CRITICAL", "HIGH"])
            with f2: sort_by = st.selectbox("Sort By", ["Risk (CVSS)", "Newest First", "Asset Name"])
            with f3: min_cvss = st.slider("Min CVSS", 0.0, 10.0, 0.0)

        # DEBUG FILTER
        filtered = [
            a for a in active_alerts 
            if a['severity'] in sev_filter # Strict exact match
            and a.get('cvss', 0) >= min_cvss
        ]
        
        if "Risk" in sort_by: filtered.sort(key=lambda x: x.get('cvss', 0), reverse=True)
        elif "Newest" in sort_by: filtered.sort(key=lambda x: x['date'], reverse=True)
        
        t1, t2 = st.tabs([f"Active Threats ({len(filtered)})", "Triage Log"])
        
        with t1:
            if not filtered: 
                if active_alerts:
                    st.info(f"Filters hidden {len(active_alerts)} alerts. Showing 0.")
                else:
                    st.success("System Clean. No active threats detected.")
            
            for row in filtered:
                s_norm = row['severity']
                s_cls = "crit" if s_norm == "CRITICAL" else "high" if s_norm == "HIGH" else "med" if s_norm == "MEDIUM" else "low"
                
                with st.container(border=True):
                    c_main, c_act = st.columns([4, 1.5])
                    with c_main:
                        st.markdown(f"### {row['affected_asset'].upper()} | {row['cve']}")
                        st.markdown(f"<span class='badge {s_cls}'>{s_norm}</span> <span class='badge {s_cls}'>CVSS {row['cvss']}</span>", unsafe_allow_html=True)
                        st.write(row['description'])
                        st.caption(f"**Sources:** {row['source']} • **Detected:** {row['date']}")
                        st.markdown(f"[🔗 Read Intelligence Report]({row['url']})", unsafe_allow_html=True)
                    
                    with c_act:
                        st.write("**Triage**")
                        with st.form(key=f"form_{row['cve']}"):
                            decision = st.selectbox("Action", ["Select...", "True Positive", "False Positive", "Mitigated"], label_visibility="collapsed")
                            reason = st.text_input("Reasoning", placeholder="Notes...")
                            if st.form_submit_button("Confirm"):
                                if decision != "Select...":
                                    rec = row.copy()
                                    rec.update({"decision": decision, "notes": reason, "triaged_at": str(datetime.now()), "triaged_by": "Admin"})
                                    triage_history.append(rec)
                                    save_json(TRIAGE_FILE, triage_history)
                                    st.rerun()

        with t2:
            if triage_history:
                for item in reversed(triage_history):
                    with st.expander(f"{item['decision']}: {item['cve']}"):
                        st.write(f"**Notes:** {item.get('notes')}")
                        if st.button("Undo", key=f"undo_{item['cve']}"):
                            triage_history.remove(item)
                            save_json(TRIAGE_FILE, triage_history)
                            st.rerun()
            else: st.info("Empty.")

    elif page == "Asset Inventory":
        st.title("Asset Management")
        with st.form("new_asset"):
            c1, c2, c3 = st.columns(3)
            name = c1.text_input("Software Name", placeholder="nginx")
            ver = c2.text_input("Version", placeholder="All")
            owner = c3.text_input("Context", placeholder="DevOps Team")
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
        
        st.subheader("Data Management")
        if st.button("🗑️ Flush Alert Database (Hard Reset)", type="primary"):
            if os.path.exists(ALERTS_FILE): os.remove(ALERTS_FILE)
            if os.path.exists(TRIAGE_FILE): os.remove(TRIAGE_FILE)
            st.toast("Database Flushed.")
            time.sleep(1); st.rerun()

        st.divider()
        st.subheader("Data Retention")
        days = st.selectbox("Feed Lookback (Days)", [30, 90, 365], index=1)
        if days != inventory.get("lookback_days"):
            inventory["lookback_days"] = days
            save_json(INVENTORY_FILE, inventory)
            st.toast("Saved")

        st.subheader("Integrations")
        with st.form("slack_config"):
            c1, c2 = st.columns(2)
            webhook = c1.text_input("Webhook URL", value=inventory.get("slack_webhook", ""), type="password")
            channel = c2.text_input("Channel", value=inventory.get("slack_channel", "#security-alerts"))
            if st.form_submit_button("Save"):
                inventory.update({"slack_webhook": webhook, "slack_channel": channel})
                save_json(INVENTORY_FILE, inventory)
                st.success("Saved")
        
        if inventory.get("slack_webhook"):
            if st.button("Send Test Notification"):
                if send_slack_test(inventory["slack_webhook"], inventory.get("slack_channel"), "Guardian AI"):
                    st.toast("Sent!", icon="✅")
                else: st.error("Failed.")

    if refresh_opt != "Off":
        secs = {"30 Seconds": 30, "5 Minutes": 300, "15 Minutes": 900, "1 Hour": 3600}.get(refresh_opt, 300)
        time.sleep(secs)
        st.rerun()
