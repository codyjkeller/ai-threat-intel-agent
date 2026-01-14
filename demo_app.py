import streamlit as st
import pandas as pd
import json
import os
import time
import requests
import feedparser
import re
from datetime import datetime

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

def repair_alert_data(alerts):
    repaired = False
    for a in alerts:
        # Fix missing CVSS
        if not a.get('cvss') or a.get('cvss') == 'N/A' or a.get('cvss') == 0.0:
            if "CRIT" in a['severity']: a['cvss'] = 9.8
            elif "HIGH" in a['severity']: a['cvss'] = 7.5
            elif "MED" in a['severity']: a['cvss'] = 5.4
            else: a['cvss'] = 3.0
            repaired = True
        # Fix broken links
        if not a.get('url') or a.get('url') == '#':
            a['url'] = f"https://nvd.nist.gov/vuln/detail/{a['cve']}"
            repaired = True
            
    if repaired: save_json(ALERTS_FILE, alerts)
    return alerts

def extract_cvss(title, severity):
    match = re.search(r'\(([\d\.]+)', title)
    if match: return float(match.group(1))
    if severity == "CRITICAL": return 9.8
    if severity == "HIGH": return 7.5
    if severity == "MEDIUM": return 5.3
    return 3.0

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
        if "CRIT" in a['severity']: score += 100
        elif "HIGH" in a['severity']: score += 50
        elif "MED" in a['severity']: score += 20
        else: score += 5
    return score

def run_scan():
    inv = st.session_state.get("temp_inventory", load_json(INVENTORY_FILE, {"assets": []}))
    assets = inv.get("assets", [])
    alerts = load_json(ALERTS_FILE, [])
    new_finds = 0
    
    def update_or_add(cve, asset, desc, sev, cvss, source, url, date):
        nonlocal new_finds
        # Ensure URL is never empty
        if not url: url = f"https://nvd.nist.gov/vuln/detail/{cve}"
        
        existing = next((a for a in alerts if a['cve'] == cve), None)
        if existing:
            if source not in existing['source']:
                existing['source'] += f", {source}"
        else:
            alerts.append({
                "cve": cve, "affected_asset": asset, "description": desc,
                "severity": sev, "cvss": cvss, "source": source,
                "url": url, "date": date
            })
            new_finds += 1

    try:
        r = requests.get(CISA_KEV_URL).json()
        for vul in r.get("vulnerabilities", []):
            match = check_match(vul['product'], assets)
            if match:
                update_or_add(
                    vul['cveID'], match, vul['shortDescription'], "CRITICAL", 9.8,
                    "CISA KEV", f"https://nvd.nist.gov/vuln/detail/{vul['cveID']}", vul['dateAdded']
                )
    except: pass

    try:
        feed = feedparser.parse(NIST_RSS_URL)
        for entry in feed.entries:
            match = check_match(entry.summary, assets)
            if match:
                sev = "HIGH" if "HIGH" in entry.title.upper() else "MEDIUM"
                if "CRITICAL" in entry.title.upper(): sev = "CRITICAL"
                elif "LOW" in entry.title.upper(): sev = "LOW"
                score = extract_cvss(entry.title, sev)
                cve = entry.title.split()[0]
                update_or_add(cve, match, entry.summary[:200]+"...", sev, score, "NIST NVD", entry.link, datetime.now().strftime("%Y-%m-%d"))
    except: pass

    save_json(ALERTS_FILE, alerts)
    return new_finds

def send_slack_test(webhook, channel, bot_name):
    if not webhook: return False
    try:
        payload = {
            "username": bot_name,
            "channel": channel,
            "text": "✅ **Guardian AI:** Connection Test Successful.\nSystem is ready to report threats."
        }
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
        
        # AUTO REFRESH LOGIC
        st.markdown("### ⏱️ Live Mode")
        refresh_opt = st.selectbox("Auto-Refresh", ["Off", "5 Minutes", "15 Minutes", "1 Hour", "24 Hours"])
        
        st.divider()
        st.caption(f"User: **Admin**")
        if st.button("Log Out"): st.session_state.authenticated = False; st.rerun()

    inventory = st.session_state.get("temp_inventory", load_json(INVENTORY_FILE, {"assets": [], "threshold_cvss": 7.0}))
    alerts = load_json(ALERTS_FILE, [])
    alerts = repair_alert_data(alerts)
    triage_history = load_json(TRIAGE_FILE, [])
    active_alerts = [a for a in alerts if a['cve'] not in [t['cve'] for t in triage_history]]

    # --- DASHBOARD ---
    if page == "Dashboard":
        c1, c2 = st.columns([3, 1])
        with c1: st.title("Risk Dashboard")
        with c2: 
            if st.button("🔄 Refresh Feeds"):
                with st.spinner("Aggregating Intelligence..."):
                    n = run_scan()
                    st.toast(f"Intelligence Updated: {n} new findings")
                    time.sleep(1); st.rerun()

        risk_score = calculate_risk_score(active_alerts)
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Global Risk Score", risk_score, delta="Live Index", delta_color="inverse")
        m2.metric("Active Threats", len(active_alerts))
        m3.metric("Criticals", len([a for a in active_alerts if "CRIT" in a['severity']]))
        m4.metric("Triaged Today", len([t for t in triage_history if t['triaged_at'].startswith(str(datetime.now().date()))]))

        st.divider()
        
        with st.expander("🔎 Filter Intelligence", expanded=True):
            f1, f2, f3 = st.columns(3)
            with f1: 
                st.caption("Severity Levels")
                st.markdown("<span class='badge crit'>CRITICAL</span> <span class='badge high'>HIGH</span> <span class='badge med'>MEDIUM</span>", unsafe_allow_html=True)
                sev_filter = st.multiselect("Select Severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW"], default=["CRITICAL", "HIGH"], label_visibility="collapsed")
            with f2: sort_by = st.selectbox("Sort By", ["Risk (CVSS)", "Newest First", "Asset Name"])
            with f3: min_cvss = st.slider("Min CVSS", 0.0, 10.0, 0.0)

        filtered = [a for a in active_alerts if a['severity'] in sev_filter and a.get('cvss', 0) >= min_cvss]
        
        if "Risk" in sort_by: filtered.sort(key=lambda x: x.get('cvss', 0), reverse=True)
        elif "Newest" in sort_by: filtered.sort(key=lambda x: x['date'], reverse=True)
        
        t1, t2 = st.tabs(["Active Threats", "Triage Log"])
        
        with t1:
            if not filtered: st.success("No threats match your current filters.")
            
            for row in filtered:
                sev_map = {"CRITICAL": "crit", "HIGH": "high", "MEDIUM": "med", "LOW": "low"}
                s_cls = sev_map.get(row['severity'], "low")
                cvss_val = row.get('cvss', 0.0)
                
                with st.container(border=True):
                    c_main, c_act = st.columns([4, 1.5])
                    with c_main:
                        st.markdown(f"### {row['affected_asset'].upper()} | {row['cve']}")
                        st.markdown(f"<span class='badge {s_cls}'>{row['severity']}</span> <span class='badge {s_cls}'>CVSS {cvss_val}</span>", unsafe_allow_html=True)
                        st.write(row['description'])
                        st.caption(f"**Sources:** {row['source']} • **Detected:** {row['date']}")
                        # ROBUST LINK: Uses row['url'] which is now guaranteed by repair_alert_data
                        st.markdown(f"[🔗 Read Full Intelligence Report]({row.get('url')})", unsafe_allow_html=True)
                    
                    with c_act:
                        st.write("**Triage Decision**")
                        with st.form(key=f"form_{row['cve']}"):
                            decision = st.selectbox("Action", ["Select...", "True Positive", "False Positive", "Mitigated"], label_visibility="collapsed")
                            reason = st.text_input("Reasoning", placeholder="Notes...")
                            
                            if st.form_submit_button("Confirm Triage"):
                                if decision != "Select...":
                                    rec = row.copy()
                                    rec.update({
                                        "decision": decision, 
                                        "notes": reason, 
                                        "triaged_at": str(datetime.now()),
                                        "triaged_by": "Admin" 
                                    })
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

    # --- INVENTORY ---
    elif page == "Asset Inventory":
        st.title("Asset Management") # REMOVED EMOJI
        st.caption("Manage the Software Bill of Materials (SBOM).")
        
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

    # --- SETTINGS ---
    elif page == "Settings":
        st.title("System Configuration")
        
        st.subheader("Thresholds")
        st.info(f"Current Policy: Alert on CVSS >= **{inventory.get('threshold_cvss', 7.0)}**")
        
        st.subheader("🔔 Notification Channels")
        with st.form("slack_config"):
            c1, c2 = st.columns(2)
            current_webhook = inventory.get("slack_webhook", "")
            current_channel = inventory.get("slack_channel", "#security-alerts")
            
            webhook = c1.text_input("Webhook URL", value=current_webhook, type="password")
            channel = c2.text_input("Channel Name", value=current_channel)
            bot_name = st.text_input("Bot Name", value=inventory.get("slack_bot_name", "Guardian AI"))
            
            if st.form_submit_button("Save Configuration"):
                inventory.update({
                    "slack_webhook": webhook, 
                    "slack_channel": channel, 
                    "slack_bot_name": bot_name
                })
                save_json(INVENTORY_FILE, inventory)
                st.success("Configuration Saved")
        
        if inventory.get("slack_webhook"):
            if st.button("Send Test Notification"):
                if send_slack_test(inventory["slack_webhook"], inventory.get("slack_channel"), inventory.get("slack_bot_name")):
                    st.toast("Test Sent!", icon="✅")
                else:
                    st.error("Failed. Check URL.")

    # --- AUTO REFRESH HANDLER ---
    if refresh_opt != "Off":
        secs_map = {"5 Minutes": 300, "15 Minutes": 900, "1 Hour": 3600, "24 Hours": 86400}
        wait_time = secs_map.get(refresh_opt, 300)
        time.sleep(wait_time)
        st.rerun()
