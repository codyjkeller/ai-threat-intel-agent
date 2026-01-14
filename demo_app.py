import streamlit as st
import pandas as pd
import json
import os
import time
import requests
import feedparser
from datetime import datetime

# --- CONFIGURATION ---
INVENTORY_FILE = "inventory.json"
ALERTS_FILE = "alerts.json"
TRIAGE_FILE = "triage_history.json"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NIST_RSS_URL = "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss-analyst.xml"

# --- PAGE CONFIG ---
st.set_page_config(
    page_title="Threat Intel Agent",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- ENTERPRISE CSS ---
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600&display=swap');
    html, body, [class*="css"] { font-family: 'Inter', sans-serif; background-color: #FFFFFF; color: #111827; }
    .stButton>button { background-color: #0F172A; color: white; border-radius: 6px; border: none; height: 2.5em; font-weight: 600; transition: all 0.2s; }
    .stButton>button:hover { background-color: #334155; color: white; }
    div[data-testid="stMetric"] { background-color: #F8FAFC; padding: 15px; border-radius: 8px; border: 1px solid #E2E8F0; box-shadow: 0 1px 2px 0 rgba(0, 0, 0, 0.05); }
    h1, h2, h3 { color: #0F172A; font-weight: 700; }
    section[data-testid="stSidebar"] { background-color: #F1F5F9; }
    .severity-critical { color: #DC2626; font-weight: bold; }
    .severity-high { color: #EA580C; font-weight: bold; }
    .severity-medium { color: #CA8A04; font-weight: bold; }
    .severity-low { color: #16A34A; font-weight: bold; }
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

def check_match(description, assets):
    description = description.lower()
    for asset in assets:
        asset_name = asset["name"] if isinstance(asset, dict) else asset
        if asset_name.lower() in description:
            return asset_name
    return None

def run_scan():
    inv = st.session_state.get("temp_inventory", load_json(INVENTORY_FILE, {"assets": []}))
    assets = inv.get("assets", [])
    alerts = load_json(ALERTS_FILE, [])
    new_finds = 0
    
    # 1. CISA SCAN
    try:
        r = requests.get(CISA_KEV_URL).json()
        for vul in r.get("vulnerabilities", []):
            match = check_match(vul['product'], assets)
            if match:
                if not any(a['cve'] == vul['cveID'] for a in alerts):
                    alerts.append({
                        "source": "CISA KEV",
                        "cve": vul['cveID'],
                        "affected_asset": match,
                        "description": vul['shortDescription'],
                        "severity": "CRITICAL",
                        "cvss": 9.8, # Placeholder for CISA
                        "date": vul['dateAdded'],
                        "url": f"https://nvd.nist.gov/vuln/detail/{vul['cveID']}"
                    })
                    new_finds += 1
    except: pass

    # 2. NIST SCAN
    try:
        feed = feedparser.parse(NIST_RSS_URL)
        for entry in feed.entries:
            match = check_match(entry.summary, assets)
            if match:
                sev = "HIGH" if "HIGH" in entry.title.upper() else "MEDIUM"
                if "CRITICAL" in entry.title.upper(): sev = "CRITICAL"
                
                cve = entry.title.split()[0]
                if not any(a['cve'] == cve for a in alerts):
                    alerts.append({
                        "source": "NIST NVD",
                        "cve": cve,
                        "affected_asset": match,
                        "description": entry.summary[:200] + "...",
                        "severity": sev,
                        "cvss": 7.5 if sev=="HIGH" else 9.0 if sev=="CRITICAL" else 5.0,
                        "date": datetime.now().strftime("%Y-%m-%d"),
                        "url": entry.link
                    })
                    new_finds += 1
    except: pass

    save_json(ALERTS_FILE, alerts)
    return new_finds

# --- APP LOGIC ---

if "authenticated" not in st.session_state: st.session_state.authenticated = False

# LOGIN
if not st.session_state.authenticated:
    _, c2, _ = st.columns([1, 2, 1])
    with c2:
        st.markdown("<br><br><h1 style='text-align: center; font-size: 60px;'>🛡️</h1>", unsafe_allow_html=True)
        st.markdown("<h2 style='text-align: center;'>Threat Intel Agent</h2>", unsafe_allow_html=True)
        if st.button("🔒 Sign In with SSO", use_container_width=True):
            time.sleep(0.5)
            st.session_state.authenticated = True
            st.rerun()

# MAIN APP
else:
    with st.sidebar:
        st.title("Guardian AI")
        page = st.radio("Menu", ["Dashboard", "Asset Inventory", "Settings"], label_visibility="collapsed")
        st.divider()
        if st.button("Log Out"): st.session_state.authenticated = False; st.rerun()

    # Load Data
    inventory = st.session_state.get("temp_inventory", load_json(INVENTORY_FILE, {"assets": [], "threshold_cvss": 7.0}))
    alerts = load_json(ALERTS_FILE, [])
    triage_history = load_json(TRIAGE_FILE, [])

    # Filter out triaged alerts from the main view
    triaged_cves = [t['cve'] for t in triage_history]
    active_alerts = [a for a in alerts if a['cve'] not in triaged_cves]

    if page == "Dashboard":
        c1, c2 = st.columns([3, 1])
        with c1: st.title("Executive Threat Overview")
        with c2: 
            st.write("")
            if st.button("🔄 Refresh Feeds", type="primary"):
                with st.spinner("Scanning..."):
                    found = run_scan()
                    st.success(f"Found {found} new.")
                    time.sleep(1); st.rerun()

        # Metrics
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Assets", len(inventory.get("assets", [])))
        m2.metric("Active Alerts", len(active_alerts))
        m3.metric("Triaged", len(triage_history))
        m4.metric("Status", "Operational")

        st.divider()
        
        # FILTERS
        with st.expander("🔎 Filter & Sort", expanded=True):
            f1, f2, f3 = st.columns(3)
            with f1:
                sev_filter = st.multiselect("Severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW"], default=["CRITICAL", "HIGH"])
            with f2:
                sort_order = st.selectbox("Sort By", ["CVSS Score (High-Low)", "Date (Newest)", "Asset Name"])
            with f3:
                min_cvss = st.slider("Min CVSS", 0.0, 10.0, 0.0)

        # APPLY FILTERS
        filtered_alerts = [a for a in active_alerts if a['severity'] in sev_filter and a.get('cvss', 0) >= min_cvss]
        
        # APPLY SORT
        if "CVSS" in sort_order:
            filtered_alerts.sort(key=lambda x: x.get('cvss', 0), reverse=True)
        elif "Date" in sort_order:
            filtered_alerts.sort(key=lambda x: x['date'], reverse=True)
        else:
            filtered_alerts.sort(key=lambda x: x['affected_asset'])

        # MAIN FEED TABS
        feed_tab, history_tab = st.tabs(["🔴 Active Threats", "✅ Triage History"])

        with feed_tab:
            if filtered_alerts:
                for row in filtered_alerts:
                    # Severity Color Logic
                    s_class = "severity-critical" if "CRIT" in row['severity'] else "severity-high" if "HIGH" in row['severity'] else "severity-medium"
                    
                    with st.container(border=True):
                        c_main, c_actions = st.columns([4, 1.5])
                        with c_main:
                            st.markdown(f"### {row['affected_asset'].upper()} | {row['cve']}")
                            st.markdown(f"<span class='{s_class}'>{row['severity']} (CVSS {row.get('cvss', 'N/A')})</span>", unsafe_allow_html=True)
                            st.write(row['description'])
                            st.markdown(f"[🔗 Read Source Analysis]({row.get('url', '#')})")
                            st.caption(f"Detected: {row['date']} • Source: {row['source']}")
                        
                        with c_actions:
                            st.write(" **Triage Decision:**")
                            decision = st.selectbox("Status", ["Select...", "True Positive", "False Positive", "Not Applicable"], key=f"sel_{row['cve']}")
                            notes = st.text_input("Reasoning", placeholder="e.g. WAF blocks this", key=f"note_{row['cve']}")
                            
                            if st.button("Confirm Triage", key=f"btn_{row['cve']}", type="primary"):
                                if decision != "Select...":
                                    # Move to Triage History
                                    triage_record = row.copy()
                                    triage_record.update({"decision": decision, "notes": notes, "triaged_at": str(datetime.now())})
                                    triage_history.append(triage_record)
                                    save_json(TRIAGE_FILE, triage_history)
                                    st.toast("Alert Triaged!")
                                    time.sleep(0.5)
                                    st.rerun()
                                else:
                                    st.warning("Select a decision.")
            else:
                st.info("No alerts match your filters.")

        with history_tab:
            if triage_history:
                st.write("Previously processed alerts. Click 'Undo' to return to active feed.")
                for item in reversed(triage_history):
                    with st.expander(f"{item['cve']} - {item['decision']}"):
                        st.write(f"**Asset:** {item['affected_asset']}")
                        st.write(f"**Reasoning:** {item['notes']}")
                        st.caption(f"Triaged: {item['triaged_at']}")
                        if st.button("↩️ Undo Decision", key=f"undo_{item['cve']}"):
                            triage_history.remove(item)
                            save_json(TRIAGE_FILE, triage_history)
                            st.rerun()
            else:
                st.caption("No history yet.")

    elif page == "Asset Inventory":
        st.title("📦 Asset Management")
        # (Same logic as before, just kept concise for this paste)
        with st.form("add_asset"):
            c1, c2 = st.columns(2)
            n = c1.text_input("Software"); d = c2.text_input("Context")
            if st.form_submit_button("Add"):
                inventory["assets"].append({"name": n, "description": d, "date": str(datetime.now().date())})
                save_json(INVENTORY_FILE, inventory); st.rerun()
        
        if inventory["assets"]:
            for i, a in enumerate(inventory["assets"]):
                name = a["name"] if isinstance(a, dict) else a
                with st.container(border=True):
                    c1, c2 = st.columns([5, 1])
                    c1.markdown(f"**{name}**"); c2.button("🗑️", key=f"del_{i}", on_click=lambda: (inventory["assets"].pop(i), save_json(INVENTORY_FILE, inventory)))

    elif page == "Settings":
        st.title("System Settings")
        st.info("Configuration is managed via `inventory.json` or Streamlit Secrets in Cloud Mode.")
