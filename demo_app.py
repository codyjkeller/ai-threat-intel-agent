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
    page_title="Guardian AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- ENTERPRISE CSS ---
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
    html, body, [class*="css"] { font-family: 'Inter', sans-serif; background-color: #FFFFFF; color: #0F172A; }
    
    div.stButton > button { 
        background-color: #0F172A !important; 
        color: white !important; 
        border-radius: 6px !important; 
        font-weight: 600 !important; 
    }
    
    /* Severity Badges */
    .badge { padding: 4px 10px; border-radius: 6px; font-weight: 700; font-size: 0.85em; display: inline-block; margin-right: 8px; }
    .crit { background-color: #FEF2F2; color: #991B1B; border: 1px solid #FCA5A5; }
    .high { background-color: #FFF7ED; color: #9A3412; border: 1px solid #FDBA74; }
    .med  { background-color: #FEFCE8; color: #854D0E; border: 1px solid #FDE047; }
    .low  { background-color: #F0FDF4; color: #166534; border: 1px solid #86EFAC; }
    
    section[data-testid="stSidebar"] { background-color: #F8FAFC; border-right: 1px solid #E2E8F0; }
</style>
""", unsafe_allow_html=True)

# --- HELPER FUNCTIONS ---

def load_json(filepath, default):
    """Load JSON from disk."""
    if "inventory" in st.secrets and filepath == INVENTORY_FILE:
        return dict(st.secrets["inventory"])
    if not os.path.exists(filepath): return default
    try:
        with open(filepath, "r") as f: return json.load(f)
    except: return default

def save_json(filepath, data):
    """Save JSON to disk."""
    if "inventory" in st.secrets and filepath == INVENTORY_FILE:
        st.session_state.temp_inventory = data
    else:
        with open(filepath, "w") as f: json.dump(data, f, indent=4)

def normalize_severity(sev_str):
    """Strictly normalize severity to 4 buckets."""
    s = str(sev_str).upper().strip()
    if "CRIT" in s: return "CRITICAL"
    if "HIGH" in s: return "HIGH"
    if "MED" in s: return "MEDIUM"
    return "LOW"

def check_match(description, assets):
    description = description.lower()
    for asset in assets:
        asset_name = asset["name"] if isinstance(asset, dict) else asset
        if asset_name.lower() in description:
            return asset_name
    return None

# --- STATE MANAGEMENT (THE FIX) ---

def init_state():
    """Load data into Session State ONCE to prevent disk-read lag."""
    if "data_alerts" not in st.session_state:
        raw_alerts = load_json(ALERTS_FILE, [])
        # Repair data on load
        cleaned = []
        for a in raw_alerts:
            # Fix Severity
            a['severity'] = normalize_severity(a.get('severity', 'LOW'))
            # Fix CVSS
            if not a.get('cvss') or a.get('cvss') == 'N/A':
                if a['severity'] == "CRITICAL": a['cvss'] = 9.8
                elif a['severity'] == "HIGH": a['cvss'] = 7.5
                elif a['severity'] == "MEDIUM": a['cvss'] = 5.4
                else: a['cvss'] = 3.0
            # Fix URL
            if not a.get('url'): a['url'] = f"https://nvd.nist.gov/vuln/detail/{a['cve']}"
            cleaned.append(a)
        st.session_state.data_alerts = cleaned

    if "data_triage" not in st.session_state:
        st.session_state.data_triage = load_json(TRIAGE_FILE, [])

    if "data_inventory" not in st.session_state:
        st.session_state.data_inventory = load_json(INVENTORY_FILE, {"assets": []})

def run_scan(lookback_days=90):
    """Fetch new threats and update Session State + Disk."""
    assets = st.session_state.data_inventory.get("assets", [])
    current_alerts = st.session_state.data_alerts
    new_finds = 0
    cutoff = datetime.now() - timedelta(days=lookback_days)

    def add_alert(cve, asset, desc, sev_raw, cvss, source, url, date_str):
        nonlocal new_finds
        # 1. Date Filter
        try:
            if datetime.strptime(date_str, "%Y-%m-%d") < cutoff: return
        except: pass
        
        # 2. Strict Normalization
        s_norm = normalize_severity(sev_raw)
        if not url: url = f"https://nvd.nist.gov/vuln/detail/{cve}"
        
        if not any(a['cve'] == cve for a in current_alerts):
            new_alert = {
                "cve": cve, "affected_asset": asset, "description": desc,
                "severity": s_norm, "cvss": cvss, "source": source,
                "url": url, "date": date_str
            }
            current_alerts.append(new_alert)
            new_finds += 1

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
                sev_raw = "MEDIUM"
                if "HIGH" in entry.title.upper(): sev_raw = "HIGH"
                if "CRITICAL" in entry.title.upper(): sev_raw = "CRITICAL"
                match_cvss = re.search(r'\(([\d\.]+)', entry.title)
                score = float(match_cvss.group(1)) if match_cvss else (9.8 if sev_raw=="CRITICAL" else 7.5)
                cve = entry.title.split()[0]
                date = datetime.now().strftime("%Y-%m-%d")
                add_alert(cve, match, entry.summary[:200]+"...", sev_raw, score, "NIST NVD", entry.link, date)
    except: pass

    # Update State & Save
    st.session_state.data_alerts = current_alerts
    save_json(ALERTS_FILE, current_alerts)
    return new_finds

# --- APP LOGIC ---

if "authenticated" not in st.session_state: st.session_state.authenticated = False

# LOGIN
if not st.session_state.authenticated:
    _, c2, _ = st.columns([1, 2, 1])
    with c2:
        st.markdown("<br><br><h1 style='text-align: center;'>🛡️ Guardian AI</h1>", unsafe_allow_html=True)
        if st.button("Sign In", use_container_width=True):
            st.session_state.authenticated = True
            st.rerun()
else:
    # Initialize Memory State
    init_state()

    with st.sidebar:
        st.title("Guardian AI")
        page = st.radio("Navigation", ["Dashboard", "Asset Inventory", "Settings"], label_visibility="collapsed")
        st.divider()
        refresh_opt = st.selectbox("Live Mode", ["Off", "30 Seconds", "5 Minutes"], index=0)
        st.divider()
        st.caption("v3.1.0 - In-Memory")
        if st.button("Log Out"): st.session_state.authenticated = False; st.rerun()

    # --- MAIN PAGES ---
    
    if page == "Dashboard":
        c1, c2 = st.columns([3, 1])
        with c1: st.title("Risk Dashboard")
        with c2: 
            if st.button("🔄 Refresh Feeds"):
                with st.spinner("Scanning..."):
                    n = run_scan(90)
                    st.toast(f"Found {n} new threats")
                    time.sleep(0.5); st.rerun()

        # DATA PREP (FROM MEMORY)
        alerts = st.session_state.data_alerts
        history = st.session_state.data_triage
        triaged_ids = [t['cve'] for t in history]
        active = [a for a in alerts if a['cve'] not in triaged_ids]

        # METRICS
        crit_count = len([a for a in active if a['severity'] == "CRITICAL"])
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Risk Index", len(active) * 10, delta="Live", delta_color="inverse")
        m2.metric("Active Threats", len(active))
        m3.metric("Criticals", crit_count)
        m4.metric("Triaged", len(history))

        st.divider()
        
        # FILTERS
        with st.expander("🔎 Filter Intelligence", expanded=True):
            f1, f2, f3 = st.columns(3)
            with f1: 
                sev_filter = st.multiselect("Severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW"], default=["CRITICAL", "HIGH"])
            with f2: sort_by = st.selectbox("Sort By", ["Risk (CVSS)", "Newest First", "Asset Name"])
            with f3: min_cvss = st.slider("Min CVSS", 0.0, 10.0, 0.0)
            
            # VISIBLE DEBUG
            # st.caption(f"DEBUG: Active: {len(active)} | Filters: {sev_filter} | Min CVSS: {min_cvss}")

        # LOGIC (MEMORY BASED)
        filtered = []
        for a in active:
            if a['severity'] in sev_filter and float(a.get('cvss', 0)) >= min_cvss:
                filtered.append(a)
        
        # Sort
        if "Risk" in sort_by: filtered.sort(key=lambda x: float(x.get('cvss', 0)), reverse=True)
        elif "Newest" in sort_by: filtered.sort(key=lambda x: x.get('date', ''), reverse=True)

        # RENDER
        t1, t2 = st.tabs([f"Active Threats ({len(filtered)})", "Triage Log"])
        
        with t1:
            if not filtered:
                st.success("No threats match your current filters.")
            
            for row in filtered:
                # Badge Style
                s = row['severity']
                cls = "crit" if s == "CRITICAL" else "high" if s == "HIGH" else "med" if s == "MEDIUM" else "low"
                
                with st.container(border=True):
                    c_main, c_act = st.columns([4, 1.5])
                    with c_main:
                        st.markdown(f"### {row['affected_asset'].upper()} | {row['cve']}")
                        st.markdown(f"<span class='badge {cls}'>{s}</span> <span class='badge {cls}'>CVSS {row.get('cvss')}</span>", unsafe_allow_html=True)
                        st.write(row['description'])
                        st.caption(f"Source: {row['source']} • Detected: {row['date']}")
                        st.markdown(f"[🔗 Intelligence Link]({row['url']})", unsafe_allow_html=True)
                    
                    with c_act:
                        st.write("**Triage**")
                        with st.form(key=f"f_{row['cve']}"):
                            decision = st.selectbox("Action", ["Select...", "True Positive", "False Positive", "Mitigated"], label_visibility="collapsed")
                            note = st.text_input("Note")
                            if st.form_submit_button("Confirm"):
                                if decision != "Select...":
                                    # UPDATE MEMORY STATE DIRECTLY
                                    rec = row.copy()
                                    rec.update({"decision": decision, "notes": note, "triaged_at": str(datetime.now())})
                                    st.session_state.data_triage.append(rec)
                                    save_json(TRIAGE_FILE, st.session_state.data_triage)
                                    st.toast("Triaged!")
                                    st.rerun()

        with t2:
            if history:
                for item in reversed(history):
                    with st.expander(f"{item['decision']}: {item['cve']}"):
                        st.write(f"Note: {item.get('notes')}")
                        if st.button("Undo", key=f"u_{item['cve']}"):
                            st.session_state.data_triage.remove(item)
                            save_json(TRIAGE_FILE, st.session_state.data_triage)
                            st.rerun()
            else: st.info("Empty")

    elif page == "Asset Inventory":
        st.title("Asset Management")
        with st.form("add"):
            c1, c2 = st.columns(2)
            n = c1.text_input("Software"); d = c2.text_input("Context")
            if st.form_submit_button("Add"):
                if n:
                    st.session_state.data_inventory["assets"].append({"name": n, "description": d})
                    save_json(INVENTORY_FILE, st.session_state.data_inventory)
                    st.rerun()
        
        st.divider()
        if st.session_state.data_inventory["assets"]:
            for i, a in enumerate(st.session_state.data_inventory["assets"]):
                name = a.get("name") if isinstance(a, dict) else a
                with st.container(border=True):
                    c1, c2 = st.columns([5, 1])
                    c1.markdown(f"**{name}**")
                    if c2.button("🗑️", key=f"d_{i}"):
                        st.session_state.data_inventory["assets"].pop(i)
                        save_json(INVENTORY_FILE, st.session_state.data_inventory)
                        st.rerun()

    elif page == "Settings":
        st.title("System Settings")
        if st.button("🗑️ Flush All Data"):
            st.session_state.data_alerts = []
            st.session_state.data_triage = []
            if os.path.exists(ALERTS_FILE): os.remove(ALERTS_FILE)
            if os.path.exists(TRIAGE_FILE): os.remove(TRIAGE_FILE)
            st.toast("System Reset"); time.sleep(1); st.rerun()

    # AUTO REFRESH
    if refresh_opt != "Off":
        secs = {"30 Seconds": 30, "5 Minutes": 300}.get(refresh_opt, 300)
        time.sleep(secs)
        st.rerun()
