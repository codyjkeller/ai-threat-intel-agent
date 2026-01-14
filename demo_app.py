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
    
    /* Buttons */
    .stButton>button { 
        background-color: #0F172A; 
        color: white; 
        border-radius: 6px; 
        border: none; 
        height: 2.5em; 
        font-weight: 600; 
        box-shadow: 0 1px 2px 0 rgba(0, 0, 0, 0.05);
    }
    .stButton>button:hover { 
        background-color: #334155; 
        color: white; 
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

def extract_cvss(title, severity):
    """
    Extracts CVSS from title or estimates based on Severity if missing.
    Ensures the UI always has a number to display.
    """
    match = re.search(r'\(([\d\.]+)', title)
    if match:
        return float(match.group(1))
    
    # Fallback Estimates if feed is missing score
    if severity == "CRITICAL": return 9.8
    if severity == "HIGH": return 7.5
    if severity == "MEDIUM": return 5.3
    return 0.0

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

    # 1. CISA KEV (Always Critical)
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

    # 2. NIST SCAN
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
                
                update_or_add(
                    cve, match, entry.summary[:200]+"...", sev, score,
                    "NIST NVD", entry.link, datetime.now().strftime("%Y-%m-%d")
                )
    except: pass

    save_json(ALERTS_FILE, alerts)
    return new_finds

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
        st.caption("Admin User")
        if st.button("Log Out"): st.session_state.authenticated = False; st.rerun()

    inventory = st.session_state.get("temp_inventory", load_json(INVENTORY_FILE, {"assets": [], "threshold_cvss": 7.0}))
    alerts = load_json(ALERTS_FILE, [])
    triage_history = load_json(TRIAGE_FILE, [])
    active_alerts = [a for a in alerts if a['cve'] not in [t['cve'] for t in triage_history]]

    if page == "Dashboard":
        c1, c2 = st.columns([3, 1])
        with c1: st.title("Risk Dashboard")
        with c2: 
            if st.button("🔄 Refresh Feeds", type="primary"):
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
                st.markdown("<span style='color:#991B1B; font-weight:bold'>CRITICAL</span> • <span style='color:#9A3412; font-weight:bold'>HIGH</span> • <span style='color:#854D0E; font-weight:bold'>MEDIUM</span>", unsafe_allow_html=True)
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
                cvss_val = row.get('cvss', 'N/A')
                
                with st.container(border=True):
                    c_main, c_act = st.columns([4, 1.5])
                    with c_main:
                        st.markdown(f"### {row['affected_asset'].upper()} | {row['cve']}")
                        st.markdown(f"<span class='badge {s_cls}'>{row['severity']}</span> <span class='badge {s_cls}'>CVSS {cvss_val}</span>", unsafe_allow_html=True)
                        st.write(row['description'])
                        st.caption(f"**Sources:** {row['source']} • **Detected:** {row['date']}")
                        st.markdown(f"[🔗 Read Full Intelligence Report]({row.get('url', '#')})")
                    
                    with c_act:
                        st.write("**Triage Decision**")
                        with st.form(key=f"form_{row['cve']}"):
                            decision = st.selectbox("Status", ["Select...", "True Positive", "False Positive", "Mitigated"], label_visibility="collapsed")
                            reason = st.text_input("Reasoning", placeholder="Notes...")
                            if st.form_submit_button("Confirm Triage", type="primary"):
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
                        c1, c2 = st.columns(2)
                        c1.write(f"**Owner:** {item.get('triaged_by', 'System')}")
                        c1.write(f"**Reason:** {item.get('notes', 'N/A')}")
                        c2.caption(f"Time: {item['triaged_at']}")
                        if c2.button("Undo", key=f"undo_{item['cve']}"):
                            triage_history.remove(item)
                            save_json(TRIAGE_FILE, triage_history)
                            st.rerun()
            else: st.info("No triage history found.")

    elif page == "Asset Inventory":
        st.title("Asset Inventory")
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
                c1, c2, c3, c4 = st.columns([2, 1, 2, 0.5])
                c1.markdown(f"**{name}**")
                c2.caption(f"v{a.get('version', 'All')}" if isinstance(a, dict) else "vAll")
                c3.caption(desc)
                if c4.button("✕", key=f"del_{i}"):
                    inventory["assets"].pop(i)
                    save_json(INVENTORY_FILE, inventory); st.rerun()

    elif page == "Settings":
        st.title("System Configuration")
        st.info(f"Current Policy: Alert on CVSS >= **{inventory.get('threshold_cvss', 7.0)}**")
        if inventory.get("slack_webhook"): st.success("✅ Slack Active")
        else: st.warning("⚠️ Slack Inactive")
