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
    page_title="Threat Intel Agent",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- ENTERPRISE CSS ---
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600&display=swap');
    
    html, body, [class*="css"] { 
        font-family: 'Inter', sans-serif; 
        background-color: #FFFFFF; 
        color: #111827; 
    }
    
    /* Buttons */
    .stButton>button { 
        background-color: #0F172A; 
        color: white; 
        border-radius: 6px; 
        border: none; 
        height: 2.5em; 
        font-weight: 600; 
        transition: all 0.2s; 
    }
    .stButton>button:hover { 
        background-color: #334155; 
        color: white; 
    }

    /* Cards */
    div[data-testid="stMetric"] { 
        background-color: #F8FAFC; 
        padding: 15px; 
        border-radius: 8px; 
        border: 1px solid #E2E8F0; 
        box-shadow: 0 1px 2px 0 rgba(0, 0, 0, 0.05); 
    }

    /* Severity Colors */
    .sev-critical { color: #DC2626; font-weight: 800; }  /* Red */
    .sev-high { color: #EA580C; font-weight: 700; }      /* Orange */
    .sev-medium { color: #CA8A04; font-weight: 700; }    /* Yellow */
    .sev-low { color: #16A34A; font-weight: 600; }       /* Green */
    .sev-info { color: #2563EB; font-weight: 600; }      /* Blue */
    
    /* Headers */
    h1, h2, h3 { color: #0F172A; font-weight: 700; }
    
    /* Sidebar */
    section[data-testid="stSidebar"] { background-color: #F1F5F9; }
</style>
""", unsafe_allow_html=True)

# --- HELPER FUNCTIONS ---

def load_json(filepath, default):
    """Load JSON with Streamlit Secrets fallback for Cloud Mode"""
    if "inventory" in st.secrets and filepath == INVENTORY_FILE:
        return dict(st.secrets["inventory"])
    if not os.path.exists(filepath): return default
    with open(filepath, "r") as f: return json.load(f)

def save_json(filepath, data):
    """Save JSON (Session state fallback for Cloud Mode)"""
    if "inventory" in st.secrets and filepath == INVENTORY_FILE:
        st.session_state.temp_inventory = data
    else:
        with open(filepath, "w") as f: json.dump(data, f, indent=4)

def extract_cvss(title_text):
    """Regex to find CVSS score in NIST titles like 'CVE-2024-1234 (7.5 HIGH)'"""
    match = re.search(r'\(([\d\.]+)', title_text)
    if match:
        try:
            return float(match.group(1))
        except:
            return 0.0
    return 0.0

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
    
    # 1. CISA SCAN (Always Critical)
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
                        "cvss": 9.8, # Implied Critical for KEV
                        "date": vul['dateAdded'],
                        "url": f"https://nvd.nist.gov/vuln/detail/{vul['cveID']}"
                    })
                    new_finds += 1
    except: pass

    # 2. NIST SCAN (Extract Score)
    try:
        feed = feedparser.parse(NIST_RSS_URL)
        for entry in feed.entries:
            match = check_match(entry.summary, assets)
            if match:
                title_upper = entry.title.upper()
                score = extract_cvss(entry.title)
                
                # Determine Severity
                sev = "INFO"
                if "CRITICAL" in title_upper: sev = "CRITICAL"
                elif "HIGH" in title_upper: sev = "HIGH"
                elif "MEDIUM" in title_upper: sev = "MEDIUM"
                elif "LOW" in title_upper: sev = "LOW"
                
                cve = entry.title.split()[0]
                if not any(a['cve'] == cve for a in alerts):
                    alerts.append({
                        "source": "NIST NVD",
                        "cve": cve,
                        "affected_asset": match,
                        "description": entry.summary[:250] + "...",
                        "severity": sev,
                        "cvss": score,
                        "date": datetime.now().strftime("%Y-%m-%d"),
                        "url": entry.link
                    })
                    new_finds += 1
    except: pass

    save_json(ALERTS_FILE, alerts)
    return new_finds

# --- APP LOGIC ---

if "authenticated" not in st.session_state: st.session_state.authenticated = False

# LOGIN SCREEN
if not st.session_state.authenticated:
    _, c2, _ = st.columns([1, 2, 1])
    with c2:
        st.markdown("<br><br><h1 style='text-align: center; font-size: 60px;'>🛡️</h1>", unsafe_allow_html=True)
        st.markdown("<h2 style='text-align: center;'>Guardian AI</h2>", unsafe_allow_html=True)
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

    # Filter Alerts
    triaged_cves = [t['cve'] for t in triage_history]
    active_alerts = [a for a in alerts if a['cve'] not in triaged_cves]

    # --- DASHBOARD ---
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
        crit_cnt = len([a for a in active_alerts if "CRIT" in a['severity']])
        m3.metric("Critical", crit_cnt, delta="Action Required", delta_color="inverse" if crit_cnt>0 else "off")
        m4.metric("Status", "Operational")

        st.divider()
        
        # FILTERS
        with st.expander("🔎 Filter & Sort", expanded=True):
            f1, f2, f3 = st.columns(3)
            with f1:
                sev_filter = st.multiselect("Severity", 
                    ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"], 
                    default=["CRITICAL", "HIGH", "MEDIUM"])
            with f2:
                sort_order = st.selectbox("Sort By", ["CVSS Score (High-Low)", "Date (Newest)", "Asset Name"])
            with f3:
                min_cvss = st.slider("Min CVSS", 0.0, 10.0, 0.0)

        # APPLY FILTERS
        filtered = [a for a in active_alerts if a['severity'] in sev_filter and a.get('cvss', 0) >= min_cvss]
        
        # APPLY SORT
        if "CVSS" in sort_order: filtered.sort(key=lambda x: x.get('cvss', 0), reverse=True)
        elif "Date" in sort_order: filtered.sort(key=lambda x: x['date'], reverse=True)
        else: filtered.sort(key=lambda x: x['affected_asset'])

        # FEED TABS
        tab_feed, tab_hist = st.tabs(["🔴 Active Threats", "✅ Triage History"])

        with tab_feed:
            if filtered:
                for row in filtered:
                    # Color Class
                    s = row['severity'].upper()
                    cls = "sev-critical" if "CRIT" in s else "sev-high" if "HIGH" in s else "sev-medium" if "MED" in s else "sev-low" if "LOW" in s else "sev-info"
                    
                    with st.container(border=True):
                        c_main, c_act = st.columns([3.5, 1.5])
                        with c_main:
                            st.markdown(f"### {row['affected_asset'].upper()} | {row['cve']}")
                            # Show CVSS Score if available
                            cvss_disp = f"(CVSS {row.get('cvss')})" if row.get('cvss') else ""
                            st.markdown(f"<span class='{cls}'>{row['severity']} {cvss_disp}</span>", unsafe_allow_html=True)
                            st.write(row['description'])
                            st.markdown(f"[🔗 Read Source Analysis]({row.get('url', '#')})")
                            st.caption(f"Detected: {row['date']} • Source: {row['source']}")
                        
                        with c_act:
                            st.caption("Triage Action")
                            decision = st.selectbox("Status", ["Select...", "True Positive", "False Positive", "Not Applicable", "Informational"], key=f"d_{row['cve']}")
                            notes = st.text_input("Reasoning", placeholder="e.g. WAF blocks this", key=f"n_{row['cve']}")
                            if st.button("Confirm", key=f"b_{row['cve']}", type="primary", disabled=(decision=="Select...")):
                                record = row.copy()
                                record.update({"decision": decision, "notes": notes, "triaged_at": str(datetime.now())})
                                triage_history.append(record)
                                save_json(TRIAGE_FILE, triage_history)
                                st.rerun()
            else:
                st.info("No active alerts match filters.")

        with tab_hist:
            if triage_history:
                st.write("Recent decisions. Click 'Undo' to re-open.")
                for item in reversed(triage_history):
                    with st.expander(f"{item['decision']}: {item['cve']} ({item['affected_asset']})"):
                        st.write(f"**Reasoning:** {item.get('notes', 'No notes')}")
                        st.caption(f"Triaged: {item['triaged_at']}")
                        if st.button("↩️ Undo", key=f"undo_{item['cve']}"):
                            triage_history.remove(item)
                            save_json(TRIAGE_FILE, triage_history)
                            st.rerun()
            else:
                st.caption("No history.")

    # --- INVENTORY ---
    elif page == "Asset Inventory":
        st.title("📦 Asset Management")
        st.write("Manage the Software Bill of Materials (SBOM).")
        
        with st.expander("➕ Register New Asset", expanded=False):
            with st.form("add_asset"):
                c1, c2, c3 = st.columns(3)
                name = c1.text_input("Software Name", placeholder="nginx")
                ver = c2.text_input("Version (Optional)", placeholder="1.21.0")
                desc = c3.text_input("Description/Owner", placeholder="Production Web Server")
                if st.form_submit_button("Add Asset"):
                    if name:
                        inventory["assets"].append({
                            "name": name, 
                            "version": ver, 
                            "description": desc,
                            "added_by": "Admin",
                            "date_added": str(datetime.now().date())
                        })
                        save_json(INVENTORY_FILE, inventory)
                        st.success(f"Added {name}")
                        time.sleep(0.5); st.rerun()

        if inventory["assets"]:
            for i, a in enumerate(inventory["assets"]):
                # Handle old string format if exists
                aname = a["name"] if isinstance(a, dict) else a
                aver = a.get("version", "All") if isinstance(a, dict) else "All"
                adesc = a.get("description", "") if isinstance(a, dict) else ""
                
                with st.container(border=True):
                    c1, c2, c3, c4 = st.columns([2, 1, 2, 0.5])
                    with c1: st.markdown(f"**{aname}**")
                    with c2: st.caption(f"v{aver}")
                    with c3: st.caption(adesc)
                    with c4: 
                        if st.button("🗑️", key=f"del_{i}"):
                            inventory["assets"].pop(i)
                            save_json(INVENTORY_FILE, inventory)
                            st.rerun()
        else:
            st.info("Inventory empty.")

    # --- SETTINGS ---
    elif page == "Settings":
        st.title("System Settings")
        st.info("Configuration managed via `inventory.json` or Secrets.")
