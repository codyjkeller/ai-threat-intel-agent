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
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NIST_RSS_URL = "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss-analyst.xml"

# --- PAGE CONFIG & ENTERPRISE STYLING ---
st.set_page_config(
    page_title="Guardian AI | Threat Intel",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# Custom CSS for Enterprise Look
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600&display=swap');
    
    html, body, [class*="css"] {
        font-family: 'Inter', sans-serif;
        background-color: #0E1117; 
        color: #FAFAFA;
    }
    
    /* Login Button Styling */
    .stButton>button {
        background-color: #2563EB;
        color: white;
        border-radius: 6px;
        border: none;
        height: 3em;
        font-weight: 600;
    }
    .stButton>button:hover {
        background-color: #1D4ED8;
        border-color: #1D4ED8;
    }

    /* Cards/Metrics */
    div[data-testid="stMetric"] {
        background-color: #1F2937;
        padding: 15px;
        border-radius: 8px;
        border: 1px solid #374151;
    }

    /* Table Styling */
    div[data-testid="stDataFrame"] {
        border: 1px solid #374151;
        border-radius: 6px;
    }
    
    /* Headers */
    h1, h2, h3 {
        color: #F3F4F6;
        font-weight: 600;
    }
    
    /* Sidebar */
    section[data-testid="stSidebar"] {
        background-color: #111827;
    }
</style>
""", unsafe_allow_html=True)

# --- HELPER FUNCTIONS ---

def load_json(filepath, default):
    if not os.path.exists(filepath): return default
    with open(filepath, "r") as f: return json.load(f)

def save_json(filepath, data):
    with open(filepath, "w") as f: json.dump(data, f, indent=4)

def check_match(description, assets):
    description = description.lower()
    for asset in assets:
        if asset.lower() in description:
            return asset
    return None

def run_scan():
    """Runs the scanning logic immediately (Demo Mode)"""
    inv = load_json(INVENTORY_FILE, {"assets": []})
    assets = inv.get("assets", [])
    alerts = load_json(ALERTS_FILE, [])
    
    new_finds = 0
    
    # 1. CISA SCAN
    try:
        r = requests.get(CISA_KEV_URL).json()
        for vul in r.get("vulnerabilities", []):
            match = check_match(vul['product'], assets)
            if match:
                # Deduplicate
                if not any(a['cve'] == vul['cveID'] for a in alerts):
                    alerts.append({
                        "source": "CISA KEV",
                        "cve": vul['cveID'],
                        "affected_asset": match,
                        "description": vul['shortDescription'],
                        "severity": "CRITICAL",
                        "date": vul['dateAdded']
                    })
                    new_finds += 1
    except: pass

    # 2. NIST SCAN
    try:
        feed = feedparser.parse(NIST_RSS_URL)
        for entry in feed.entries:
            match = check_match(entry.summary, assets)
            if match:
                sev = "HIGH" if "HIGH" in entry.title.upper() else "CRITICAL" if "CRITICAL" in entry.title.upper() else "MEDIUM"
                if sev in ["HIGH", "CRITICAL"]:
                    cve = entry.title.split()[0]
                    if not any(a['cve'] == cve for a in alerts):
                        alerts.append({
                            "source": "NIST NVD",
                            "cve": cve,
                            "affected_asset": match,
                            "description": entry.summary[:150] + "...",
                            "severity": sev,
                            "date": datetime.now().strftime("%Y-%m-%d")
                        })
                        new_finds += 1
    except: pass

    save_json(ALERTS_FILE, alerts)
    return new_finds

# --- APP LOGIC ---

if "authenticated" not in st.session_state:
    st.session_state.authenticated = False

# 1. LANDING PAGE
if not st.session_state.authenticated:
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.markdown("<br><br><br>", unsafe_allow_html=True)
        st.image("https://upload.wikimedia.org/wikipedia/commons/thumb/9/9a/Shield_icon.svg/1200px-Shield_icon.svg.png", width=80)
        st.title("Guardian AI")
        st.markdown("### Enterprise Threat Intelligence Platform")
        st.write("Automated SBOM monitoring, real-time CISA ingestion, and vulnerability filtration.")
        
        st.markdown("<br>", unsafe_allow_html=True)
        
        # Mock Login
        if st.button("🔒 Sign In with SSO", use_container_width=True):
            with st.spinner("Authenticating via Okta..."):
                time.sleep(1)
                st.session_state.authenticated = True
                st.rerun()
                
        st.caption("Protected by Guardian AI • v2.4.0-Enterprise")

# 2. MAIN DASHBOARD
else:
    # Sidebar Navigation
    with st.sidebar:
        st.title("Guardian AI")
        page = st.radio("Navigation", ["Dashboard", "Asset Inventory", "Integrations", "Settings"])
        st.divider()
        st.caption(f"Logged in as: **Admin**")
        if st.button("Log Out"):
            st.session_state.authenticated = False
            st.rerun()

    # Load Data
    inventory = load_json(INVENTORY_FILE, {"assets": [], "threshold_cvss": 7.0})
    alerts = load_json(ALERTS_FILE, [])

    # -- PAGE: DASHBOARD --
    if page == "Dashboard":
        c1, c2 = st.columns([3, 1])
        with c1: st.title("Executive Threat Overview")
        with c2: 
            if st.button("🔄 Force Feed Refresh", type="primary"):
                with st.spinner("Scanning Global Threat Feeds..."):
                    found = run_scan()
                    st.success(f"Scan Complete. {found} new threats identified.")
                    time.sleep(1)
                    st.rerun()

        # Metrics
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Assets Monitored", len(inventory.get("assets", [])))
        m2.metric("Active Threats", len(alerts), delta="Live Feed")
        m3.metric("Critical Vulnerabilities", len([a for a in alerts if "CRITICAL" in a['severity']]), delta_color="inverse")
        m4.metric("System Status", "Operational", delta_color="normal")

        st.divider()
        
        st.subheader("🔴 Real-Time Alert Feed")
        if alerts:
            # Display as a clean table or cards
            df = pd.DataFrame(alerts)
            
            # Custom rendering for visual pop
            for i, row in df.iterrows():
                with st.expander(f"🚨 {row['severity']} | {row['affected_asset'].upper()} ({row['cve']})", expanded=True):
                    c_left, c_right = st.columns([4, 1])
                    with c_left:
                        st.markdown(f"**Description:** {row['description']}")
                        st.caption(f"Source: {row['source']} • Detected: {row['date']}")
                    with c_right:
                        if st.button("Triaged", key=f"triage_{row['cve']}"):
                            st.toast("Marked as Triaged")
        else:
            st.info("No active threats detected matching your inventory.")

    # -- PAGE: INVENTORY --
    elif page == "Asset Inventory":
        st.title("📦 Asset Management")
        st.write("Curate the Software Bill of Materials (SBOM) to filter noise.")
        
        c1, c2 = st.columns([3, 1])
        new_asset = c1.text_input("Add Software Asset", placeholder="e.g. nginx, kubernetes")
        if c2.button("Add to Watchlist", use_container_width=True):
            if new_asset and new_asset not in inventory["assets"]:
                inventory["assets"].append(new_asset)
                save_json(INVENTORY_FILE, inventory)
                st.rerun()

        if inventory["assets"]:
            st.markdown("### Currently Tracking")
            cols = st.columns(4)
            for i, asset in enumerate(inventory["assets"]):
                with cols[i % 4]:
                    st.info(f"**{asset}**")
                    if st.button("Remove", key=f"rem_{asset}"):
                        inventory["assets"].remove(asset)
                        save_json(INVENTORY_FILE, inventory)
                        st.rerun()

    # -- PAGE: INTEGRATIONS --
    elif page == "Integrations":
        st.title("⚙️ Integrations")
        st.subheader("Slack Notifications")
        webhook = st.text_input("Webhook URL", value=inventory.get("slack_webhook", ""), type="password")
        if st.button("Save Configuration"):
            inventory["slack_webhook"] = webhook
            save_json(INVENTORY_FILE, inventory)
            st.success("Configuration Saved")

    elif page == "Settings":
        st.title("System Settings")
        st.write("Current Engine Version: v2.4.0")
        st.slider("Global Alert Threshold (CVSS)", 0.0, 10.0, 7.0, disabled=True)
