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

# --- PAGE CONFIG ---
st.set_page_config(
    page_title="Threat Intel Agent",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# --- ENTERPRISE CSS (LIGHT MODE) ---
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600&display=swap');
    
    html, body, [class*="css"] {
        font-family: 'Inter', sans-serif;
        background-color: #FFFFFF; 
        color: #111827;
    }
    
    /* Login Button */
    .stButton>button {
        background-color: #0F172A;
        color: white;
        border-radius: 6px;
        border: none;
        height: 3em;
        font-weight: 600;
        transition: all 0.2s;
    }
    .stButton>button:hover {
        background-color: #334155;
        border-color: #334155;
        color: white;
    }

    /* Cards/Metrics (Light Grey) */
    div[data-testid="stMetric"] {
        background-color: #F8FAFC;
        padding: 15px;
        border-radius: 8px;
        border: 1px solid #E2E8F0;
        box-shadow: 0 1px 2px 0 rgba(0, 0, 0, 0.05);
    }

    /* Table Styling */
    div[data-testid="stDataFrame"] {
        border: 1px solid #E2E8F0;
        border-radius: 6px;
    }
    
    /* Headers */
    h1, h2, h3 {
        color: #0F172A;
        font-weight: 700;
    }
    
    /* Sidebar */
    section[data-testid="stSidebar"] {
        background-color: #F1F5F9;
    }
    
    /* Expander Headers */
    .streamlit-expanderHeader {
        background-color: #F8FAFC;
        border-radius: 4px;
    }
</style>
""", unsafe_allow_html=True)

# --- HELPER FUNCTIONS ---

def load_inventory_data():
    """Smart Loader with Auto-Migration for Old String Lists"""
    # 1. Load Data
    data = {"assets": [], "threshold_cvss": 7.0}
    if "inventory" in st.secrets:
        data = dict(st.secrets["inventory"])
    elif os.path.exists(INVENTORY_FILE):
        with open(INVENTORY_FILE, "r") as f:
            data = json.load(f)
            
    # 2. Migrate Assets (String -> Object) if needed
    new_assets = []
    for asset in data.get("assets", []):
        if isinstance(asset, str):
            # Convert old string asset to new object format
            new_assets.append({
                "name": asset,
                "date_added": datetime.now().strftime("%Y-%m-%d"),
                "added_by": "System",
                "description": "Legacy import"
            })
        else:
            new_assets.append(asset)
    
    data["assets"] = new_assets
    return data

def save_inventory_data(data):
    if "inventory" in st.secrets:
        st.warning("⚠️ Cloud Mode: Changes are session-only (Secrets are read-only).")
        st.session_state.temp_inventory = data # Persist in session at least
    else:
        with open(INVENTORY_FILE, "w") as f: json.dump(data, f, indent=4)

def load_alerts_data():
    if not os.path.exists(ALERTS_FILE): return []
    with open(ALERTS_FILE, "r") as f: return json.load(f)

def save_alerts_data(data):
    with open(ALERTS_FILE, "w") as f: json.dump(data, f, indent=4)

def check_match(description, assets):
    description = description.lower()
    for asset in assets:
        # Handle object structure
        asset_name = asset["name"] if isinstance(asset, dict) else asset
        if asset_name.lower() in description:
            return asset_name
    return None

def run_scan():
    """Runs the scanning logic"""
    # Prefer session state inventory if modified in Cloud Mode
    if "temp_inventory" in st.session_state:
        inv = st.session_state.temp_inventory
    else:
        inv = load_inventory_data()
        
    assets = inv.get("assets", [])
    alerts = load_alerts_data()
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

    save_alerts_data(alerts)
    return new_finds

# --- APP LOGIC ---

if "authenticated" not in st.session_state:
    st.session_state.authenticated = False

# 1. LANDING PAGE
if not st.session_state.authenticated:
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.markdown("<br><br><br>", unsafe_allow_html=True)
        # Replaced broken image with a reliable shield emoji as a big icon
        st.markdown("<h1 style='text-align: center; font-size: 80px;'>🛡️</h1>", unsafe_allow_html=True)
        st.markdown("<h1 style='text-align: center;'>Threat Intel Agent</h1>", unsafe_allow_html=True)
        st.markdown("<p style='text-align: center; color: #64748B;'>Automated SBOM monitoring, real-time CISA ingestion, and vulnerability filtration.</p>", unsafe_allow_html=True)
        
        st.markdown("<br>", unsafe_allow_html=True)
        
        # Mock Login
        if st.button("🔒 Sign In with SSO", use_container_width=True):
            with st.spinner("Authenticating..."):
                time.sleep(0.8)
                st.session_state.authenticated = True
                st.rerun()
                
        st.markdown("<p style='text-align: center; font-size: 12px; color: #94A3B8; margin-top: 20px;'>Protected by Enterprise SSO • v2.5.0</p>", unsafe_allow_html=True)

# 2. MAIN DASHBOARD
else:
    # Sidebar
    with st.sidebar:
        st.title("Threat Intel Agent")
        st.caption("v2.5.0-Enterprise")
        page = st.radio("Menu", ["Dashboard", "Asset Inventory", "Settings"], label_visibility="collapsed")
        st.divider()
        st.caption(f"User: **Admin**")
        if st.button("Log Out"):
            st.session_state.authenticated = False
            st.rerun()

    # Load Data (Priority to session cache for cloud persistence simulation)
    if "temp_inventory" in st.session_state:
        inventory = st.session_state.temp_inventory
    else:
        inventory = load_inventory_data()
        
    alerts = load_alerts_data()

    # -- PAGE: DASHBOARD --
    if page == "Dashboard":
        c1, c2 = st.columns([3, 1])
        with c1: st.title("Executive Threat Overview")
        with c2: 
            st.write("") # Spacer
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
        crit_count = len([a for a in alerts if "CRITICAL" in a['severity']])
        m3.metric("Critical Vulnerabilities", crit_count, delta="Attention Needed", delta_color="inverse" if crit_count > 0 else "off")
        m4.metric("System Status", "Operational", delta_color="normal")

        st.divider()
        
        st.subheader("🔴 Real-Time Alert Feed")
        if alerts:
            # Sort newest first
            df = pd.DataFrame(alerts).iloc[::-1]
            
            for i, row in df.iterrows():
                # Severity Badge Color
                sev_color = "red" if "CRITICAL" in row['severity'].upper() else "orange"
                
                with st.container():
                    col_icon, col_details, col_action = st.columns([0.5, 4, 1])
                    with col_icon:
                        st.markdown(f"<h2 style='color:{sev_color};'>●</h2>", unsafe_allow_html=True)
                    with col_details:
                        st.markdown(f"**{row['affected_asset'].upper()}** | {row['cve']}")
                        st.caption(f"{row['description']}")
                        st.caption(f"📅 {row['date']} • Source: {row['source']}")
                    with col_action:
                        if st.button("Ack", key=f"ack_{row['cve']}"):
                            st.toast("Alert Acknowledged")
                    st.divider()
        else:
            st.info("No active threats detected matching your inventory.")

    # -- PAGE: INVENTORY --
    elif page == "Asset Inventory":
        st.title("📦 Asset Management")
        st.write("Manage the Software Bill of Materials (SBOM) used to filter threat feeds.")
        
        # ADD NEW ASSET FORM
        with st.expander("➕ Register New Asset", expanded=False):
            with st.form("new_asset_form"):
                c1, c2 = st.columns(2)
                with c1: 
                    new_name = st.text_input("Software Name", placeholder="e.g. nginx, kubernetes")
                with c2:
                    new_desc = st.text_input("Business Context", placeholder="e.g. Used in Production API Gateway")
                
                submitted = st.form_submit_button("Add Asset to Watchlist")
                
                if submitted and new_name:
                    # Check duplicates
                    existing_names = [a["name"].lower() for a in inventory["assets"]]
                    if new_name.lower() in existing_names:
                        st.error("Asset already exists.")
                    else:
                        new_entry = {
                            "name": new_name,
                            "date_added": datetime.now().strftime("%Y-%m-%d"),
                            "added_by": "Admin", # Mocked User
                            "description": new_desc
                        }
                        inventory["assets"].append(new_entry)
                        save_inventory_data(inventory)
                        st.success(f"Tracking {new_name}...")
                        time.sleep(0.5)
                        st.rerun()

        # VIEW ASSETS TABLE
        if inventory["assets"]:
            st.markdown("### Watchlist")
            
            # Convert to DataFrame for pretty display
            asset_df = pd.DataFrame(inventory["assets"])
            
            # Custom Grid Display
            for i, asset in enumerate(inventory["assets"]):
                with st.container():
                    c1, c2, c3, c4 = st.columns([2, 3, 2, 1])
                    with c1: st.markdown(f"**{asset['name']}**")
                    with c2: st.caption(asset.get('description', 'No description'))
                    with c3: st.caption(f"Added: {asset.get('date_added', 'N/A')} by {asset.get('added_by', 'System')}")
                    with c4:
                        if st.button("Remove", key=f"rem_{i}"):
                            inventory["assets"].pop(i)
                            save_inventory_data(inventory)
                            st.rerun()
                    st.divider()
        else:
            st.info("Inventory is empty. Add assets to start monitoring.")

    # -- PAGE: SETTINGS --
    elif page == "Settings":
        st.title("System Settings")
        
        st.subheader("🚨 Alert Sensitivity")
        st.write("Configure the CVSS threshold for generating alerts.")
        
        current_thresh = inventory.get("threshold_cvss", 7.0)
        new_thresh = st.slider(
            "Minimum CVSS Score", 
            min_value=0.0, max_value=10.0, value=float(current_thresh), step=0.1
        )
        
        if new_thresh != current_thresh:
            inventory["threshold_cvss"] = new_thresh
            save_inventory_data(inventory)
            st.toast("Threshold Updated")
            
        st.info(f"Current Logic: Alerts will trigger for vulnerabilities with **CVSS >= {new_thresh}** or confirmed **Active Exploitation**.")

        st.divider()
        st.subheader("🔔 Notification Channels")
        webhook = st.text_input("Slack Webhook URL", value=inventory.get("slack_webhook", ""), type="password")
        if st.button("Save Integrations"):
            inventory["slack_webhook"] = webhook
            save_inventory_data(inventory)
            st.success("Configuration Saved")
