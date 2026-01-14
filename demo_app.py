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
        font-weight: 600 !important; 
        box-shadow: 0 1px 2px 0 rgba(0, 0, 0, 0.05) !important;
    }
    div.stButton > button:hover { 
        background-color: #334155 !important; 
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
    
    /* Sidebar */
    section[data-testid="stSidebar"] { background-color: #F8FAFC; border-right: 1px solid #E2E8F0; }
</style>
""", unsafe_allow_html=True)

# --- HELPER FUNCTIONS ---

def load_json(filepath, default):
    """Load JSON safely."""
    if "inventory" in st.secrets and filepath == INVENTORY_FILE:
        return dict(st.secrets["inventory"])
    if not os.path.exists(filepath): return default
    try:
        with open(filepath, "r") as f: return json.load(f)
    except: return default

def save_json(filepath, data):
    """Save JSON safely."""
    if "inventory" in st.secrets and filepath == INVENTORY_FILE:
        st.session_state.temp_inventory = data
    else:
        with open(filepath, "w") as f: json.dump(data, f, indent=4)

def normalize_severity(sev_str):
    """STRICT Normalization."""
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

def calculate_risk_score(alerts):
    score = 0
    for a in alerts:
        s = normalize_severity(a.get('severity', 'LOW'))
        if s == "CRITICAL": score += 100
        elif s == "HIGH": score += 50
        elif s == "MEDIUM": score += 20
        else: score += 5
    return score

# --- SCANNING ENGINE ---

def run_scan(lookback_days=365):
    inv = st.session_state.get("temp_inventory", load_json(INVENTORY_FILE, {"assets": []}))
    assets = inv.get("assets", [])
    alerts = load_json(ALERTS_FILE, [])
    new_finds = 0
    
    cutoff_date = datetime.now() - timedelta(days=lookback_days)

    def add_alert(cve, asset, desc, sev_raw, cvss, source, url, date_str):
        nonlocal new_finds
        
        # 1. Date Check
        try:
            d_obj = datetime.strptime(date_str, "%Y-%m-%d")
            if d_obj < cutoff_date: return 
        except: pass
        
        # 2. Strict Normalization BEFORE Saving
        sev = normalize_severity(sev_raw)
        if not url: url = f"https://nvd.nist.gov/vuln/detail/{cve}"
        
        # 3. Deduplication
        if not any(a['cve'] == cve for a in alerts):
            new_alert = {
                "cve": cve, 
                "affected_asset": asset, 
                "description": desc,
                "severity": sev,  # Normalized!
                "cvss": float(cvss), 
                "source": source,
                "url": url, 
                "date": date_str
            }
            alerts.append(new_alert)
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
                
                # Extract CVSS
                match_cvss = re.search(r'\(([\d\.]+)', entry.title)
                score = float(match_cvss.group(1)) if match_cvss else (9.8 if sev_raw=="CRITICAL" else 7.5 if sev_raw=="HIGH" else 5.0)
                
                cve = entry.title.split()[0]
                date_str = datetime.now().strftime("%Y-%m-%d")
                add_alert(cve, match, entry.summary[:200]+"...", sev_raw, score, "NIST NVD", entry.link, date_str)
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
        st.markdown("### ⏱️ Live Mode")
        refresh_opt = st.selectbox("Auto-Refresh", ["Off", "30 Seconds", "5 Minutes", "15 Minutes"], label_visibility="collapsed")
        st.divider()
        st.caption(f"User: **Admin**")
        if st.button("Log Out"): st.session_state.authenticated = False; st.rerun()

    inventory = st.session_state.get("temp_inventory", load_json(INVENTORY_FILE, {"assets": [], "threshold_cvss": 7.0}))
    
    # LOAD DATA
    raw_alerts = load_json(ALERTS_FILE, [])
    triage_history = load_json(TRIAGE_FILE, [])
    
    # Separate Active vs Triaged
    triaged_cves = [t['cve'] for t in triage_history]
    active_alerts = [a for a in raw_alerts if a['cve'] not in triaged_cves]

    if page == "Dashboard":
        c1, c2 = st.columns([3, 1])
        with c1: st.title("Risk Dashboard")
        with c2: 
            if st.button("🔄 Refresh Feeds"):
                with st.spinner("Scanning..."):
                    lookback = inventory.get("lookback_days", 365)
                    n = run_scan(lookback)
                    st.toast(f"Found {n} new threats")
                    time.sleep(1); st.rerun()

        # METRICS
        risk_score = calculate_risk_score(active_alerts)
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Global Risk Score", risk_score, delta="Live Index", delta_color="inverse")
        m2.metric("Active Threats", len(active_alerts))
        m3.metric("Criticals", len([a for a in active_alerts if normalize_severity(a.get('severity')) == "CRITICAL"]))
        m4.metric("Triaged Today", len([t for t in triage_history if t['triaged_at'].startswith(str(datetime.now().date()))]))

        st.divider()
        
        # --- FILTERS (FIXED) ---
        with st.expander("🔎 Filter Intelligence", expanded=True):
            f1, f2, f3 = st.columns(3)
            with f1: 
                sev_filter = st.multiselect("Severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW"], default=["CRITICAL", "HIGH"])
            with f2: sort_by = st.selectbox("Sort By", ["Risk (CVSS)", "Newest First", "Asset Name"])
            with f3: min_cvss = st.slider("Min CVSS", 0.0, 10.0, 0.0)
            
            # DEBUG READOUT (Visible confirmation for User)
            st.caption(f"Debug: Showing {sev_filter} with CVSS >= {min_cvss}")

        # --- PANDAS FILTERING (ROBUST) ---
        if active_alerts:
            df = pd.DataFrame(active_alerts)
            
            # 1. Normalize Severity Column
            df['norm_severity'] = df['severity'].apply(normalize_severity)
            
            # 2. Apply Filters
            mask_sev = df['norm_severity'].isin(sev_filter)
            mask_cvss = df['cvss'] >= min_cvss
            
            df_filtered = df[mask_sev & mask_cvss]
            
            # 3. Sort
            if "Risk" in sort_by: df_filtered = df_filtered.sort_values(by="cvss", ascending=False)
            elif "Newest" in sort_by: df_filtered = df_filtered.sort_values(by="date", ascending=False)
            
            # Convert back to dict for rendering
            filtered_list = df_filtered.to_dict('records')
        else:
            filtered_list = []

        # --- RENDER LIST ---
        t1, t2 = st.tabs(["Active Threats", "Triage Log"])
        
        with t1:
            if not filtered_list: 
                if active_alerts:
                    st.info(f"Filters active. {len(active_alerts)} threats hidden.")
                else:
                    st.success("System Clean. No active threats detected.")
            
            for row in filtered_list:
                s_norm = row['norm_severity'] # Use the normalized value we calculated
                
                # Badge Color Logic
                s_cls = "crit" if s_norm == "CRITICAL" else "high" if s_norm == "HIGH" else "med" if s_norm == "MEDIUM" else "low"
                
                with st.container(border=True):
                    c_main, c_act = st.columns([4, 1.5])
                    with c_main:
                        st.markdown(f"### {row['affected_asset'].upper()} | {row['cve']}")
                        st.markdown(f"<span class='badge {s_cls}'>{s_norm}</span> <span class='badge {s_cls}'>CVSS {row['cvss']}</span>", unsafe_allow_html=True)
                        st.write(row['description'])
                        st.caption(f"**Sources:** {row['source']} • **Detected:** {row['date']}")
                        st.markdown(f"[🔗 Read Full Intelligence Report]({row.get('url', '#')})", unsafe_allow_html=True)
                    
                    with c_act:
                        st.write("**Triage**")
                        with st.form(key=f"form_{row['cve']}"):
                            decision = st.selectbox("Action", ["Select...", "True Positive", "False Positive", "Mitigated"], label_visibility="collapsed")
                            reason = st.text_input("Reasoning", placeholder="Notes...")
                            if st.form_submit_button("Confirm"):
                                if decision != "Select...":
                                    rec = row.copy()
                                    # Clean up pandas timestamp if present
                                    if isinstance(rec.get('cvss'), float): rec['cvss'] = float(rec['cvss'])
                                    rec.update({"decision": decision, "notes": reason, "triaged_at": str(datetime.now()), "triaged_by": "Admin"})
                                    triage_history.append(rec)
                                    save_json(TRIAGE_FILE, triage_history)
                                    st.toast("Triaged!")
                                    time.sleep(0.5); st.rerun()

        with t2:
            if triage_history:
                st.caption("History")
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
            st.toast("Database Flushed. Please Refresh Feeds.")
            time.sleep(1); st.rerun()

        st.divider()
        
        st.subheader("Thresholds & Scope")
        days = st.selectbox("Lookback Period (Days)", [30, 90, 365, 730], index=2)
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

    # --- AUTO REFRESH ---
    if refresh_opt != "Off":
        secs = {"30 Seconds": 30, "5 Minutes": 300, "15 Minutes": 900, "1 Hour": 3600}.get(refresh_opt, 300)
        time.sleep(secs)
        st.rerun()
