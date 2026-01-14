import streamlit as st
import json
import os
import pandas as pd
from datetime import datetime

# --- CONFIGURATION ---
INVENTORY_FILE = "inventory.json"
ALERTS_FILE = "alerts.json"

st.set_page_config(page_title="Threat Intel Manager", page_icon="🛡️", layout="wide")

def load_json(filepath, default):
    if not os.path.exists(filepath): return default
    with open(filepath, "r") as f: return json.load(f)

def save_json(filepath, data):
    with open(filepath, "w") as f: json.dump(data, f, indent=4)

# --- UI LOGIC ---
st.title("🛡️ Threat Intel Control Center")

# Load Data
data = load_json(INVENTORY_FILE, {"assets": [], "threshold_cvss": 7.0, "slack_webhook": ""})
alerts = load_json(ALERTS_FILE, [])

# TABS
tab1, tab2, tab3 = st.tabs(["🔴 Live Threat Feed", "📦 Inventory & Filters", "⚙️ Integrations"])

# --- TAB 1: THE FEED ---
with tab1:
    st.markdown("### Detected Threats")
    if alerts:
        # Convert to DataFrame for sorting
        df = pd.DataFrame(alerts)
        if not df.empty:
            # Sort by date (newest first)
            df = df.iloc[::-1]
            
            for index, row in df.iterrows():
                # Color code severity
                color = "red" if "CRITICAL" in row['severity'].upper() else "orange"
                
                with st.container(border=True):
                    c1, c2 = st.columns([1, 5])
                    with c1:
                        st.markdown(f":{color}[**{row['severity']}**]")
                        st.caption(row['date'])
                    with c2:
                        st.subheader(f"{row['affected_asset'].upper()} - {row['cve']}")
                        st.write(row['description'])
                        st.caption(f"Source: {row['source']}")
    else:
        st.success("No threats detected matching your inventory.")

# --- TAB 2: INVENTORY (Existing Logic) ---
with tab2:
    st.subheader("Asset Watchlist")
    
    # 1. Threshold
    new_threshold = st.slider("Min CVSS Score", 0.0, 10.0, float(data.get("threshold_cvss", 7.0)), 0.1)
    if new_threshold != data.get("threshold_cvss"):
        data["threshold_cvss"] = new_threshold
        save_json(INVENTORY_FILE, data)
        st.toast("Saved!")

    st.divider()

    # 2. Add Asset
    c1, c2 = st.columns([3, 1])
    new_asset = c1.text_input("Add Software", placeholder="e.g. nginx")
    if c2.button("➕ Add", use_container_width=True):
        if new_asset and new_asset not in data["assets"]:
            data["assets"].append(new_asset)
            save_json(INVENTORY_FILE, data)
            st.rerun()

    # 3. View Assets
    if data["assets"]:
        st.markdown(f"**Tracking {len(data['assets'])} assets:**")
        cols = st.columns(4)
        for i, asset in enumerate(data["assets"]):
            with cols[i % 4]:
                st.info(f"**{asset}**")
                if st.button("🗑️", key=f"del_{asset}"):
                    data["assets"].remove(asset)
                    save_json(INVENTORY_FILE, data)
                    st.rerun()

# --- TAB 3: INTEGRATIONS ---
with tab3:
    st.subheader("🔔 Notification Channels")
    
    current_webhook = data.get("slack_webhook", "")
    new_webhook = st.text_input("Slack Webhook URL", value=current_webhook, type="password")
    
    if st.button("Save Integration"):
        data["slack_webhook"] = new_webhook
        save_json(INVENTORY_FILE, data)
        st.success("Webhook saved! The Agent will now push alerts to Slack.")
    
    with st.expander("How to get a Webhook URL"):
        st.markdown("""
        1. Go to [api.slack.com/apps](https://api.slack.com/apps).
        2. Create a New App > "From Scratch".
        3. Click **Incoming Webhooks** > Toggle "On".
        4. Click **Add New Webhook to Workspace**.
        5. Copy the URL (starts with `https://hooks.slack.com/...`).
        """)
