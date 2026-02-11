import streamlit as st
import json
import os
import pandas as pd
import logging
from datetime import datetime

# --- ENTERPRISE CONFIGURATION ---
INVENTORY_FILE = "inventory.json"
ALERTS_FILE = "alerts.json"

# Configure Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - [DASHBOARD] - %(message)s')
logger = logging.getLogger(__name__)

st.set_page_config(
    page_title="Threat Intel Manager",
    page_icon="security_shield", # Professional icon alias
    layout="wide"
)

# --- UTILITIES ---
def load_json(filepath, default):
    if not os.path.exists(filepath):
        logger.info(f"File not found: {filepath}. Using default.")
        return default
    try:
        with open(filepath, "r") as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        logger.error(f"Failed to load {filepath}: {e}")
        return default

def save_json(filepath, data):
    try:
        with open(filepath, "w") as f:
            json.dump(data, f, indent=4)
        logger.info(f"Saved configuration to {filepath}")
        return True
    except IOError as e:
        logger.error(f"Failed to save {filepath}: {e}")
        st.error(f"System Error: Could not save configuration. {e}")
        return False

# --- MAIN APPLICATION ---
def main():
    st.title("Threat Intelligence Control Center")

    # Load Persistence Layer
    data = load_json(INVENTORY_FILE, {"assets": [], "threshold_cvss": 7.0, "slack_webhook": ""})
    alerts = load_json(ALERTS_FILE, [])

    # Navigation Tabs
    tab1, tab2, tab3 = st.tabs(["Live Threat Feed", "Inventory & Filters", "Integrations"])

    # --- TAB 1: THREAT FEED ---
    with tab1:
        st.markdown("### Detected Threats")
        
        if not alerts:
            st.info("System Status: Normal. No active threats detected matching inventory.")
        else:
            # Data Processing
            df = pd.DataFrame(alerts)
            if not df.empty:
                # Sort newest first
                if 'date' in df.columns:
                    df = df.iloc[::-1]
                
                for index, row in df.iterrows():
                    # Determine Severity Styling
                    severity = row.get('severity', 'UNKNOWN').upper()
                    is_critical = "CRITICAL" in severity
                    
                    # Enterprise Card Design
                    with st.container(border=True):
                        c1, c2 = st.columns([1, 6])
                        with c1:
                            if is_critical:
                                st.error(f"**{severity}**", icon="🚨")
                            else:
                                st.warning(f"**{severity}**", icon="⚠️")
                            st.caption(f"Date: {row.get('date', 'N/A')}")
                        
                        with c2:
                            asset_name = row.get('affected_asset', 'Unknown').upper()
                            cve_id = row.get('cve', 'Unknown ID')
                            st.subheader(f"{asset_name} | {cve_id}")
                            st.write(row.get('description', 'No description available.'))
                            st.markdown(f"**Source:** {row.get('source', 'Unknown')}")

    # --- TAB 2: INVENTORY ---
    with tab2:
        st.subheader("Asset Configuration")
        
        # 1. Risk Policy
        st.markdown("**Risk Policy**")
        current_thresh = float(data.get("threshold_cvss", 7.0))
        new_threshold = st.slider("Minimum CVSS Score for Alerting", 0.0, 10.0, current_thresh, 0.1)
        
        if new_threshold != current_thresh:
            data["threshold_cvss"] = new_threshold
            save_json(INVENTORY_FILE, data)
            st.toast("Policy updated.")

        st.divider()

        # 2. Asset Management
        st.markdown("**Asset Whitelist**")
        c1, c2 = st.columns([3, 1])
        new_asset = c1.text_input("Register New Software/Asset", placeholder="e.g. nginx, kubernetes")
        
        if c2.button("Register Asset", use_container_width=True):
            if new_asset:
                if new_asset not in data["assets"]:
                    data["assets"].append(new_asset)
                    if save_json(INVENTORY_FILE, data):
                        st.success(f"Successfully registered: {new_asset}")
                        st.rerun()
                else:
                    st.warning("Asset already exists in inventory.")

        # 3. Asset Grid
        if data.get("assets"):
            st.markdown(f"**Monitoring {len(data['assets'])} Assets**")
            
            # Display assets in a clean grid
            assets = data["assets"]
            cols = st.columns(4)
            for i, asset in enumerate(assets):
                with cols[i % 4]:
                    with st.container(border=True):
                        st.markdown(f"**{asset}**")
                        if st.button("Remove", key=f"del_{asset}"):
                            data["assets"].remove(asset)
                            save_json(INVENTORY_FILE, data)
                            st.rerun()
        else:
            st.info("Inventory is empty. Add assets to begin monitoring.")

    # --- TAB 3: INTEGRATIONS ---
    with tab3:
        st.subheader("Notification Channels")
        st.markdown("Configure downstream alerting services.")
        
        current_webhook = data.get("slack_webhook", "")
        new_webhook = st.text_input("Slack Webhook URL", value=current_webhook, type="password")
        
        if st.button("Save Configuration"):
            data["slack_webhook"] = new_webhook
            if save_json(INVENTORY_FILE, data):
                st.success("Configuration saved successfully.")
        
        with st.expander("Configuration Guide"):
            st.markdown("""
            1. Navigate to your Slack App settings.
            2. Enable **Incoming Webhooks**.
            3. Create a new webhook for your desired channel.
            4. Paste the URL (starts with `https://hooks.slack.com/...`) above.
            """)

if __name__ == "__main__":
    main()
