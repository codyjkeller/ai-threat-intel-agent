import streamlit as st
import json
import os
import pandas as pd

# --- CONFIGURATION ---
INVENTORY_FILE = "inventory.json"
st.set_page_config(page_title="Threat Intel Manager", page_icon="🛡️")

def load_inventory():
    if not os.path.exists(INVENTORY_FILE):
        return {"assets": [], "threshold_cvss": 7.0}
    with open(INVENTORY_FILE, "r") as f:
        return json.load(f)

def save_inventory(data):
    with open(INVENTORY_FILE, "w") as f:
        json.dump(data, f, indent=4)

# --- UI LOGIC ---
st.title("🛡️ Threat Intel Control Center")
st.caption("Curate your SBOM (Software Bill of Materials) to filter threat feeds.")

# Load Data
data = load_inventory()
assets = data.get("assets", [])
threshold = data.get("threshold_cvss", 7.0)

# 1. THRESHOLD SETTING
st.subheader("🚨 Alert Sensitivity")
new_threshold = st.slider(
    "Minimum CVSS Score to Alert", 
    min_value=0.0, max_value=10.0, value=float(threshold), step=0.1,
    help="7.0+ is High/Critical. Lowering this increases noise."
)

if new_threshold != threshold:
    data["threshold_cvss"] = new_threshold
    save_inventory(data)
    st.toast("Sensitivity Updated!")

st.divider()

# 2. ASSET MANAGEMENT
st.subheader("📦 Asset Watchlist")

col1, col2 = st.columns([3, 1])
with col1:
    new_asset = st.text_input("Add Software to Track", placeholder="e.g. nginx, salesforce, zoom")
with col2:
    st.write("") # Spacer
    st.write("") 
    if st.button("➕ Add", type="primary", use_container_width=True):
        if new_asset and new_asset.lower() not in [a.lower() for a in assets]:
            assets.append(new_asset)
            data["assets"] = assets
            save_inventory(data)
            st.rerun()
        elif new_asset:
            st.warning("Asset already in list.")

# Display List with Delete Buttons
if assets:
    st.markdown(f"**Tracking {len(assets)} unique technologies:**")
    
    # Grid Layout for Chips
    cols = st.columns(4)
    for i, asset in enumerate(assets):
        with cols[i % 4]:
            st.info(f"**{asset}**")
            if st.button(f"🗑️", key=f"del_{asset}"):
                assets.remove(asset)
                data["assets"] = assets
                save_inventory(data)
                st.rerun()
else:
    st.info("Watchlist is empty. Add software above to start tracking.")

# 3. PREVIEW RAW FILE
with st.expander("📄 View Raw Inventory File"):
    st.json(data)
