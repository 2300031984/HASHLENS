"""
HashLens Dashboard
Security Operations Center (SOC) style web interface for file integrity,
chunk forensics, version timelines, tamper-evident chaining, and evidence reporting.
"""

import streamlit as st
from dashboard.utils.styles import apply_soc_theme
from dashboard.utils.api_client import api_client

st.set_page_config(
    page_title="HashLens | File Integrity & Forensics",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

apply_soc_theme()

# Sidebar Header & Quick Status
st.sidebar.markdown(
    """
    <div style="text-align: center; padding: 10px 0 20px 0;">
        <h2 style="color: #00f0ff; margin-bottom: 2px; font-weight: 800; letter-spacing: 0.1em;">HASHLENS</h2>
        <div style="font-size: 11px; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.15em;">
            File Integrity & Forensics Platform
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)

# Live Chain Heartbeat in Sidebar
health = api_client.get_health()
chain_badge = "badge-green" if health.get("chain_health") == "CHAIN_VALID" else "badge-yellow"
if health.get("chain_health") == "CHAIN_BROKEN":
    chain_badge = "badge-red"

st.sidebar.markdown(
    f"""
    <div class="soc-card" style="padding: 12px; margin-bottom: 20px;">
        <div class="stat-label">PLATFORM STATUS</div>
        <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 6px;">
            <span style="font-size: 13px; font-weight: 600;">{health.get('status', 'ONLINE').upper()}</span>
            <span class="badge-tag {chain_badge}">{health.get('chain_health', 'CHAIN_VALID')}</span>
        </div>
        <div style="font-size: 11px; color: #64748b; margin-top: 6px;">
            v{health.get('version', '1.0.0')} | Env: {health.get('environment', 'dev')}
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)

# Navigation Menu
nav_choice = st.sidebar.radio(
    "NAVIGATION",
    [
        "1. Overview",
        "2. Hash Generator",
        "3. File Integrity",
        "4. Compare Files",
        "5. Version Timeline",
        "6. Integrity Chain",
        "7. Evidence Reports",
        "8. Security Guide",
        "9. API Information",
    ],
    index=0,
)

st.sidebar.markdown("---")
st.sidebar.caption("HashLens Forensics Platform • Python 3.11 • FastAPI • SQLite/PostgreSQL")

# Route to Page View
if nav_choice == "1. Overview":
    from dashboard.pages_impl import overview_view
    overview_view.render()
elif nav_choice == "2. Hash Generator":
    from dashboard.pages_impl import hash_generator_view
    hash_generator_view.render()
elif nav_choice == "3. File Integrity":
    from dashboard.pages_impl import file_integrity_view
    file_integrity_view.render()
elif nav_choice == "4. Compare Files":
    from dashboard.pages_impl import compare_files_view
    compare_files_view.render()
elif nav_choice == "5. Version Timeline":
    from dashboard.pages_impl import version_timeline_view
    version_timeline_view.render()
elif nav_choice == "6. Integrity Chain":
    from dashboard.pages_impl import integrity_chain_view
    integrity_chain_view.render()
elif nav_choice == "7. Evidence Reports":
    from dashboard.pages_impl import evidence_reports_view
    evidence_reports_view.render()
elif nav_choice == "8. Security Guide":
    from dashboard.pages_impl import security_guide_view
    security_guide_view.render()
elif nav_choice == "9. API Information":
    from dashboard.pages_impl import api_info_view
    api_info_view.render()
