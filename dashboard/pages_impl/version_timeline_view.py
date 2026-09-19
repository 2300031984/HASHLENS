"""
HashLens Dashboard - Version Timeline Page
Renders interactive version progression timelines and historical integrity analysis for tracked assets.
"""

import streamlit as st
import pandas as pd
from dashboard.utils.api_client import api_client


def render():
    st.markdown('<div class="soc-header">ASSET VERSION INTEGRITY TIMELINE</div>', unsafe_allow_html=True)
    st.markdown("Inspect historical version progressions and forensic audit trajectories for tracked files.")

    tracked_files = api_client.get_tracked_files()

    if not tracked_files:
        st.info("No files currently tracked. Go to 'File Integrity' or 'Hash Generator' to register an asset baseline.")
        return

    # Select box of files
    file_map = {f"{f['filename']} ({f['latest_version']} versions)": f["file_id"] for f in tracked_files}
    selected_label = st.selectbox("Select Tracked File", options=list(file_map.keys()))
    selected_file_id = file_map[selected_label]

    timeline_data = api_client.get_timeline(selected_file_id)

    st.markdown(f"### Historical Progression: `{timeline_data['filename']}`")
    st.markdown(f"**Total Tracked Versions:** `{timeline_data['total_versions']}` | **Type:** `{timeline_data['file_type']}`")

    # Interactive timeline sequence
    nodes = timeline_data.get("timeline", [])

    for idx, node in enumerate(nodes):
        v_num = node["version_num"]
        status = node["integrity_status"]
        badge_color = {
            "ORIGINAL": "#38bdf8",
            "UNCHANGED": "#10b981",
            "MODIFIED": "#ef4444",
        }.get(status, "#f59e0b")

        st.markdown(
            f"""
            <div class="soc-card" style="border-left: 5px solid {badge_color}; margin-bottom: 16px;">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <span style="font-size: 18px; font-weight: 800; color: #f8fafc;">VERSION {v_num}</span>
                        <span style="color: #64748b; font-size: 12px; margin-left: 12px;">{node['timestamp'][:19].replace('T', ' ')} UTC</span>
                    </div>
                    <span class="badge-tag" style="background: rgba(255,255,255,0.05); color: {badge_color}; border: 1px solid {badge_color};">
                        {status}
                    </span>
                </div>
                <div style="margin-top: 10px; font-size: 13px; color: #94a3b8;">
                    <strong>Change Summary:</strong> {node.get('change_summary') or 'Baseline registered.'}
                </div>
                <div style="display: flex; gap: 24px; margin-top: 10px; font-size: 12px;">
                    <div><span style="color: #64748b;">Size:</span> <strong>{node['size_human']}</strong> ({node['size_bytes']} B)</div>
                    <div><span style="color: #64748b;">Chunks:</span> <strong>{node['chunk_count']}</strong> chunks</div>
                </div>
                <div style="margin-top: 10px;">
                    <span style="font-size: 11px; text-transform: uppercase; color: #64748b;">SHA-256 DIGEST:</span>
                    <div class="hash-box" style="margin-top: 2px;">{node['sha256']}</div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        if idx < len(nodes) - 1:
            st.markdown(
                """
                <div style="text-align: center; color: #00f0ff; margin: -10px 0 10px 0; font-size: 18px;">
                    ↓
                </div>
                """,
                unsafe_allow_html=True,
            )
