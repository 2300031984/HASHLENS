"""
HashLens Dashboard - Overview Page
Displays operational SOC metrics, chain status, recent activity feed, and cryptographic health.
"""

import streamlit as st
import pandas as pd
import plotly.express as px
from dashboard.utils.api_client import api_client


def render():
    st.markdown('<div class="soc-header">SOC INTEGRITY & FORENSICS OVERVIEW</div>', unsafe_allow_html=True)

    # 1. Fetch live metrics from persistence & chain
    tracked_files = api_client.get_tracked_files()
    chain_records = api_client.get_chain_records(limit=100)
    chain_audit = api_client.verify_chain()

    total_files = len(tracked_files)
    total_events = len(chain_records)
    changes_detected = sum(1 for f in tracked_files if f.get("latest_status") == "MODIFIED")
    chain_status = chain_audit.get("status", "UNKNOWN")

    # 2. Top Metric Cards Grid
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.markdown(
            f"""
            <div class="soc-card">
                <div class="stat-label">TRACKED ASSETS</div>
                <div class="stat-value">{total_files}</div>
                <div style="font-size: 11px; color: #94a3b8; margin-top: 4px;">Registered Baselines</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col2:
        st.markdown(
            f"""
            <div class="soc-card">
                <div class="stat-label">AUDIT CHAIN EVENTS</div>
                <div class="stat-value">{total_events}</div>
                <div style="font-size: 11px; color: #94a3b8; margin-top: 4px;">Cryptographic Blocks</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col3:
        st.markdown(
            f"""
            <div class="soc-card">
                <div class="stat-label">MODIFIED ASSETS</div>
                <div class="stat-value" style="color: {'#ef4444' if changes_detected > 0 else '#10b981'};">{changes_detected}</div>
                <div style="font-size: 11px; color: #94a3b8; margin-top: 4px;">Integrity Divergences</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col4:
        chain_color = "#10b981" if chain_audit.get("valid") else "#ef4444"
        st.markdown(
            f"""
            <div class="soc-card">
                <div class="stat-label">CHAIN STATUS</div>
                <div class="stat-value" style="color: {chain_color}; font-size: 24px;">{chain_status}</div>
                <div style="font-size: 11px; color: #94a3b8; margin-top: 4px;">
                    {'100% Cryptographically Valid' if chain_audit.get('valid') else 'Fault Detected!'}
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.markdown("<br>", unsafe_allow_html=True)

    # 3. Two Column Layout: Recent Activity vs Cryptographic Standards
    c_left, c_right = st.columns([3, 2])

    with c_left:
        st.subheader("Live Forensics & Audit Feed")
        if chain_records:
            feed_data = []
            for r in chain_records[:10]:
                feed_data.append({
                    "Seq #": f"#{r['sequence_num']}",
                    "Timestamp": r["timestamp"][:19].replace("T", " "),
                    "Event Type": r["event_type"],
                    "File Hash (SHA-256)": r["file_hash"][:16] + "...",
                    "Block Hash": r["current_record_hash"][:16] + "...",
                })
            df_feed = pd.DataFrame(feed_data)
            st.dataframe(df_feed, use_container_width=True, hide_index=True)
        else:
            st.info("No audit chain events recorded yet. Upload a file or generate an evidence report to populate the audit log.")

    with c_right:
        st.subheader("Cryptographic Algorithms Status")
        alg_data = pd.DataFrame({
            "Algorithm": ["SHA-256", "SHA-512", "SHA-1", "MD5"],
            "Security Level": ["Secure Standard", "High Security", "Broken", "Compromised"],
            "Digest Size": ["256 bits", "512 bits", "160 bits", "128 bits"],
            "Collision Resistant": ["Yes", "Yes", "No (SHAttered)", "No (Wang 2004)"],
        })
        st.dataframe(alg_data, use_container_width=True, hide_index=True)

        st.markdown(
            """
            <div class="soc-card" style="margin-top: 15px; padding: 14px;">
                <div style="font-size: 12px; font-weight: bold; color: #f59e0b;">FORENSIC ADVISORY:</div>
                <div style="font-size: 12px; color: #94a3b8; margin-top: 4px;">
                    MD5 and SHA-1 are provided strictly for backward compatibility and legacy verification.
                    All primary forensic integrity checks and hash-chain audits in HashLens mandate SHA-256.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
