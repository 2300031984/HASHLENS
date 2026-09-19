"""
HashLens Dashboard - File Integrity Page
Uploads file, computes deep forensic fingerprint, checks against baseline,
and provides status (NEW, UNCHANGED, MODIFIED) with version commitment.
"""

import streamlit as st
import pandas as pd
from dashboard.utils.api_client import api_client


def render():
    st.markdown('<div class="soc-header">FILE INTEGRITY MONITORING & BASELINING</div>', unsafe_allow_html=True)
    st.markdown("Analyze an asset to assess its current integrity state against existing forensic baselines.")

    uploaded = st.file_uploader("Select file for integrity analysis", key="fi_uploader")

    if uploaded is not None:
        file_bytes = uploaded.read()

        with st.spinner("Executing chunked forensic hashing..."):
            fp = api_client.hash_file(file_bytes, uploaded.name)

        st.markdown("### Forensic Fingerprint Summary")

        # Inspect if asset exists in repository
        tracked_files = api_client.get_tracked_files()
        matching_file = next((f for f in tracked_files if f["filename"] == fp["filename"]), None)

        if matching_file is None:
            status_text = "NEW ASSET"
            status_class = "badge-blue"
            desc = "This file has not been registered yet. It can be initialized as Version 1 baseline."
        elif matching_file.get("latest_sha256") == fp["hashes"]["sha256"]:
            status_text = "UNCHANGED"
            status_class = "badge-green"
            desc = f"Matches recorded baseline Version {matching_file.get('latest_version')} (SHA-256 identical)."
        else:
            status_text = "MODIFIED"
            status_class = "badge-red"
            desc = f"Divergence detected against Version {matching_file.get('latest_version')}! Content has been altered."

        # Banner with Status
        st.markdown(
            f"""
            <div class="soc-card" style="border-left: 5px solid {'#10b981' if status_text in ['UNCHANGED', 'NEW ASSET'] else '#ef4444'};">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <div class="stat-label">INTEGRITY STATUS</div>
                        <div style="font-size: 22px; font-weight: 800; color: #f8fafc; margin-top: 4px;">{status_text}</div>
                    </div>
                    <span class="badge-tag {status_class}" style="font-size: 14px; padding: 6px 16px;">{status_text}</span>
                </div>
                <div style="font-size: 13px; color: #94a3b8; margin-top: 8px;">{desc}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        # File Properties Table
        c1, c2, c3 = st.columns(3)
        c1.metric("Filename", fp["filename"])
        c2.metric("File Size", f"{fp['size_human']} ({fp['size_bytes']} B)")
        c3.metric("Detected MIME", fp["mime_type"])

        st.markdown("#### Primary Cryptographic Digest (SHA-256)")
        st.code(fp["hashes"]["sha256"], language=None)

        st.markdown("#### Full Algorithm Suite")
        col_m, col_s1, col_s5 = st.columns(3)
        with col_m:
            st.caption("MD5 (Checksum)")
            st.code(fp["hashes"]["md5"], language=None)
        with col_s1:
            st.caption("SHA-1 (Legacy)")
            st.code(fp["hashes"]["sha1"], language=None)
        with col_s5:
            st.caption("SHA-512 (High Security)")
            st.code(fp["hashes"]["sha512"][:32] + "...", language=None)

        st.markdown("---")

        # Track & Commit Button
        action_label = "Register as Version 1 Baseline" if matching_file is None else "Commit as New Version to Hash Chain"
        if st.button(f"🛡️ {action_label}", key="btn_commit_version"):
            with st.spinner("Recording version and appending to Tamper-Evident Hash Chain..."):
                res = api_client.track_file(fp)
                st.success(f"{res.get('message')} (Version {res.get('version')})")
                st.rerun()

        # Chunk breakdown table
        with st.expander("View Chunk Block Map"):
            df_chunks = pd.DataFrame(fp["chunk_fingerprints"])
            st.dataframe(df_chunks, use_container_width=True)
