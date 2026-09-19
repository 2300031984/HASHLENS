"""
HashLens Dashboard - Forensic Comparison Page
Compares two files or version fingerprints, computes chunk differential maps,
and delivers deterministic 'Why Did My Hash Change?' root-cause diagnosis.
"""

import streamlit as st
import pandas as pd
import plotly.express as px
from dashboard.utils.api_client import api_client


def render():
    st.markdown('<div class="soc-header">FORENSIC FILE COMPARISON & DIFF DIAGNOSTICS</div>', unsafe_allow_html=True)
    st.markdown("Perform differential analysis between two files or versions to pinpoint byte-level mutations.")

    col1, col2 = st.columns(2)
    with col1:
        file_a = st.file_uploader("Upload File A (Baseline / Original)", key="cmp_file_a")
    with col2:
        file_b = st.file_uploader("Upload File B (Target / Suspect)", key="cmp_file_b")

    chunk_size_kb = st.select_slider(
        "Granularity (Chunk Size)",
        options=[64, 256, 512, 1024, 2048],
        value=512,
        format_func=lambda x: f"{x} KiB",
        key="cmp_chunk_slider",
    )

    if file_a is not None and file_b is not None:
        if st.button("Execute Forensic Comparison", key="btn_run_compare"):
            with st.spinner("Streaming files and calculating chunk-level diffs..."):
                chunk_bytes = chunk_size_kb * 1024
                bytes_a = file_a.read()
                bytes_b = file_b.read()

                fp_a = api_client.hash_file(bytes_a, file_a.name, chunk_size=chunk_bytes)
                fp_b = api_client.hash_file(bytes_b, file_b.name, chunk_size=chunk_bytes)

                comp = api_client.compare_fingerprints(fp_a, fp_b)

            assessment = comp["assessment"]
            classification = assessment["classification"]

            # 1. Big Forensic Assessment Card ("Why Did My Hash Change?")
            class_badge_color = {
                "NO_CHANGE": "#10b981",
                "CONTENT_MODIFICATION": "#f59e0b",
                "SIZE_CHANGE": "#38bdf8",
                "STRUCTURAL_CHANGE": "#a855f7",
                "METADATA_CHANGE": "#00f0ff",
                "FILE_TYPE_CHANGE": "#ec4899",
                "MAJOR_REPLACEMENT": "#ef4444",
                "INCONCLUSIVE": "#64748b",
            }.get(classification, "#00f0ff")

            st.markdown(
                f"""
                <div class="soc-card" style="border-top: 4px solid {class_badge_color};">
                    <div style="display: flex; justify-content: space-between; align-items: flex-start;">
                        <div>
                            <div class="stat-label">WHY DID MY HASH CHANGE? - DETERMINISTIC ASSESSMENT</div>
                            <h2 style="color: {class_badge_color}; margin: 4px 0 8px 0; letter-spacing: 0.05em;">
                                {classification}
                            </h2>
                            <div style="font-size: 14px; color: #f8fafc; font-weight: 500;">
                                {assessment['summary']}
                            </div>
                        </div>
                        <div style="text-align: right;">
                            <div class="stat-label">CHANGE METRIC</div>
                            <div style="font-size: 28px; font-weight: 800; color: #00f0ff;">
                                {comp['change_percentage']}%
                            </div>
                        </div>
                    </div>
                    <div style="margin-top: 14px; border-top: 1px solid #1e293b; padding-top: 10px;">
                        <strong style="font-size: 12px; color: #94a3b8; text-transform: uppercase;">Forensic Evidence Points:</strong>
                        <ul style="margin-top: 6px; font-size: 13px; color: #cbd5e1; padding-left: 20px;">
                            {''.join(f'<li>{pt}</li>' for pt in assessment['evidence_points'])}
                        </ul>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

            # 2. Metric Comparative Grid
            m1, m2, m3, m4 = st.columns(4)
            m1.metric("SHA-256 Changed", "YES" if comp["sha256_changed"] else "NO", delta=None)
            m2.metric("Size Delta", comp["size_delta_human"], delta=comp["size_delta_human"])
            m3.metric("Matching Chunks", f"{comp['chunks_matching']} chunks")
            m4.metric("Changed Chunks", f"{comp['chunks_changed']} chunks")

            # 3. Visual Chunk Diff Block Map
            st.markdown("### Chunk Alignment Map")
            diffs = comp.get("chunk_diffs", [])
            if diffs:
                # Render visual blocks
                blocks_html = '<div style="display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 20px;">'
                for d in diffs:
                    status = d["status"]
                    color = "#10b981" if status == "UNCHANGED" else "#ef4444" if status == "MODIFIED" else "#38bdf8"
                    blocks_html += (
                        f'<div style="background-color: {color}; width: 26px; height: 26px; border-radius: 4px; '
                        f'display: flex; align-items: center; justify-content: center; font-size: 10px; '
                        f'font-weight: bold; color: #0b0f19;" title="Chunk #{d["index"]}: {status}">{d["index"]}</div>'
                    )
                blocks_html += '</div>'
                st.markdown(blocks_html, unsafe_allow_html=True)
                st.caption("Legend: 🟩 Unchanged Matching Chunk | 🟥 Modified Byte Chunk | 🟦 Added Chunk")

            # 4. Detailed Chunk Diff Table
            with st.expander("Explore Detailed Chunk Diff Table"):
                df_diff = pd.DataFrame(diffs)
                st.dataframe(df_diff, use_container_width=True)

            # 5. Side-by-side Digest Inspection
            with st.expander("Compare Full Cryptographic Digests"):
                c_a, c_b = st.columns(2)
                with c_a:
                    st.markdown(f"**File A:** `{fp_a['filename']}`")
                    for alg, h in fp_a["hashes"].items():
                        st.text(f"{alg.upper()}: {h}")
                with c_b:
                    st.markdown(f"**File B:** `{fp_b['filename']}`")
                    for alg, h in fp_b["hashes"].items():
                        st.text(f"{alg.upper()}: {h}")
