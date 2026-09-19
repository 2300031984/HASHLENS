"""
HashLens Dashboard - Evidence Reports Page
Generates forensic Evidence Reports, displays Evidence Report Hashes,
and exports canonical JSON or styled printable HTML reports.
"""

import streamlit as st
import json
from dashboard.utils.api_client import api_client
from backend.app.services.evidence_service import EvidenceService


def render():
    st.markdown('<div class="soc-header">FORENSIC EVIDENCE REPORTS</div>', unsafe_allow_html=True)
    st.markdown("Generate self-authenticating Evidence Reports containing cryptographic digests and tamper-audit proofs.")

    uploaded = st.file_uploader("Select asset for Evidence Report generation", key="ev_uploader")
    analyst_notes = st.text_input("Analyst Notes / Incident Reference", value="Standard forensic baseline verification.")

    if uploaded is not None:
        if st.button("Generate Evidence Report", key="btn_gen_report"):
            with st.spinner("Generating forensic evidence report & calculating Evidence Report Hash..."):
                file_bytes = uploaded.read()
                fp = api_client.hash_file(file_bytes, uploaded.name)
                report = api_client.generate_evidence(fp, notes=analyst_notes)

            st.success(f"Forensic Evidence Report generated: `{report['report_id']}`")

            # Big Evidence Report Hash Card
            st.markdown(
                f"""
                <div class="soc-card" style="border: 2px solid #00f0ff;">
                    <div class="stat-label">EVIDENCE REPORT HASH (SHA-256 FORENSIC SEAL)</div>
                    <div class="hash-box" style="color: #00f0ff; font-weight: bold; font-size: 15px;">
                        {report['evidence_report_hash']}
                    </div>
                    <div style="font-size: 12px; color: #94a3b8;">
                        This digest cryptographically seals the report metadata, digests, and audit state.
                        Any modification to this report will invalidate this hash.
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

            # Metadata and Hashes
            c1, c2 = st.columns(2)
            with c1:
                st.markdown("#### Asset Metadata")
                meta = report.get("file_metadata", {})
                st.write(f"**Filename:** `{meta.get('filename')}`")
                st.write(f"**Size:** `{meta.get('size_bytes')}` bytes ({meta.get('size_human')})")
                st.write(f"**MIME:** `{meta.get('mime_type')}`")
                st.write(f"**Chunks:** `{meta.get('total_chunks')}`")

            with c2:
                st.markdown("#### Cryptographic Digests")
                hashes = report.get("cryptographic_hashes", {})
                for alg, h in hashes.items():
                    st.write(f"**{alg.upper()}:** `{h}`")

            # Downloads
            st.markdown("---")
            st.subheader("Export Evidence Report")

            col_json, col_html = st.columns(2)

            json_str = json.dumps(report, indent=2)
            with col_json:
                st.download_button(
                    label="💾 Download Canonical JSON Report",
                    data=json_str,
                    file_name=f"{report['report_id']}.json",
                    mime="application/json",
                )

            html_report = EvidenceService.render_html_report(report)
            with col_html:
                st.download_button(
                    label="📄 Download Printable HTML Report",
                    data=html_report,
                    file_name=f"{report['report_id']}.html",
                    mime="text/html",
                )

            with st.expander("Preview HTML Report"):
                st.components.v1.html(html_report, height=600, scrolling=True)
