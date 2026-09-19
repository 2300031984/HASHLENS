"""
HashLens Dashboard - Integrity Chain Page
Visualizes the mathematically linked Tamper-Evident Hash Chain,
runs cryptographic integrity audits, and provides live tamper detection simulations.
"""

import streamlit as st
import pandas as pd
from dashboard.utils.api_client import api_client


def render():
    st.markdown('<div class="soc-header">TAMPER-EVIDENT INTEGRITY CHAIN</div>', unsafe_allow_html=True)
    st.markdown(
        """
        HashLens records every integrity event into a mathematically linked **Tamper-Evident Hash Chain**:
        <br><code>H₁ = SHA256(Record₁)</code> &nbsp;|&nbsp; 
        <code>H₂ = SHA256(Record₂ + H₁)</code> &nbsp;|&nbsp; 
        <code>Hₙ = SHA256(Recordₙ + Hₙ₋₁)</code>
        <br>Any retroactive modification, block deletion, or reordering breaks downstream cryptographic continuity.
        """,
        unsafe_allow_html=True,
    )

    st.markdown("<br>", unsafe_allow_html=True)

    # 1. Audit Runner Section
    col_audit, col_sim = st.columns([1, 1])

    with col_audit:
        if st.button("🔍 Run Full Cryptographic Audit", key="btn_run_audit"):
            with st.spinner("Auditing cryptographic links across all records..."):
                audit = api_client.verify_chain()

            if audit.get("valid"):
                st.success(f"✓ CHAIN VALID: All {audit.get('total_records')} audit records verified untampered.")
                st.markdown(f"**Chain Head Digest:** `{audit.get('head_hash')}`")
            else:
                st.error(f"✗ {audit.get('status')}: Cryptographic failure detected!")
                st.markdown(f"**Broken Record ID:** `{audit.get('broken_record_id')}` (Seq #{audit.get('sequence_num')})")
                st.markdown(f"**Diagnosis:** {audit.get('reason')}")

    # 2. Tamper Simulation Lab (Demonstration Mode)
    with col_sim:
        with st.expander("⚠️ Tamper Simulation Lab (Demonstration)"):
            st.caption("Demonstrate tamper detection by deliberately altering a record in the database.")
            records = api_client.get_chain_records(limit=20)
            if records:
                rec_choices = {f"Seq #{r['sequence_num']} ({r['event_type']}) - {r['record_id'][:8]}...": r["record_id"] for r in records}
                chosen_label = st.selectbox("Select Block to Tamper", options=list(rec_choices.keys()))
                chosen_id = rec_choices[chosen_label]

                if st.button("Inject Tampered Payload", key="btn_tamper_payload"):
                    res = api_client.simulate_tamper(chosen_id)
                    st.warning(res.get("message", "Tamper injected."))
                    st.info("Now click 'Run Full Cryptographic Audit' above to watch the platform pinpoint the exact altered block!")
            else:
                st.info("No records to tamper. Register a file first.")

    st.markdown("---")

    # 3. Chain Records Inspector
    st.subheader("Audit Chain Ledger")
    records = api_client.get_chain_records(limit=50)

    if records:
        df_records = []
        for r in records:
            df_records.append({
                "Seq #": f"#{r['sequence_num']}",
                "Timestamp": r["timestamp"][:19].replace("T", " "),
                "Event Type": r["event_type"],
                "File Hash": r["file_hash"][:16] + "...",
                "Previous Block Hash": r["previous_record_hash"][:16] + "...",
                "Current Block Hash": r["current_record_hash"][:16] + "...",
                "Record ID": r["record_id"],
            })
        st.dataframe(pd.DataFrame(df_records), use_container_width=True, hide_index=True)
    else:
        st.info("No integrity events yet. HASHLENS will create chain records as tracked integrity events are recorded.")
