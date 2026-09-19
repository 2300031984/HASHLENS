"""
HashLens Dashboard - Hash Generator Page
Dual-mode text and file cryptographic hashing with copy tools and interactive avalanche simulator.
"""

import streamlit as st
import plotly.graph_objects as go
from dashboard.utils.api_client import api_client


def render():
    st.markdown('<div class="soc-header">CRYPTOGRAPHIC HASH GENERATOR</div>', unsafe_allow_html=True)

    tab_text, tab_file, tab_avalanche = st.tabs([
        "🔤 Text String Hashing",
        "📁 File Hashing (Streaming)",
        "⚡ Avalanche Effect Lab",
    ])

    # Tab 1: Text Hashing
    with tab_text:
        st.subheader("Generate Hashes from Text Input")
        user_text = st.text_area(
            "Input Text Payload",
            value="HashLens: Advanced File Integrity & Forensic Platform",
            height=100,
        )

        selected_algs = st.multiselect(
            "Select Algorithms",
            options=["md5", "sha1", "sha256", "sha512"],
            default=["md5", "sha1", "sha256", "sha512"],
        )

        if st.button("Generate Hashes", key="btn_hash_text"):
            if user_text is not None:
                res = api_client.hash_text(user_text, algorithms=selected_algs)
                hashes = res.get("hashes", {})

                st.markdown(f"**Input Stats:** `{res.get('input_length_chars')}` characters | `{res.get('input_length_bytes')}` UTF-8 bytes")

                for alg in selected_algs:
                    digest = hashes.get(alg, "")
                    badge_class = "badge-green" if alg in ["sha256", "sha512"] else "badge-red"
                    sec_label = "SECURE" if alg in ["sha256", "sha512"] else "LEGACY / BROKEN"

                    st.markdown(
                        f"""
                        <div class="soc-card" style="padding: 14px; margin-bottom: 12px;">
                            <div style="display: flex; justify-content: space-between; align-items: center;">
                                <strong style="color: #f8fafc; font-size: 14px;">{alg.upper()}</strong>
                                <span class="badge-tag {badge_class}">{sec_label}</span>
                            </div>
                            <div class="hash-box">{digest}</div>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )
                    st.code(digest, language=None)

    # Tab 2: File Hashing (Streaming)
    with tab_file:
        st.subheader("Streaming File Hash & Deep Fingerprint")
        uploaded_file = st.file_uploader("Upload file for forensic analysis (Processed in streaming chunks)", key="uploader_single")
        chunk_size_kb = st.select_slider(
            "Configurable Chunk Size",
            options=[64, 256, 512, 1024, 2048, 4096],
            value=1024,
            format_func=lambda x: f"{x} KiB",
        )

        if uploaded_file is not None:
            if st.button("Compute File Fingerprint", key="btn_hash_file"):
                with st.spinner("Processing file stream through cryptographic engines..."):
                    file_bytes = uploaded_file.read()
                    chunk_bytes = chunk_size_kb * 1024
                    fp = api_client.hash_file(file_bytes, uploaded_file.name, chunk_size=chunk_bytes)

                    st.success(f"Fingerprint generated successfully for `{fp['filename']}`")

                    # Metadata Grid
                    m1, m2, m3, m4 = st.columns(4)
                    m1.metric("File Size", fp["size_human"])
                    m2.metric("Detected MIME", fp["mime_type"])
                    m3.metric("Category", fp["file_category"])
                    m4.metric("Chunks Generated", f"{fp['chunk_count']} chunks")

                    # Hashes
                    st.markdown("#### Cryptographic Digests")
                    for alg, digest in fp["hashes"].items():
                        st.markdown(f"**{alg.upper()}**")
                        st.code(digest, language=None)

                    # Metadata Fingerprint
                    st.markdown("#### Metadata Fingerprint (Canonical JSON Hash)")
                    st.code(fp["metadata_fingerprint"], language=None)

                    # Chunk Explorer expander
                    with st.expander(f"Inspect Chunk Map ({fp['chunk_count']} total chunks)"):
                        st.dataframe(fp["chunk_fingerprints"][:50], use_container_width=True)

    # Tab 3: Avalanche Effect Lab
    with tab_avalanche:
        st.subheader("Cryptographic Avalanche Effect Explorer")
        st.markdown(
            "A key design property of cryptographic hashes: changing even a single bit in the input "
            "should alter approximately **50%** of the output digest bits in an unpredictable manner."
        )

        col_a, col_b = st.columns(2)
        with col_a:
            text1 = st.text_input("Input String A", value="The quick brown fox jumps over the lazy dog")
        with col_b:
            text2 = st.text_input("Input String B (1 character difference)", value="The quick brown fox jumps over the lazy cog")

        alg_choice = st.selectbox("Algorithm", options=["sha256", "sha512", "md5", "sha1"], index=0)

        if st.button("Analyze Avalanche Metrics"):
            res = api_client.calculate_avalanche(text1, text2, algorithm=alg_choice)

            st.markdown(f"**Digest A:** `{res['digest1']}`")
            st.markdown(f"**Digest B:** `{res['digest2']}`")

            k1, k2, k3 = st.columns(3)
            k1.metric("Total Bits", res["total_bits"])
            k2.metric("Flipped Bits", res["flipped_bits"])
            k3.metric("Bit Flip Rate", f"{res['flip_percentage']}%")

            # Plotly Gauge Chart
            fig = go.Figure(go.Indicator(
                mode="gauge+number",
                value=res["flip_percentage"],
                domain={'x': [0, 1], 'y': [0, 1]},
                title={'text': "Avalanche Bit-Flip Percentage (Ideal: ~50%)"},
                gauge={
                    'axis': {'range': [0, 100]},
                    'bar': {'color': "#00f0ff"},
                    'steps': [
                        {'range': [0, 35], 'color': "#334155"},
                        {'range': [35, 65], 'color': "#1e293b"},
                        {'range': [65, 100], 'color': "#334155"},
                    ],
                    'threshold': {
                        'line': {'color': "#10b981", 'width': 4},
                        'thickness': 0.75,
                        'value': 50,
                    }
                }
            ))
            fig.update_layout(
                paper_bgcolor="#131b2e",
                font={'color': "#f8fafc"},
                height=300,
                margin=dict(l=20, r=20, t=50, b=20),
            )
            st.plotly_chart(fig, use_container_width=True)
