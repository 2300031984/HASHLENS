"""
HashLens Dashboard - API Information Page
API catalog, interactive curl examples, OpenAPI links, and Burp/ZAP security testing guidance.
"""

import streamlit as st
from backend.app.core.config import settings


def render():
    st.markdown('<div class="soc-header">REST API DOCUMENTATION & INTEGRATION</div>', unsafe_allow_html=True)

    st.markdown(
        f"""
        HashLens exposes a secure, high-throughput REST API suitable for SIEM, SOAR,
        CI/CD security pipelines, and automated forensic ingest.
        <br><br>
        * **API Base URL:** <code>http://{settings.API_HOST}:{settings.API_PORT}{settings.API_V1_PREFIX}</code>
        * **Interactive Swagger UI:** <a href="http://localhost:8000/docs" target="_blank" style="color: #00f0ff;">http://localhost:8000/docs</a>
        * **ReDoc Reference:** <a href="http://localhost:8000/redoc" target="_blank" style="color: #00f0ff;">http://localhost:8000/redoc</a>
        * **OpenAPI JSON Schema:** <a href="http://localhost:8000/api/v1/openapi.json" target="_blank" style="color: #00f0ff;">/api/v1/openapi.json</a>
        """,
        unsafe_allow_html=True,
    )

    st.markdown("---")

    # Curl Snippets
    st.subheader("Interactive CLI & cURL Integration Snippets")

    t_text, t_file, t_cmp, t_chain, t_ev = st.tabs([
        "Text Hashing",
        "Streaming File Hash",
        "File Comparison",
        "Verify Chain",
        "Generate Evidence",
    ])

    with t_text:
        st.caption("POST /api/v1/hash/text")
        st.code(
            """curl -X POST "http://localhost:8000/api/v1/hash/text" \\
  -H "Content-Type: application/json" \\
  -d '{
    "text": "Cyber forensic baseline string",
    "algorithms": ["sha256", "sha512", "md5"]
  }'""",
            language="bash",
        )

    with t_file:
        st.caption("POST /api/v1/hash/file")
        st.code(
            """curl -X POST "http://localhost:8000/api/v1/hash/file" \\
  -F "file=@/path/to/suspect_file.bin" \\
  -F "chunk_size=1048576" """,
            language="bash",
        )

    with t_cmp:
        st.caption("POST /api/v1/compare/files")
        st.code(
            """curl -X POST "http://localhost:8000/api/v1/compare/files" \\
  -F "file_a=@baseline_doc.pdf" \\
  -F "file_b=@modified_doc.pdf" \\
  -F "chunk_size=524288" """,
            language="bash",
        )

    with t_chain:
        st.caption("POST /api/v1/chain/verify")
        st.code(
            """curl -X POST "http://localhost:8000/api/v1/chain/verify" \\
  -H "Accept: application/json" """,
            language="bash",
        )

    with t_ev:
        st.caption("POST /api/v1/evidence/generate")
        st.code(
            """# 1. First obtain fingerprint via /hash/file, then submit:
curl -X POST "http://localhost:8000/api/v1/evidence/generate" \\
  -H "Content-Type: application/json" \\
  -d '{
    "fingerprint": { ... },
    "analyst_notes": "Incident Case IR-2026-0919"
  }'""",
            language="bash",
        )

    st.markdown("---")

    # Security Testing Section (Burp / ZAP)
    st.subheader("Security Testing Compatibility (OWASP ZAP / Burp Suite)")
    st.markdown(
        """
        The HashLens API is engineered for automated DAST security scanning and penetration testing:
        
        * **Configured for Local Interception:** Route requests through `http://127.0.0.1:8080` (Burp/ZAP default proxy).
        * **Input Sanitization:** Evaluated against OWASP Top 10 A03 (Injection) and A01 (Broken Access Control).
        * **Defensive Headers:** Automatically injects strict CSP, `X-Content-Type-Options: nosniff`, and `X-Frame-Options: DENY`.
        * **Path Traversal Shield:** Upload handlers neutralize directory traversal sequences (`../../`, `..\\`, null bytes).
        * **Resource Bounds:** Upload ceiling capped at 100 MB with chunk-level streaming to mitigate DoS / zip-bomb storage exhaustion.
        """
    )
