# HASHLENS — Portfolio Screenshots & Assets Guide

This directory contains visual documentation and screenshot checklists for showcasing HASHLENS in portfolios, demonstrations, and technical presentations.

## Recommended Portfolio Screenshots

| # | Screenshot Name | Target URL / Command | Purpose / Focus |
|---|---|---|---|
| 1 | `01_dashboard_overview.png` | `http://127.0.0.1:8501` | Main Streamlit interface with sidebar navigation and platform summary. |
| 2 | `02_hash_generator.png` | `http://127.0.0.1:8501` (Text/File Hashing tab) | Multi-algorithm (MD5, SHA-1, SHA-256, SHA-512) calculations and security metadata warnings. |
| 3 | `03_file_fingerprint.png` | `http://127.0.0.1:8501` (Fingerprint tab) | Chunk-level SHA-256 block breakdowns and file category advisory. |
| 4 | `04_file_comparison.png` | `http://127.0.0.1:8501` (Diff tab) | Side-by-side differential chunk comparison and change percentage metrics. |
| 5 | `05_why_hash_changed.png` | `http://127.0.0.1:8501` ("Why Changed?" tab) | Plain-language diagnostic analysis isolating targeted byte modifications vs file rewrites. |
| 6 | `06_version_timeline.png` | `http://127.0.0.1:8501` (Version History tab) | Sequential file version progression and baseline hash evolution. |
| 7 | `07_integrity_chain.png` | `http://127.0.0.1:8501` (Tamper Chain tab) | Cryptographic ledger audit showing active `CHAIN_VALID` / `CHAIN_BROKEN` detection. |
| 8 | `08_evidence_report.png` | `http://127.0.0.1:8501` (Evidence tab) | Exported JSON/HTML Forensic Evidence Report with canonical SHA-256 digest. |
| 9 | `09_fastapi_swagger.png` | `http://127.0.0.1:8000/docs` | Interactive OpenAPI Swagger specification demonstrating REST API design. |
| 10 | `10_docker_container.png` | Terminal: `docker compose ps` | Multi-container Docker Compose deployment status and health checks. |

## Screen Recording Walkthrough Checklist

For video walkthroughs or GIF assets:
1. Start Streamlit dashboard and perform text hashing across all 4 algorithms.
2. Upload a sample report file to generate a baseline version entry.
3. Edit 1 byte of the sample file and upload to run the "Why Did My Hash Change?" diagnostic.
4. Open the Tamper-Evident Hash Chain ledger view and run active integrity verification.
5. Simulate block tampering to demonstrate real-time `CHAIN_BROKEN` detection.
6. Export the Certified Evidence Report and demonstrate canonical SHA-256 digest verification.
