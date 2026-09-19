# Changelog

All notable changes to the HASHLENS platform are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-09-20

### Added
- **Cryptographic Hashing Engine:** Support for streaming multi-algorithm hashing (MD5, SHA-1, SHA-256, SHA-512) for text strings and files.
- **Chunk-Based Fingerprinting:** Rolling window chunk hashing and file boundary breakdown for localized diff analysis.
- **Forensic File Comparison:** Automated 7-tier classification differential engine (`NO_CHANGE`, `CONTENT_MODIFICATION`, `SIZE_CHANGE`, `MAJOR_REPLACEMENT`, `INCONCLUSIVE`, `METADATA_CHANGE`).
- **"Why Did My Hash Change?" Engine:** Plain-language diagnostic analysis explaining hash discrepancies, chunk shifts, and bit modifications.
- **Version History Tracking:** Historical file fingerprint baseline tracking and version progression repository.
- **Tamper-Evident Hash Chain:** Cryptographic linked-list ledger tracking version modifications with active integrity auditing and tamper simulation (`/api/v1/tamper/simulate`).
- **Certified Evidence Reports:** Canonical JSON SHA-256 evidence digest generation and verification (`EvidenceService.compute_report_hash()` & `verify_report_integrity()`).
- **REST API:** FastAPI backend with OpenAPI / Swagger documentation (`/docs`) and automated Pydantic validation.
- **Forensic Dashboard:** Interactive Streamlit dashboard for visual file hashing, forensic comparison, hash chain ledger auditing, and evidence report export.
- **Python CLI:** Command-line tool supporting hash calculation, file diffing, chain audit, and report generation (`python -m backend.app.cli`).
- **Security Controls:** HTTP Security Headers middleware, in-memory rate limiting with stale IP cleanup, path traversal prevention, upload file size limits, and configurable HSTS.
- **Docker Containerization:** Multi-stage non-root Docker builds for FastAPI backend and Streamlit dashboard orchestrated via Docker Compose.
- **Automated Test Suite:** 38 automated unit, API, integration, and security tests.
