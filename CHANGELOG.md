# Changelog

All notable changes to the HASHLENS platform are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-09-20 — Public Release

### Added
- **Multi-Algorithm Hashing Engine:** Streaming MD5, SHA-1, SHA-256, and SHA-512 calculation for text and multipart file uploads.
- **Chunk Forensics & Fingerprinting:** Fixed-size chunk-level block mapping (4 KB to 16 MB) and advisory magic-byte category sniffing.
- **Forensic Differential Comparison Engine:** Automated 7-tier diagnostic classification (`NO_CHANGE`, `CONTENT_MODIFICATION`, `SIZE_CHANGE`, `STRUCTURAL_CHANGE`, `METADATA_CHANGE`, `FILE_TYPE_CHANGE`, `MAJOR_REPLACEMENT`, `INCONCLUSIVE`).
- **"Why Did My Hash Change?" Engine:** Rule-driven diagnostic analysis that translates chunk diffs into plain-language forensic assessments.
- **Argon2id Authentication & User Accounts:** Secure user registration, password hashing via Argon2id KDF, and JWT access token issuance.
- **Per-User Data Isolation & BOLA/IDOR Defenses:** Scoped resource ownership (`user_id`) for files, versions, ledgers, and reports with `HTTP 404` existence masking.
- **Dual Persistence Architecture:** SQLite for local development and PostgreSQL (`psycopg3`) with connection pooling for production.
- **Tamper-Evident Hash Chain:** Per-user cryptographic linked-list ledger ($H_n = \text{SHA256}(\text{Record}_n + H_{n-1})$) with active audit verification and production tamper endpoint gating (`HTTP 403`).
- **Forensic Evidence Reports:** Self-verifying SHA-256 Evidence Report Hash signatures, canonical JSON envelopes, and standalone printable HTML certificates.
- **Security Engineering & Hardening:** Defensive headers (`nosniff`, `DENY`, `CSP`), sliding-window rate limiting (120 req/min), path traversal/null-byte stripping, and controlled error masking.
- **Public Operator Documentation:** Public User Guide (`docs/user-guide.md`), API specification (`docs/api.md`), Security Guide (`docs/security.md`), Architecture Guide (`docs/architecture.md`), and Deployment Guide (`docs/deployment.md`).
- **Docker Compose Containerization:** Multi-container orchestration with unprivileged non-root execution (`hashlens` UID 10001).
- **Automated Validation Suite:** 70 Pytest unit/integration tests, 25 live production verification checks, 15 security fuzzing tests, 7 forensic classification scenarios, 13-step acceptance demo workflow, 0 Bandit HIGH/HIGH issues, and 0 `pip-audit` CVEs.
