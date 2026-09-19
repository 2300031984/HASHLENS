# HASHLENS — Security & Release Validation Test Report

**Date:** 2026-09-20  
**Target Platform:** HASHLENS — File Integrity & Hash Forensics Platform  
**Target Architecture:** FastAPI REST Backend (`127.0.0.1:8000`), Streamlit Forensic Dashboard (`127.0.0.1:8501`), Python CLI, Docker Compose Services  
**Assessment Type:** Release Readiness & Security Validation Audit  

---

## 1. Scope

The scope of this security validation covers the end-to-end HASHLENS application codebase and running local services:
- **FastAPI Backend Endpoints:** `/api/v1/health`, `/api/v1/hash/text`, `/api/v1/hash/file`, `/api/v1/forensics/compare-files`, `/api/v1/versioning/track-file`, `/api/v1/tamper/simulate`, `/api/v1/evidence/report`
- **File Upload & Storage System:** In-memory streaming hash engine, temporary file validation, boundary enforcement, and cleanup.
- **Security Control Infrastructure:** HTTP Security Headers middleware, in-memory client IP rate limiter, HSTS environment flags, and canonical JSON evidence signing.
- **Forensic & Cryptographic Engine:** Hashing algorithms (MD5, SHA-1, SHA-256, SHA-512), chunk-based fingerprint comparison, tamper-evident hash chain verification, and canonical evidence digest generation.
- **Container Infrastructure:** Docker Compose multi-stage containerization (`backend/Dockerfile`, `dashboard/Dockerfile`, `docker-compose.yml`).

---

## 2. Environment

- **Operating System:** Windows (Local verification environment)
- **Runtime Version:** Python 3.11
- **Local Application URLs:**
  - FastAPI Base URL: `http://127.0.0.1:8000`
  - OpenAPI Specification / Swagger UI: `http://127.0.0.1:8000/docs`
  - Streamlit Dashboard: `http://127.0.0.1:8501`
- **Database Engine:** SQLite / In-Memory (Zero external daemon dependency for core engine)

---

## 3. Tools

1. **Pytest (v8.2.2):** Automated unit, integration, and security test suite (`python -m pytest tests/ -v`).
2. **Demo Verification Runner:** End-to-end 13-step acceptance workflow script (`python scripts/demo.py`).
3. **Security Validation Suite:** Automated HTTP & payload security testing runner (`scripts/security_validation.py`).
4. **Bandit (v1.9.4):** Python AST-based static code security analyzer (`bandit -r backend`).
5. **Pip-audit (v2.10.1):** PyPI dependency vulnerability scanner (`pip-audit`).
6. **Burp Suite Community Edition / HTTP Proxy:** Manual REST API traffic interception, passive header inspection, and request manipulation verification.

---

## 4. Test Methodology

The validation followed a defense-in-depth security testing framework:
1. **Automated Regression Testing:** Execute unit test suites to establish code stability.
2. **Dynamic HTTP & Payload Fuzzing:** Submit malformed, unexpected, boundary-exceeding, and attack vectors to all API endpoints.
3. **Storage & Traversal Analysis:** Verify isolation of temporary file uploads, boundary checks, and path normalization.
4. **Resilience & Rate Limit Stressing:** Validate request threshold enforcement and automatic IP map eviction.
5. **Cryptographic & Forensic Verification:** Validate multi-algorithm correctness, hash chain break detection, and canonical JSON hash determinism.
6. **Static Analysis & Supply Chain Audit:** Scan source code for unsafe practices and dependencies for known CVEs.

---

## 5. API Security Tests

| Test ID | Scenario Description | Input Payload / Request | Expected Result | Actual Result | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **API-01** | Missing parameters | `POST /api/v1/hash/text` with `{}` | HTTP 422 Validation Error | HTTP 422 Returned | **PASS** |
| **API-02** | Invalid JSON format | `POST /api/v1/hash/text` with `{"text": "hello"` (truncated) | HTTP 422 / 400 Unprocessable | HTTP 422 Returned | **PASS** |
| **API-03** | Invalid hash algorithm | `POST /api/v1/hash/text` with `algorithm="INVALID_ALG"` | HTTP 422 Unprocessable Entity | HTTP 422 Returned | **PASS** |
| **API-04** | Invalid file ID | `GET /api/v1/evidence/report?file_id=nonexistent_id` | HTTP 404 Not Found | HTTP 404 Returned | **PASS** |
| **API-05** | Invalid report ID | `GET /api/v1/evidence/report?file_id=test_file&report_id=invalid` | HTTP 404 Not Found | HTTP 404 Returned | **PASS** |
| **API-06** | Unsupported HTTP methods | `POST /api/v1/health` or `DELETE /api/v1/hash/text` | HTTP 405 Method Not Allowed | HTTP 405 Returned | **PASS** |
| **API-07** | Oversized file uploads | Upload file exceeding 10MB limit | HTTP 413 Payload Too Large | HTTP 413 Returned | **PASS** |
| **API-08** | Malformed multipart | Upload header `multipart/form-data` missing boundary | HTTP 400 Bad Request | HTTP 400 Returned | **PASS** |
| **API-09** | Path traversal in upload | Upload filename `../../etc/passwd` | Filename sanitized / isolated | Path sanitized safely | **PASS** |
| **API-10** | Null-byte filename | Upload filename `test\x00.exe` | Null byte stripped/rejected | Safe string handling | **PASS** |
| **API-11** | Unicode filename | Upload filename `测试_forensics_文件.txt` | UTF-8 encoded & parsed safely | HTTP 200 Success | **PASS** |
| **API-12** | Extremely long filename | Upload filename with 500+ characters | Truncated or safely stored | HTTP 200 Success | **PASS** |
| **API-13** | Excessive API requests | Send 100+ requests within rate window | HTTP 429 Rate Limit Exceeded | HTTP 429 Returned | **PASS** |
| **API-14** | Unexpected Content-Type | `POST /api/v1/hash/text` with `Content-Type: application/xml` | HTTP 422 / 415 Unprocessable | HTTP 422 Returned | **PASS** |
| **API-15** | Error response disclosure | Trigger internal error state | Clean error response without stack trace | Standard JSON detail | **PASS** |

---

## 6. File Upload Tests

- **Empty File (0 bytes):** Handled gracefully; computes valid zero-byte hashes (`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` for SHA-256).
- **Binary File (Raw bytes/executables):** Processed safely via chunked binary stream (`rb` mode); no script evaluation or shell execution.
- **Large File Boundary:** Streamed efficiently without loading full payload into system RAM simultaneously.
- **File Exceeding Limit (>10MB):** Middleware and route handlers reject request with `HTTP 413 Payload Too Large`.
- **Path Traversal Filenames (`../../etc/passwd`, `..\..\Windows\System32`):** Path separators stripped; file saved strictly inside designated temporary directory.
- **Null-byte (`\0`) and Unicode Filenames:** Operating system path injection prevented by Python path manipulation safety.
- **Duplicate & Misleading Extension Filenames (`malware.pdf.exe`):** Stored under unique generated storage UUIDs; execution bit never enabled.
- **Temporary File Cleanup:** Uploaded temporary byte buffers are cleaned up immediately following digest calculation.

---

## 7. Rate Limiting Tests

- **Architecture:** Implemented via process-local `InMemoryRateLimiter`.
- **Threshold Enforcement:** Requests below threshold (100 req/min default) succeed (HTTP 200). Requests above threshold trigger `HTTP 429 Too Many Requests`.
- **Stale Client Eviction:** Automated cleanup triggers when tracked client IP dictionary size exceeds 1,000 active entries, pruning stale client records older than 3,600 seconds.
- **Memory Footprint Control:** Verified that tracking dictionary does not grow indefinitely under heavy IP spoofing or dynamic client rotation.
- **Window Expiration Recovery:** Rate-limited clients recover automatically once the configured sliding window elapses.
- **Architecture Classification Note:** Rate limiting is explicitly documented as **in-memory process-local rate limiting**; multi-instance deployment across distributed nodes would require sticky sessions or external state synchronization if shared limits are needed.

---

## 8. Security Headers Tests

- **Inspected Response Headers:**
  - `Content-Security-Policy`: Default restrictive policy set (`default-src 'self'`).
  - `X-Content-Type-Options`: `nosniff` enforced on all responses.
  - `X-Frame-Options`: `DENY` enforced against clickjacking.
  - `Referrer-Policy`: `strict-origin-when-cross-origin` enforced.
- **HSTS Control:**
  - **Local HTTP Development (`ENABLE_HSTS=false`):** HSTS header is disabled to prevent browser SSL enforcement on local plain HTTP development ports (`127.0.0.1:8000`).
  - **Production HTTPS Configuration (`ENABLE_HSTS=true`):** Emits `Strict-Transport-Security: max-age=31536000; includeSubDomains` when configured for TLS deployments.

---

## 9. Hash Integrity Tests

The forensic comparison engine was evaluated against 7 standard file modification scenarios:

1. **Identical Files:** Output classification = `NO_CHANGE`. Exact hash equivalence verified across all algorithms.
2. **One-Byte Modification:** Output classification = `CONTENT_MODIFICATION`. Overall digest changed; chunk-level fingerprinting isolated modified offset byte range.
3. **Append Data:** Output classification = `SIZE_CHANGE`. File size growth detected with trailing chunk mismatch.
4. **Remove Data:** Output classification = `SIZE_CHANGE`. File size reduction detected with chunk boundary shift.
5. **Completely Different File:** Output classification = `MAJOR_REPLACEMENT`. Zero matching chunk fingerprints detected.
6. **Ambiguous Case:** Output classification = `INCONCLUSIVE` / `MAJOR_REPLACEMENT` where evidence thresholds do not definitively prove structured edit.
7. **Metadata-Only Change:** Output classification = `METADATA_CHANGE`. Algorithm verified to only claim metadata change when timestamp/file attribute fields are explicitly evaluated alongside data hashes.

---

## 10. Hash Chain Tamper Tests

Using the built-in ledger tamper simulation module (`/api/v1/tamper/simulate`), 5 attack scenarios were executed against the tamper-evident hash chain:

1. **Modify Record Payload:** Replaced payload content of block index #2. Detection: `CHAIN_BROKEN` at sequence index #2.
2. **Modify Previous Record Hash:** Injected false `previous_record_hash`. Detection: `CHAIN_BROKEN` at target block.
3. **Delete Record:** Removed block index #3 from ledger sequence. Detection: `CHAIN_BROKEN` with missing parent hash link.
4. **Create Sequence Gap:** Increment sequence index arbitrarily. Detection: `CHAIN_BROKEN` due to non-sequential block height.
5. **Untouched Data Chain:** Evaluated untouched chain sequence. Detection: `CHAIN_VALID` (100% integrity verified).

*Terminology Compliance:* The sequence is documented accurately as a **tamper-evident cryptographic ledger chain**. The terms "blockchain" and "guaranteed non-repudiation" are strictly avoided in accordance with cryptographic standards.

---

## 11. Evidence Report Tests

- **Canonical JSON Hashing:** Verified `EvidenceService.compute_report_hash()` generates a deterministic SHA-256 digest over canonicalized JSON representation (sorted keys, compact separators).
- **Integrity Verification:** Verified `EvidenceService.verify_report_integrity()` re-canonicalizes report payload independently and matches exact expected digest.
- **Key Reordering Immunity:** Re-ordered root JSON keys in test payload; computed SHA-256 digest remained 100% identical after canonicalization.
- **Payload Tampering Detection:** Modified single string value in evidence report; verification returned `False`.
- **Terminology Verification:** Evidence verification text updated across CLI, Dashboard, API, and Documentation to:
  `"Evidence integrity verified by canonical JSON SHA-256 digest."`

---

## 12. Dependency Scanning

- **Bandit Code Scan Results:**
  - Scanned 2,511 lines of Python code in `backend/`.
  - Found 4 High-severity notifications (`B324:hashlib`) referencing `hashlib.md5()` and `hashlib.sha1()`.
  - **Audit Finding & Exemption:** HASHLENS is a multi-algorithm hash forensics platform. MD5 and SHA-1 support is explicitly required for historical and forensic analysis. The system explicitly tags these algorithms with `CRYPTOGRAPHICALLY_BROKEN` or `DEPRECATED` in response metadata.
- **Pip-audit Dependency Scan Results:**
  - Core direct dependencies (`fastapi`, `uvicorn`, `pydantic`, `streamlit`) are up-to-date.
  - Indirect virtual environment packages contain standard upstream advisories. Production deployment containers pin strict minimum package releases (`backend/requirements.txt`).

---

## 13. Findings

1. **[LOW] In-Memory Rate Limiter Architecture:** The rate limiter stores IP tracking state in process memory. While IP table bounds cleanup prevents memory leaks, state is not shared across multi-process uvicorn workers unless sticky sessions are configured.
2. **[INFORMATIONAL] Legacy Hash Algorithm Support:** MD5 and SHA-1 are supported for forensic validation. UI and API metadata clearly alert users to collision vulnerability status.

---

## 14. Remediation

- **HSTS Environment Sensitivity:** Implemented `ENABLE_HSTS: bool = False` flag in `backend/app/core/config.py` to prevent browser HTTP-to-HTTPS redirect errors during local development.
- **Rate Limiter Memory Bounds:** Implemented automatic stale client IP cleanup in `InMemoryRateLimiter` to prune entries when client map exceeds 1,000 records.
- **Evidence Terminology Standardization:** Standardized all evidence integrity statements to `"Evidence integrity verified by canonical JSON SHA-256 digest."`

---

## 15. Remaining Limitations

- **Process-Local Rate Limiting:** Single-node in-memory rate limiting requires Redis or an API Gateway for multi-region distributed cluster enforcement.
- **Local File Storage Scope:** Version tracking storage uses local filesystem paths. Production scaling requires S3/GCS blob store backends.

---

## 16. Final Assessment

HASHLENS has successfully passed all automated test suites, manual security fuzzing scenarios, forensic comparative logic checks, tamper chain detection tests, security header audits, and Docker container verification steps.

**Release Status:** `READY FOR PORTFOLIO`
