# HashLens Security Engineering & Hardening Guide

This document outlines the defense-in-depth principles, cryptographic decisions, secure coding practices, and deployment controls enforced across HashLens.

---

## 1. Trust Boundaries & Input Validation

1. **Untrusted Client Inputs:** Every input—whether a text string, multipart file upload, query parameter, or JSON body—is treated as hostile and untrusted.
2. **Pydantic v2 Schema Enforcement:** Strict type validation, character bounds (`max_length = 1,000,000` for text), and integer ranges (`chunk_size` constrained between 4 KB and 16 MB) reject malformed payloads before processing.
3. **No File Execution:** Uploaded assets are strictly processed as static byte streams. The platform contains zero execution invocations (`exec`, `eval`, or shell spawning) on uploaded content.

---

## 2. Secure File Handling

* **Path Traversal Elimination:** Filenames sent in HTTP headers (e.g., `Content-Disposition`) can be forged by attackers. HashLens strips path separators (`/`, `\`), relative directory components (`..`), null bytes (`\x00`), and non-printable control characters via `SafeFileService.sanitize_filename`.
* **Advisory Type Sniffing:** HashLens never relies on the client-declared `Content-Type` header or file extension to determine behavior. Magic byte header sniffing inspects the first 1 KB of raw binary data strictly to provide advisory forensic classification.
* **Ephemeral Processing:** Uploaded files are streamed directly through hashing engines and immediately closed and cleaned. The platform does not retain raw files on disk unless explicitly designated for archival.

---

## 3. Cryptographic Design Choices

### 3.1 Hash Function Suite
* **MD5 & SHA-1:** Maintained exclusively for historical forensic verification and backward compatibility. They are explicitly designated in the UI and API as cryptographically compromised due to collision attacks (Wang 2004, Google SHAttered 2017).
* **SHA-256:** The core workhorse of HashLens. Used for primary file integrity, chunk block maps, Tamper-Evident Hash Chains, and Evidence Report Hashes.
* **SHA-512:** High-security 512-bit digest offering maximum collision resistance margin and superior performance on 64-bit systems.

### 3.2 Constant-Time Comparisons
To prevent timing-attack side channels when verifying hashes or report signatures, HashLens uses Python's `hmac.compare_digest` rather than variable-time string equality operators (`==`).

---

## 4. Password Hashing Distinction (Critical Security Principle)

> [!WARNING]
> **Raw cryptographic hash functions (MD5, SHA-1, SHA-256, SHA-512) must NEVER be used for password storage.**

General cryptographic hash functions are engineered to be **fast and computationally cheap** (achieving gigabytes per second on standard hardware). Because modern GPUs can calculate billions of SHA-256 hashes per second, raw hashes provide virtually zero resistance against dictionary attacks, rainbow tables, or brute force.

Password storage requires **intentionally slow**, **adaptive**, and **memory-hard** Key Derivation Functions (KDFs):
* **Argon2id:** The modern gold standard (winner of the Password Hashing Competition), offering proven defense against GPU and ASIC attacks via memory-hard matrix filling.
* **bcrypt:** Battle-tested Blowfish-based KDF with an adjustable cost/work factor.
* **scrypt:** Memory-hard key derivation function.

HashLens includes explicit warnings in both its REST API metadata and SOC Dashboard to educate users on this fundamental distinction.

---

## 5. Network & API Defenses

1. **Security Headers Middleware:** Every HTTP response carries defensive headers:
   * `X-Content-Type-Options: nosniff` (prevents MIME type confusion attacks)
   * `X-Frame-Options: DENY` (anti-clickjacking defense)
   * `Content-Security-Policy: default-src 'self' ...` (mitigates cross-site scripting)
   * `Referrer-Policy: strict-origin-when-cross-origin`
2. **Rate Limiting:** In-memory sliding-window limiter restricts abuse to 120 requests per minute per IP, responding with `429 Too Many Requests` and standard `Retry-After` headers.
3. **Structured Logging Without Leakage:** Server logs record correlation request IDs, execution durations, and status codes, but strictly omit raw file contents, secrets, or unhandled tracebacks.

---

## 6. Authentication, Per-User Data Isolation & IDOR / BOLA Defenses

1. **Authentication Architecture:**
   * **Password Hashing:** Passwords are hashed exclusively using **Argon2id** (`argon2-cffi`). Raw cryptographic hashes (MD5, SHA-1, SHA-256) are never used for password security.
   * **JWT Access Tokens:** Issued upon login with short lifespan (default 60 minutes) containing minimal required claims (`sub`, `iat`, `exp`). Secret keys are enforced via `Settings` validation in production.
2. **Application-Level Per-User Resource Isolation:**
   * Every user-owned persistent resource (`TrackedFile`, `FileVersion`, `ChainRecord`, `EvidenceReport`) is tied to an authoritative `user_id` foreign key referencing `users.id`.
   * Listing endpoints (`/files`, `/chain/records`, `/evidence`) automatically scope results using `WHERE user_id = current_user.id`.
3. **Insecure Direct Object Reference (IDOR / BOLA) Defenses:**
   * Every single-resource query (`/files/{file_id}/timeline`, `/evidence/{report_id}`) verifies that `resource.user_id == current_user.id`.
   * Unauthorized cross-user requests return a consistent `404 Not Found` response to prevent leaking resource existence or metadata to unauthorized callers.
4. **Per-User Tamper-Evident Hash Chain Isolation:**
   * Hash chain linking ($H_n = \text{SHA256}(\text{Record}_n + H_{n-1})$), sequencing, and audit verification (`/chain/verify`) run independently per `user_id`.
7. **Production Database Security & Transaction Safety:**
   * **SQL Injection Prevention:** All database operations utilize SQLAlchemy ORM parameterized statements. Raw SQL string concatenation is strictly prohibited.
   * **Connection Pool Hardening:** PostgreSQL connection pools employ pre-ping verification (`pool_pre_ping=True`) to validate connection health and prevent stale socket drops.
   * **Health Check Diagnostics Error Masking:** The `/api/v1/health` endpoint returns a generic `"unhealthy"` status on database connectivity failures, strictly masking raw SQL error messages, database credentials, or internal connection strings.
   * **Safe Migration Management:** Alembic versioned migrations run non-destructive, explicit schema updates, eliminating blind `DROP TABLE` commands or accidental data destruction in production.

---

## 8. OWASP API Security Assessment & Verification Matrix

| Security Area | Tested | Result | Defense Mechanism |
| :--- | :---: | :---: | :--- |
| **Authentication (API2)** | YES | PASS | Argon2id memory-hard password hashing + JWT HS256 signature verification |
| **JWT Claims Security** | YES | PASS | Minimal claims (`sub`, `iat`, `exp`), secret validation in production |
| **BOLA / IDOR Defense (API1)** | YES | PASS | Strict `WHERE user_id = current_user.id` + HTTP 404 existence masking |
| **Mass Assignment (API3)** | YES | PASS | Pydantic schema filtering; client payloads cannot assign `user_id` or `is_active` |
| **Resource Limits (API4)** | YES | PASS | 100 MB max upload limit, 4 KB–16 MB chunk bounds, input truncation |
| **Function Gating (API5)** | YES | PASS | `/chain/simulate-tamper` blocked in production (`APP_ENV=production` $\rightarrow$ 403) |
| **Path Traversal / Null Byte** | YES | PASS | `SafeFileService.sanitize_filename` strips slashes, `..`, and `\x00` |
| **SQL Injection Defense** | YES | PASS | 100% SQLAlchemy ORM parameterized queries |
| **Rate Limiting** | YES | PASS | 120 req/min sliding window per client IP with `Retry-After` header |
| **Security Headers (API8)** | YES | PASS | `X-Content-Type-Options`, `X-Frame-Options`, `CSP`, `X-Request-ID` |
| **Error Masking** | YES | PASS | Generic 500/400 error structures; stack traces and paths never leaked |
| **Hash Chain Integrity** | YES | PASS | $H_n = \text{SHA256}(\text{Record}_n + H_{n-1})$ with explicit transaction rollbacks |
| **Secrets & Container** | YES | PASS | Non-root `hashlens` user in Dockerfiles; 0 committed secrets |
| **Dependency Audit** | YES | PASS | `pip-audit` verified 0 known vulnerabilities |

### Residual Limitations
1. **Process-Local Rate Limiting**: The sliding-window rate limiter is currently process-local in memory. In multi-worker distributed clusters, a shared Redis store should be introduced in future scaling phases.
2. **Advisory Type Sniffing**: Magic-byte inspection provides advisory classification only and does not replace dedicated sandbox malware detonation engines.

---

## 9. Phase 5 Live Production Acceptance Matrix

| Verification ID | Verification Scope | Status | Details |
| :--- | :--- | :---: | :--- |
| **P5-01** | Backend & DB Health Status (`/api/v1/health`) | **PASS** | HTTP 200, DB: healthy |
| **P5-02** | Public Metadata (`/api/v1/algorithms`) | **PASS** | HTTP 200, 4 algorithms supported |
| **P5-03** | User Registration (Argon2id KDF) | **PASS** | HTTP 201 Created |
| **P5-04** | User Login & JWT Token Issuance | **PASS** | HTTP 200 Bearer Token |
| **P5-05** | Authenticated Profile (`/api/v1/auth/me`) | **PASS** | HTTP 200 Authenticated Profile |
| **P5-06** | Unauthenticated Access Rejection | **PASS** | HTTP 401 Unauthorized |
| **P5-07** | Tampered JWT Signature Rejection | **PASS** | HTTP 401 Unauthorized |
| **P5-08** | Multi-Algorithm Hashing (`/api/v1/hash/text`) | **PASS** | HTTP 200 MD5/SHA-1/256/512 |
| **P5-09** | Streaming File Fingerprinting | **PASS** | HTTP 200 Chunk Forensics |
| **P5-10** | Bit-Flip Avalanche Metric Calculation | **PASS** | HTTP 200 Avalanche Metric |
| **P5-11** | Forensic Differential Comparison | **PASS** | HTTP 200 Identical / Difference |
| **P5-12** | Baseline Asset Registration (`/files/track`) | **PASS** | HTTP 200 Baseline Created |
| **P5-13** | Version Progression & Asset Tracking | **PASS** | HTTP 200 Version Progression |
| **P5-14** | User-Scoped Tracked Asset Listing | **PASS** | HTTP 200 Scoped File List |
| **P5-15** | Asset Timeline Retrieval (`/timeline`) | **PASS** | HTTP 200 Scoped Asset Timeline |
| **P5-16** | Tamper-Evident Hash Chain Audit Status | **PASS** | HTTP 200 Valid: True |
| **P5-17** | Ledger Block Retrieval (`/chain/records`) | **PASS** | HTTP 200 Scoped Ledger |
| **P5-18** | Forensic Evidence Report Generation | **PASS** | HTTP 200 Evidence Hash Generated |
| **P5-19** | Evidence Report Fetch by ID | **PASS** | HTTP 200 Scoped Evidence Report |
| **P5-20** | Printable Evidence HTML Rendering | **PASS** | HTTP 200 HTML Document Rendered |
| **P5-21** | User B Setup (Isolation Testing) | **PASS** | HTTP 200 Isolated Credentials |
| **P5-22** | BOLA Defense: Cross-User Timeline Access | **PASS** | HTTP 404 (Existence Masked) |
| **P5-23** | BOLA Defense: Cross-User Evidence Access | **PASS** | HTTP 404 (Existence Masked) |
| **P5-24** | Production Tamper Simulation Gating | **PASS** | HTTP 403 Forbidden in Production |
| **P5-25** | Defensive Security Headers Enforcement | **PASS** | HTTP 200 CSP/nosniff/DENY |

**Final Platform Status:** `PRODUCTION VERIFIED`



