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
5. **Legacy Data Behavior:**
   * Legacy or unowned records created prior to authentication feature `user_id = NULL` and remain isolated from newly registered user accounts to prevent accidental cross-tenant data exposure.

