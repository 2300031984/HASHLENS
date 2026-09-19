# HashLens Threat Model & Risk Assessment

This threat model follows the **STRIDE** methodology (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) to analyze the attack surface of the HashLens platform.

---

## 1. System Assets & Sensitivity

| Asset | Sensitivity | Description |
| :--- | :--- | :--- |
| **Integrity Audit Chain** | Critical | Sequentially linked records of all file registrations and version transitions. |
| **Evidence Reports** | High | Forensic certificates containing digests and hashes used for compliance and legal proof. |
| **Stored Hashes & Fingerprints** | Medium | Multi-algorithm digests and chunk maps stored in the database. |
| **Uploaded Files (In Transit)** | High | Untrusted binary payloads uploaded by users for integrity evaluation. |
| **API Availability** | High | Operational readiness of REST verification endpoints for SIEM/SOAR pipelines. |

---

## 2. Threat Actors & Capabilities

1. **Malicious External Attacker:** Attempts to exhaust storage via oversized multipart payloads, execute remote code via uploaded scripts, or induce path traversals.
2. **Insiders with Direct Database Access:** Attempts to covertly alter historical audit logs to conceal evidence tampering or unauthorized file modifications.
3. **Automated Bots & Scraping Scanners:** Attempts high-frequency API abuse, credential brute-forcing, or denial of service.

---

## 3. STRIDE Threat Analysis & Defensive Mitigations

### 3.1 Spoofing (Identity & Authenticity)
* **Threat:** An adversary crafts a forged Evidence Report claiming a tampered file passed integrity checks.
* **Impact:** False sense of security; loss of evidentiary credibility in incident investigations.
* **Mitigation:** HashLens generates a canonical **Evidence Report Hash** (SHA-256 of strictly ordered canonical report JSON). Any modification to report fields invalidates the verification digest.

### 3.2 Tampering (Integrity of Data)
* **Threat:** A database administrator or compromised service modifies an existing audit record to hide a detected integrity failure.
* **Impact:** Corrupted forensic chain of custody.
* **Mitigation:** **Tamper-Evident Hash Chain**. Every event hash incorporates the cryptographic hash of the preceding block: $H_n = \text{SHA256}(\text{Record}_n + H_{n-1})$. The automated audit engine detects payload alterations, sequence gaps, or link breaks in $O(N)$ time and pinpoints the exact compromised record.
* **Threat:** Malicious file disguised as a text file contains embedded executable binary code.
* **Impact:** Inadvertent execution or misclassification.
* **Mitigation:** Files are never executed under any circumstances. Advisory magic-byte sniffing inspects binary headers rather than trusting client-supplied MIME headers or file extensions.

### 3.3 Repudiation (Non-Repudiation of Events)
* **Threat:** An analyst or system denies having registered or certified a specific version of a binary.
* **Impact:** Lack of accountability in security incident retrospectives.
* **Mitigation:** Immutable timestamped audit entries linked into the hash chain with correlation request IDs recorded in structured security logs.

### 3.4 Information Disclosure (Confidentiality)
* **Threat:** Server error returns unhandled Python tracebacks, revealing internal filesystem paths, configuration values, or database connection strings.
* **Impact:** Attackers gain architectural reconnaissance for targeted exploits.
* **Mitigation:** Global exception handlers mask internal details with generic structured error objects containing correlation IDs (`X-Request-ID`), while logging detailed errors strictly to server-side streams.
* **Threat:** Sensitive file contents leak into server log files.
* **Mitigation:** The structured logging pipeline (`SafeStructuredFormatter`) explicitly excludes file contents, raw multipart streams, or credentials from log records.

### 3.5 Denial of Service (Availability & Resource Exhaustion)
* **Threat:** Attacker uploads a 50 GB zip bomb or multi-gigabyte stream to exhaust server RAM.
* **Impact:** Out-Of-Memory (OOM) killer terminates the FastAPI application.
* **Mitigation:** 
  1. Strict upload ceiling (`MAX_UPLOAD_SIZE = 100 MB`) checked during streaming.
  2. Streaming chunked I/O (`chunk_size = 1 MB` default): files are read in sequential byte slices rather than loaded into memory.
  3. Ephemeral spooling with immediate file descriptor closure and cleanup in `finally` blocks.
* **Threat:** API endpoint flooding with thousands of concurrent hash calculations.
* **Mitigation:** Sliding-window rate limiter (`InMemoryRateLimiter`) limits client IPs to 120 requests per minute with HTTP 429 Retry-After enforcement.

### 3.6 Elevation of Privilege (Access Control & Code Execution)
* **Threat:** Attacker uses directory traversal filenames (`../../../../etc/shadow` or `..\..\cmd.exe`) in multipart upload headers to overwrite critical operating system files.
* **Impact:** Arbitrary file overwrite or execution.
* **Mitigation:** `SafeFileService.sanitize_filename` strips directory traversal markers (`/`, `\`, `..`), null bytes (`\x00`), and illegal characters, forcing files to resolve strictly within designated sandboxes.
* **Threat:** Container escape if backend process is compromised.
* **Mitigation:** Docker containers run under a dedicated, unprivileged non-root user (`hashlens`, UID 10001) with minimal base image and no sudo privileges.

---

## 4. Threat Model Summary Matrix

| Threat ID | STRIDE Category | Vector | Risk Level | Status | Enforced Mitigation |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **TM-01** | Tampering | Audit Record Mutation | High | Mitigated | Tamper-Evident Hash Chain ($H_n = \text{SHA256}(R_n + H_{n-1})$) |
| **TM-02** | Tampering | Malicious Filename Traversal | Critical | Mitigated | `SafeFileService.sanitize_filename` directory stripping |
| **TM-03** | Denial of Service | RAM Exhaustion via Large Files | High | Mitigated | Streaming chunk processing + 100 MB max size limit |
| **TM-04** | Denial of Service | High-Frequency Flooding | Medium | Mitigated | Sliding-window IP rate limiting (120 req/min) |
| **TM-05** | Info Disclosure | Stack Trace & Path Disclosures | Medium | Mitigated | Global controlled exception handlers + masked errors |
| **TM-06** | Elevation | Container Privilege Escalation | High | Mitigated | Non-root container execution (UID 10001) |
| **TM-07** | Spoofing | Forged Evidence Report | High | Mitigated | Canonical JSON Evidence Report Hash (SHA-256 seal) |
