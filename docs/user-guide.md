# HASHLENS User Guide & Operator Handbook

Welcome to **HASHLENS**, a local-first file integrity monitoring and cryptographic hash-forensics platform. This handbook provides complete operational guidance for security engineers, incident responders, and forensic analysts using HASHLENS.

---

## Table of Contents

1. [Platform Overview & Positioning](#1-platform-overview--positioning)
2. [Getting Started & Account Creation](#2-getting-started--account-creation)
3. [Multi-Algorithm Cryptographic Hashing](#3-multi-algorithm-cryptographic-hashing)
4. [Streaming File Fingerprinting](#4-streaming-file-fingerprinting)
5. [File Integrity Tracking & Version Baselines](#5-file-integrity-tracking--version-baselines)
6. [Forensic Version Comparison & Diagnostics](#6-forensic-version-comparison--diagnostics)
7. [Understanding "Why Did My Hash Change?"](#7-understanding-why-did-my-hash-change)
8. [Tamper-Evident Hash Chain Ledger](#8-tamper-evident-hash-chain-ledger)
9. [Forensic Evidence Reports & Digest Verification](#9-forensic-evidence-reports--digest-verification)
10. [REST API Integration](#10-rest-api-integration)
11. [Privacy, Data Storage & Security Model](#11-privacy-data-storage--security-model)
12. [Technical Limitations](#12-technical-limitations)

---

## 1. Platform Overview & Positioning

HASHLENS is designed to solve a core cybersecurity challenge during incident response and system auditing: **"Why did my file's hash change?"**

### Core Capabilities
- **Multi-Algorithm Hashing:** Concurrent computation of MD5, SHA-1, SHA-256, and SHA-512.
- **Chunk Forensics:** Streaming chunk-level block maps (4 KB to 16 MB) to pinpoint localized edits without loading entire files into memory.
- **Differential Classification:** Automated 7-tier diagnostic classification (`NO_CHANGE`, `CONTENT_MODIFICATION`, `SIZE_CHANGE`, `STRUCTURAL_CHANGE`, `METADATA_CHANGE`, `FILE_TYPE_CHANGE`, `MAJOR_REPLACEMENT`, `INCONCLUSIVE`).
- **Tamper-Evident Ledger:** Cryptographic linked-list audit logging ($H_n = \text{SHA256}(\text{Record}_n + H_{n-1})$) per user.
- **Self-Verifying Evidence Reports:** Deterministic canonical JSON SHA-256 digest computation (`Evidence Report Hash`) and standalone HTML rendering.

> [!NOTE]
> **Product Scope:** HASHLENS provides diagnostic integrity analysis and tamper-evident audit logging. It is **not** a malware sandbox, blockchain, or legal non-repudiation system.

---

## 2. Getting Started & Account Creation

### Accessing the Platform
- **Streamlit SOC Dashboard:** Access via your web browser at `http://localhost:8501` (or your deployed public production URL).
- **FastAPI REST API / Swagger UI:** Access API documentation at `http://localhost:8000/docs`.

### Account Registration & Login
1. On the landing page, select **Create Account**.
2. Enter your **Email**, **Username**, and a strong **Password** (minimum 8 characters). Passwords are hashed using **Argon2id** (memory-hard KDF).
3. Click **Create Account** to automatically register and log in.
4. For returning users, select **Login** and enter your credentials. An encrypted JWT access token (HS256) will be issued and stored securely in session memory.
5. Your authenticated username and email are displayed in the sidebar card. Click **Logout** at any time to invalidate session tokens.

---

## 3. Multi-Algorithm Cryptographic Hashing

HASHLENS supports four standard cryptographic hash algorithms:

| Algorithm | Status / Usage | Description |
| :--- | :--- | :--- |
| **SHA-256** | **Recommended** | Primary 256-bit workhorse digest for integrity baselines and hash chaining. |
| **SHA-512** | **High Security** | 512-bit digest offering maximum collision resistance margin. |
| **SHA-1** | **Legacy / Advisory** | 160-bit digest retained for historical comparison (Google SHAttered collision compromised). |
| **MD5** | **Legacy / Checksum** | 128-bit digest retained for historical comparison (Wang 2004 collision compromised). |

> [!WARNING]
> **Legacy Advisory:** MD5 and SHA-1 are provided strictly for historical forensic verification and backward compatibility with legacy checksum lists. They should **never** be used for primary security decisions or password hashing.

### Text Hashing
1. Navigate to **2. Hash Generator** $\rightarrow$ **Text Hashing**.
2. Enter your text payload.
3. View real-time digests calculated across all selected algorithms, byte size, and character metrics.

### File Hashing
1. Navigate to **2. Hash Generator** $\rightarrow$ **File Hashing**.
2. Upload any file (up to 100 MB).
3. The file is streamed in memory-efficient chunks; raw file data is processed inertly and cleaned immediately after hashing.

---

## 4. Streaming File Fingerprinting

Fingerprinting breaks a file down into fixed-size chunk digests (default: 64 KB).

1. Select a custom chunk size (4 KB, 16 KB, 64 KB, 256 KB, 1 MB).
2. The platform computes SHA-256 digests for each sequential chunk.
3. The resulting chunk map forms a **Fingerprint Object**, enabling localized diff analysis between file versions.

---

## 5. File Integrity Tracking & Version Baselines

To monitor asset evolution:

1. Navigate to **3. File Integrity**.
2. Upload a file or submit a fingerprint payload to establish a **Baseline Asset (Version 1)**.
3. The asset is registered in your private account repository with a unique `file_id`.
4. Uploading an updated version of an existing asset automatically registers **Version 2, Version 3, ...**, preserving full version progression.
5. View tracked assets under **5. Version Timeline** to inspect version history and timestamp logs.

---

## 6. Forensic Version Comparison & Diagnostics

1. Navigate to **4. Compare Files**.
2. Provide two file fingerprints (Version A and Version B) or select tracked asset versions from your account history.
3. The comparison engine analyzes chunk maps and reports:
   - Overall status (`NO_CHANGE` vs `MODIFIED` vs `REPLACED`)
   - Exact count of matching, modified, added, and deleted chunks
   - Byte-level size delta and percentage shift

---

## 7. Understanding "Why Did My Hash Change?"

HASHLENS automatically translates raw chunk diffs into clear diagnostic assessments:

| Diagnostic Classification | Condition & Interpretation |
| :--- | :--- |
| `NO_CHANGE` | File contents and cryptographic digests are 100% identical. |
| `CONTENT_MODIFICATION` | File size is identical, but localized chunks were modified (e.g. byte edit or config change). |
| `SIZE_CHANGE` | File size expanded or truncated while preserving existing prefix/suffix chunk matches. |
| `STRUCTURAL_CHANGE` | Internal chunk sequencing or structure shifted. |
| `METADATA_CHANGE` | Binary content matches, but header/metadata timestamps or attributes shifted. |
| `FILE_TYPE_CHANGE` | Advisory magic bytes indicate file category changed (e.g., text to executable). |
| `MAJOR_REPLACEMENT` | Majority of chunks (>75%) differ; file was completely overwritten or swapped. |
| `INCONCLUSIVE` | Available chunk map data insufficient for definitive breakdown. |

---

## 8. Tamper-Evident Hash Chain Ledger

Every file tracking event, version progression, and evidence report generation appends a record to your private **Tamper-Evident Hash Chain**.

### Cryptographic Linking
Each ledger block calculates a SHA-256 current record hash:
\[
H_n = \text{SHA-256}(\text{Record}_n \,||\, H_{n-1})
\]
where $H_0 = \text{"0"}^{64}$ (genesis block).

### Auditing Chain Integrity
1. Navigate to **6. Integrity Chain**.
2. View ledger records ($H_1, H_2, \dots, H_n$).
3. Click **Verify Chain Integrity** to perform an automated cryptographic audit across all sequence blocks.
4. If any historical record hash or previous link is altered, the audit instantly reports `CHAIN_BROKEN` and flags the corrupted sequence index.

---

## 9. Forensic Evidence Reports & Digest Verification

1. Navigate to **7. Evidence Reports**.
2. Select a tracked asset version and click **Generate Evidence Report**.
3. HASHLENS builds a canonical JSON structure containing file metadata, cryptographic digests, chain audit status, and analyst notes.
4. It signs the envelope with a canonical **Evidence Report Hash** (SHA-256 digest of the sorted JSON payload).
5. Click **Render Printable HTML Report** to view or export a clean, printable forensic document.

---

## 10. REST API Integration

All platform capabilities are exposed via REST API.

### Authentication
Authenticate to receive a JWT access token:
```bash
curl -X POST \
  "<HASHLENS_API>/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"login":"user@example.com","password":"YOUR_PASSWORD"}'
```

Response:
```json
{
  "access_token": "YOUR_JWT_ACCESS_TOKEN",
  "token_type": "bearer",
  "user": {"id": "usr_123", "username": "analyst"}
}
```

### Text Hashing Endpoint
```bash
curl -X POST \
  "<HASHLENS_API>/api/v1/hash/text" \
  -H "Content-Type: application/json" \
  -d '{"text":"Sample incident response artifact text"}'
```

### Track Asset Version
```bash
curl -X POST \
  "<HASHLENS_API>/api/v1/files/track" \
  -H "Authorization: Bearer YOUR_JWT_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"filename":"system.log","hashes":{"sha256":"82e631289..."},"size_bytes":1024,"chunk_count":1}'
```

---

## 11. Privacy, Data Storage & Security Model

### Data Storage Behavior
- **File Contents:** HASHLENS operates on streaming file uploads. Binary file contents are **not** permanently retained on disk. Once digests and chunk maps are computed, raw file streams are closed and discarded.
- **Stored Metadata:** Database tables store user accounts (email, username, Argon2id hash), file metadata (filename, size, MIME, category), chunk digests, version numbers, audit chain records, and evidence report JSON envelopes.
- **Per-User Data Isolation:** Every resource (`TrackedFile`, `FileVersion`, `ChainRecord`, `EvidenceReport`) is tied to `user_id`. Queries strictly filter by authenticated `user_id`. Unauthorized cross-user requests return `HTTP 404 Not Found` (existence masking).

---

## 12. Technical Limitations

1. **Process-Local Rate Limiting:** Rate limiting uses a sliding-window in memory. Multi-worker load-balanced clusters require a central Redis store.
2. **Advisory Magic-Byte Classification:** Header inspection provides advisory file category detection; it is not a sandbox detonation engine.
3. **Local Ledger Scope:** The Tamper-Evident Hash Chain provides local audit logging; it is not a distributed Byzantine fault-tolerant network.
