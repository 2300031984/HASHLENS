# HashLens REST API Specification

The HashLens REST API enables automated integration with SIEM platforms, SOAR playbooks, CI/CD code verification pipelines, and forensic investigative tools.

* **Base URL:** `http://localhost:8000/api/v1`
* **Interactive Swagger UI:** `http://localhost:8000/docs`
* **ReDoc Documentation:** `http://localhost:8000/redoc`
* **OpenAPI Specification JSON:** `http://localhost:8000/api/v1/openapi.json`

---

## 1. Global Security Headers & Rate Limiting

All responses include defensive security headers:
```http
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Content-Security-Policy: default-src 'self' ...
X-Request-ID: <32-char-uuid>
X-RateLimit-Limit: 120
X-RateLimit-Remaining: 119
```

### Rate Limiting Policy
* Maximum **120 requests per minute** per client IP.
* Exceeding the rate limit returns `429 Too Many Requests` with a `Retry-After: 60` header.

---

## 2. API Endpoints Catalog

### 2.1 Platform & Health

#### `GET /api/v1/health`
Returns system status, platform version, database connectivity, and tamper-evident chain audit state.

**Response:**
```json
{
  "status": "online",
  "app": "HashLens",
  "version": "1.0.0",
  "environment": "development",
  "uptime_seconds": 341.2,
  "database": "healthy",
  "chain_health": "CHAIN_VALID"
}
```

#### `GET /api/v1/algorithms`
Returns supported cryptographic hash functions and comprehensive collision & security metadata.

---

### 2.2 Cryptographic Hashing

#### `POST /api/v1/hash/text`
Computes cryptographic digests for text strings.

**Request Body:**
```json
{
  "text": "Cybersecurity forensic string",
  "algorithms": ["sha256", "sha512", "md5"]
}
```

**Response (200 OK):**
```json
{
  "input_length_chars": 29,
  "input_length_bytes": 29,
  "hashes": {
    "sha256": "81f18ba...",
    "sha512": "b6a127...",
    "md5": "a4d32f..."
  },
  "algorithms_used": ["sha256", "sha512", "md5"]
}
```

#### `POST /api/v1/hash/file`
Processes an uploaded file via streaming chunked I/O, generating whole-file digests and chunk fingerprints.

**Form Data:**
* `file`: Binary file upload
* `chunk_size`: Optional integer (4,096 to 16,777,216 bytes; default: 1,048,576)

**Response (200 OK):**
```json
{
  "filename": "evidence.bin",
  "original_filename": "evidence.bin",
  "size_bytes": 2048576,
  "size_human": "2.0 MiB",
  "extension": ".bin",
  "mime_type": "application/octet-stream",
  "file_category": "Binary / Unknown",
  "is_type_advisory": true,
  "hashes": {
    "md5": "...",
    "sha1": "...",
    "sha256": "...",
    "sha512": "..."
  },
  "chunk_size": 1048576,
  "chunk_count": 2,
  "chunk_fingerprints": [
    {"index": 0, "offset": 0, "length": 1048576, "sha256": "..."},
    {"index": 1, "offset": 1048576, "length": 1000000, "sha256": "..."}
  ],
  "timestamp": "2026-09-19T18:30:00.000000+00:00",
  "metadata_fingerprint": "..."
}
```

#### `POST /api/v1/avalanche`
Calculates bit-flip avalanche metrics between two text inputs.

---

### 2.3 Forensic Comparison & Diagnostics

#### `POST /api/v1/compare/files`
Accepts two multipart files (`file_a` and `file_b`), computes fingerprints, and delivers chunk diffs and diagnostic assessment.

**Response (200 OK):**
```json
{
  "overall_status": "modified",
  "sha256_changed": true,
  "size_changed": false,
  "size_delta_bytes": 0,
  "size_delta_human": "0 B",
  "chunks_matching": 15,
  "chunks_changed": 1,
  "chunks_added": 0,
  "chunks_removed": 0,
  "change_percentage": 6.25,
  "assessment": {
    "classification": "CONTENT_MODIFICATION",
    "summary": "Targeted content modification: 1 chunk(s) modified while 15 chunk(s) remained intact.",
    "evidence_points": [
      "Cryptographic SHA-256 digest changed.",
      "File size remained exactly unchanged.",
      "Chunk comparison: 15 unchanged, 1 modified, 0 added, 0 removed."
    ]
  }
}
```

---

### 2.4 Tamper-Evident Hash Chain

#### `GET /api/v1/chain/status` & `POST /api/v1/chain/verify`
Performs an active cryptographic audit across all ledger records.

**Response (200 OK - Valid):**
```json
{
  "status": "CHAIN_VALID",
  "valid": true,
  "total_records": 12,
  "verified_records": 12,
  "head_hash": "ec145fe29ea...",
  "message": "Tamper-Evident Hash Chain verified intact across all 12 audit records."
}
```

**Response (200 OK - Tampered):**
```json
{
  "status": "CHAIN_BROKEN",
  "valid": false,
  "failure_type": "PAYLOAD_TAMPERED",
  "broken_record_id": "37df517...",
  "sequence_num": 3,
  "reason": "Content tampering detected in record 37df517... Stored digest differs from recalculated canonical hash.",
  "total_records": 12,
  "verified_records": 2
}
```

---

### 2.5 Evidence Reports

#### `POST /api/v1/evidence/generate`
Generates a certified Evidence Report, appends the event to the audit chain, and calculates the **Evidence Report Hash**.

#### `GET /api/v1/evidence/{report_id}`
Returns report JSON.

#### `GET /api/v1/evidence/{report_id}/html`
Returns a standalone, printable HTML forensic evidence certificate.
