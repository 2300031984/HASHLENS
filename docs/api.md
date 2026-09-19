# HASHLENS REST API Specification

The HASHLENS REST API provides a high-performance RESTful interface for cryptographic hashing, chunk forensics, version tracking, tamper-evident ledger auditing, and evidence report generation.

* **Base URL:** `http://localhost:8000/api/v1` (or `<HASHLENS_API>/api/v1`)
* **Interactive Swagger UI:** `http://localhost:8000/docs`
* **ReDoc Documentation:** `http://localhost:8000/redoc`
* **OpenAPI Specification JSON:** `http://localhost:8000/api/v1/openapi.json`

---

## 1. Security Headers, Rate Limiting & Authentication

### Security Headers
All API responses carry defensive security headers:
```http
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Content-Security-Policy: default-src 'self' ...
X-Request-ID: <32-char-uuid>
```

### Rate Limiting Policy
* Sliding-window rate limiter: **120 requests per minute** per client IP.
* Exceeding the rate limit returns `429 Too Many Requests` with `Retry-After: 60`.

### Authentication & Authorization
Protected endpoints require a JWT bearer token in the `Authorization` header:
```http
Authorization: Bearer YOUR_JWT_ACCESS_TOKEN
```
Tokens are acquired via `POST /api/v1/auth/login` and expire after 60 minutes.

### Data Ownership & Isolation
All user-owned resources (`TrackedFile`, `FileVersion`, `ChainRecord`, `EvidenceReport`) are strictly scoped to the authenticated `user_id`. Attempting to access another user's resource returns `404 Not Found` (existence masking).

---

## 2. API Endpoints Catalog

### 2.1 Authentication & Profile

#### `POST /api/v1/auth/register`
Registers a new user account. Passwords are stored using Argon2id memory-hard KDF.

**Request Body:**
```json
{
  "email": "user@example.com",
  "username": "analyst",
  "password": "YOUR_SECURE_PASSWORD"
}
```

**Response (201 Created):**
```json
{
  "id": "usr_7a8b9c",
  "email": "user@example.com",
  "username": "analyst",
  "is_active": true,
  "created_at": "2026-09-20T03:30:00+00:00"
}
```

#### `POST /api/v1/auth/login`
Authenticates credentials and returns a JWT access token.

**Request Body:**
```json
{
  "login": "analyst",
  "password": "YOUR_SECURE_PASSWORD"
}
```

**Response (200 OK):**
```json
{
  "access_token": "YOUR_JWT_ACCESS_TOKEN",
  "token_type": "bearer",
  "user": {
    "id": "usr_7a8b9c",
    "email": "user@example.com",
    "username": "analyst"
  }
}
```

#### `GET /api/v1/auth/me`
Retrieves current authenticated user profile. Requires Bearer Token.

---

### 2.2 Health & Platform Metadata

#### `GET /api/v1/health`
Returns system status, app version (`1.0.0`), database status, and user chain health state.

**Response (200 OK):**
```json
{
  "status": "online",
  "app": "HashLens",
  "version": "1.0.0",
  "environment": "production",
  "database": "healthy",
  "chain_health": "CHAIN_VALID"
}
```

#### `GET /api/v1/algorithms`
Returns supported cryptographic hash algorithms (`md5`, `sha1`, `sha256`, `sha512`) and security advisories.

---

### 2.3 Cryptographic Hashing & Forensics

#### `POST /api/v1/hash/text`
Computes cryptographic digests for text strings across requested algorithms.

**Request Body:**
```json
{
  "text": "Forensic verification test string",
  "algorithms": ["sha256", "sha512", "md5"]
}
```

#### `POST /api/v1/hash/file`
Processes an uploaded file via streaming chunked I/O.

**Multipart Form:**
* `file`: Binary file upload (max 100 MB)
* `chunk_size`: Integer (4,096 to 16,777,216 bytes; default: 65,536)

#### `POST /api/v1/avalanche`
Calculates bit-flip avalanche metrics between two text payloads.

#### `POST /api/v1/compare`
Compares two fingerprint objects and returns a 7-tier diagnostic assessment (`NO_CHANGE`, `CONTENT_MODIFICATION`, `SIZE_CHANGE`, `STRUCTURAL_CHANGE`, `METADATA_CHANGE`, `FILE_TYPE_CHANGE`, `MAJOR_REPLACEMENT`, `INCONCLUSIVE`).

---

### 2.4 Version Tracking & Asset Baselines

#### `GET /api/v1/files`
Lists tracked assets owned by the current user (`Authorization: Bearer YOUR_JWT_ACCESS_TOKEN`).

#### `POST /api/v1/files/track`
Registers a new file baseline or appends a new version for an existing asset.

#### `GET /api/v1/files/{file_id}/timeline`
Retrieves chronological version history for an owned asset. Returns `404 Not Found` if not owned.

---

### 2.5 Tamper-Evident Hash Chain

#### `GET /api/v1/chain/status` & `POST /api/v1/chain/verify`
Performs an active cryptographic audit across user ledger blocks ($H_n = \text{SHA256}(\text{Record}_n + H_{n-1})$).

#### `GET /api/v1/chain/records`
Retrieves paginated ledger blocks for the authenticated user.

---

### 2.6 Evidence Reporting

#### `POST /api/v1/evidence/generate`
Generates a structured forensic Evidence Report signed with a canonical **Evidence Report Hash** (SHA-256 digest).

#### `GET /api/v1/evidence/{report_id}`
Retrieves JSON envelope for an owned report.

#### `GET /api/v1/evidence/{report_id}/html`
Renders standalone printable forensic HTML document.

---

## 3. Safe cURL Code Examples

### Login & Token Acquisition
```bash
curl -X POST \
  "<HASHLENS_API>/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"login":"analyst@example.com","password":"YOUR_PASSWORD"}'
```

### Text Hashing
```bash
curl -X POST \
  "<HASHLENS_API>/api/v1/hash/text" \
  -H "Content-Type: application/json" \
  -d '{"text":"Verification text payload","algorithms":["sha256","sha512"]}'
```

### Track Asset Version
```bash
curl -X POST \
  "<HASHLENS_API>/api/v1/files/track" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"filename":"auth.log","hashes":{"sha256":"82e631289..."},"size_bytes":2048,"chunk_count":1}'
```

### Audit Hash Chain Integrity
```bash
curl -X POST \
  "<HASHLENS_API>/api/v1/chain/verify" \
  -H "Authorization: Bearer YOUR_TOKEN"
```
