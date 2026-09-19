# HASHLENS — Public Deployment Readiness Checklist

This checklist provides step-by-step verification criteria for deploying HASHLENS as a production, publicly accessible web application behind an HTTPS reverse proxy.

---

## 1. Infrastructure Preparation

- [ ] **Hosting Server Provisioned:** Compute instance (Linux/Ubuntu 22.04 LTS or equivalent) provisioned with sufficient RAM (minimum 2 GB) and CPU cores.
- [ ] **Docker & Compose Installed:** Docker Engine (v24.0+) and Docker Compose (v2.20+) installed and running as a system daemon.
- [ ] **Firewall & Security Groups Configured:**
  - Port `80` (HTTP) open for Let's Encrypt ACME challenges and HTTP-to-HTTPS redirection.
  - Port `443` (HTTPS) open for public web traffic.
  - Port `22` (SSH) restricted to authorized admin IPs.
  - Internal application ports (`8000`, `8501`) **blocked** from direct external access.
- [ ] **Domain & DNS Configured:** A/AAAA records pointed to the server's public IP address (e.g. `hashlens.example.com`).

---

## 2. Application & Environment Configuration

- [ ] **Production `.env` Created:** Created from `.env.example` with production parameter overrides:
  - `APP_ENV=production`
  - `DEBUG=false`
  - `ENABLE_HSTS=true` (after verifying HTTPS reverse proxy functionality)
  - `MAX_UPLOAD_SIZE=104857600` (100 MB default)
  - `RATE_LIMIT_REQUESTS=120`
  - `RATE_LIMIT_WINDOW_SECONDS=60`
  - `ALLOWED_ORIGINS` configured to match the public domain URL.
- [ ] **Persistent Storage Volumes Verified:** Docker volume `hashlens_shared_data` created and mounted at `/app/data` to ensure SQLite database (`hashlens.db`) and evidence reports persist across container updates.
- [ ] **Temporary Storage Permissions:** Directory `/app/temp` writable by non-root user `hashlens` (UID `10001`) with automated post-hash cleanup.
- [ ] **Reverse Proxy Body Size Aligned:** Reverse proxy `client_max_body_size` set to `100M` to match backend `MAX_UPLOAD_SIZE`.
- [ ] **Container Healthchecks Active:** Backend healthcheck (`GET /api/v1/health`) and Dashboard healthcheck (`GET /_stcore/health`) configured and healthy.

---

## 3. HTTPS & TLS Termination

- [ ] **TLS Certificate Obtained:** Automated X.509 certificate provisioned (e.g. via Certbot / Let's Encrypt or corporate CA).
- [ ] **HTTP → HTTPS Redirection:** Reverse proxy configured to automatically redirect unencrypted HTTP (port 80) requests to HTTPS (port 443).
- [ ] **Automated Certificate Renewal:** Automated renewal cron/timer tested and verified (`certbot renew --dry-run`).
- [ ] **HSTS Header Enabled:** `ENABLE_HSTS=true` set in environment to emit `Strict-Transport-Security` headers after verifying TLS termination.

---

## 4. Container & System Security

- [ ] **No Repository Secrets:** Verified `.env` file excluded from version control (`.gitignore`) and zero embedded secrets in container images.
- [ ] **Unprivileged User Execution:** Both backend and dashboard containers execute strictly under non-root user `hashlens` (UID `10001`).
- [ ] **Minimal Host Port Exposure:** Only reverse proxy ports (80/443) published publicly; container-to-container traffic restricted to `hashlens-network` bridge.
- [ ] **Filename & Path Traversal Protections:** Uploaded files sanitized via `Path(filename).name`; execution bits explicitly disabled on upload directories.
- [ ] **Error Masking:** API error responses sanitized to prevent internal path, environment, or stack trace disclosure.

---

## 5. Post-Deployment Functional & Security Validation

- [ ] **External Browser Navigation:** Web dashboard (`https://<domain>/`) loads securely over HTTPS with valid TLS certificate lock icon.
- [ ] **API Endpoint Verification:** OpenAPI documentation (`https://<domain>/docs`) and health endpoint (`https://<domain>/api/v1/health`) accessible.
- [ ] **File Hashing & Upload Test:** Upload sample file; verify multi-algorithm hashes generated and temporary file cleaned.
- [ ] **Forensic File Differential Test:** Perform 2-file forensic comparison; verify 7-tier classification (`CONTENT_MODIFICATION`, `SIZE_CHANGE`, etc.) works.
- [ ] **Hash Chain Ledger Verification:** Run chain audit; confirm `CHAIN_VALID` status and tamper simulation functionality.
- [ ] **Certified Evidence Report Verification:** Export Evidence Report; confirm canonical SHA-256 evidence digest verification succeeds independently.
- [ ] **Rate Limit Verification:** Send rapid requests; confirm HTTP 429 response when threshold is exceeded.
