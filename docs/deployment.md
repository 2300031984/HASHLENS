# HASHLENS — Deployment & Production Architecture Guide

This document covers running HASHLENS in local development mode, containerizing it with Docker Compose for local self-hosting, and preparing the architecture for public Internet deployment behind an HTTPS reverse proxy.

> [!NOTE]
> **Hosted Instance Notice:** This repository provides source code and Docker containerization for self-hosted execution. It does **not** provide or maintain a publicly hosted cloud instance.

---

## 1. Local Python Development

This section covers executing HASHLENS directly on a host workstation using Python 3.11+.

### 1.1 Prerequisites & Virtual Environment
```bash
# Clone the repository
git clone https://github.com/2300031984/HASHLENS.git
cd HASHLENS

# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

# Install dependencies
pip install -r backend/requirements.txt -r dashboard/requirements.txt
```

### 1.2 Configuration
Copy `.env.example` to `.env` in the project root:
```bash
APP_ENV=development
DEBUG=true
API_HOST=127.0.0.1
API_PORT=8000
MAX_UPLOAD_SIZE=104857600
ENABLE_HSTS=false
```

### 1.3 Running Local Servers
Start the FastAPI REST Backend (Terminal 1):
```bash
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
```

Start the Streamlit Forensic Dashboard (Terminal 2):
```bash
python -m streamlit run dashboard/app.py --server.port 8501 --server.address 127.0.0.1
```

Access endpoints:
- **Streamlit Dashboard:** `http://127.0.0.1:8501`
- **FastAPI REST Documentation:** `http://127.0.0.1:8000/docs`
- **Health Check Endpoint:** `http://127.0.0.1:8000/api/v1/health`

---

## 2. Local Docker Containerization

HASHLENS includes a multi-container Docker Compose configuration that orchestrates the FastAPI backend and Streamlit dashboard over an isolated bridge network (`hashlens-network`).

### 2.1 Container Architecture & Security Controls
- **Non-Root User Execution:** Containers execute under dedicated unprivileged user `hashlens` (UID `10001`).
- **Persistent Storage:** Database records and generated reports are stored in persistent volume `hashlens_shared_data` mounted at `/app/data`.
- **Health Monitoring:** Healthcheck directives monitor `http://localhost:8000/api/v1/health` and `http://localhost:8501/_stcore/health`.

### 2.2 Orchestration Commands

**Launch Stack:**
```bash
docker compose up --build -d
```

**Verify Service Status:**
```bash
docker compose ps
```

**Inspect Container Logs:**
```bash
docker compose logs -f
```

**Stop Stack:**
```bash
docker compose down
```

**Published Ports:**
- `8000:8000` — FastAPI Backend API
- `8501:8501` — Streamlit Forensic Dashboard

---

## 3. Public Deployment Architecture

When deploying HASHLENS to a public server or cloud instance, the application must be deployed behind an HTTPS reverse proxy (such as Nginx, Caddy, or Traefik) that terminates TLS and proxies traffic to the internal containers.

### 3.1 Data Flow & Traffic Routing

```text
User Browser / Client
        ↓
    [ Domain ]
        ↓
HTTPS Reverse Proxy (Port 80 / 443)  ← TLS Certificate Termination
        │
        ├──────► Streamlit Dashboard (Internal Port 8501 / WebSocket)
        │
        └──────► FastAPI REST API (Internal Port 8000 / HTTP)
                    │
                    ▼
          Persistent Storage Volume (/app/data)
```

### 3.2 Production Nginx Reverse Proxy Configuration Example

Below is a reference Nginx configuration demonstrating HTTPS TLS termination, WebSocket upgrading for Streamlit, body size alignment, and API reverse proxying:

```nginx
# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name <YOUR_DOMAIN>;
    return 301 https://$host$request_uri;
}

# Main HTTPS Server Block
server {
    listen 443 ssl http2;
    server_name <YOUR_DOMAIN>;

    ssl_certificate /etc/letsencrypt/live/<YOUR_DOMAIN>/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/<YOUR_DOMAIN>/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    # Align Reverse Proxy Upload Ceiling with Backend MAX_UPLOAD_SIZE (100 MB)
    client_max_body_size 100M;

    # Route Dashboard & WebSockets to Streamlit Container
    location / {
        proxy_pass http://127.0.0.1:8501;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Route REST API Requests to FastAPI Container
    location /api/ {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### 3.3 Production Environment Hardening
1. **Enable HSTS:** Set `ENABLE_HSTS=true` in `.env` **after** confirming HTTPS reverse proxy routing operates cleanly.
2. **Configure CORS:** Set `ALLOWED_ORIGINS=https://<YOUR_DOMAIN>` to restrict cross-origin browser requests.
3. **Upload Limits:** Ensure Nginx `client_max_body_size` matches FastAPI `MAX_UPLOAD_SIZE` (100 MB).
4. **Deployment Verification:** Complete all verification steps documented in [`docs/public-deployment-checklist.md`](file:///d:/CyberTools/HashLens/docs/public-deployment-checklist.md).
