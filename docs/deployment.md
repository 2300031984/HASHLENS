# HASHLENS — Deployment & Production Architecture Guide

This document covers running HASHLENS in local development mode, containerizing it with Docker Compose for local self-hosting, deploying via generic HTTPS reverse proxies, and deploying to cloud PaaS platforms like Render.

> [!NOTE]
> **Hosted Instance Notice:** This repository provides source code, Docker containerization, and Render Blueprint configurations for self-hosted execution. It does **not** provide or maintain a publicly hosted cloud instance.

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

## 3. Public Reverse Proxy Deployment Architecture

When deploying HASHLENS to a self-hosted VPS or cloud VM, the application should be deployed behind an HTTPS reverse proxy (such as Nginx, Caddy, or Traefik) that terminates TLS and proxies traffic to internal containers.

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

---

## 4. Render Blueprint Deployment

HASHLENS includes a pre-configured `render.yaml` Render Blueprint specification for automated cloud deployment as two separate Docker Web Services on Render.

### 4.1 Architecture on Render

```text
GitHub Repository (2300031984/HASHLENS)
        │
        ▼
   Render Engine (render.yaml Blueprint)
        │
        ├──► Web Service 1: hashlens-backend (FastAPI / Docker)
        │    - Port: 8000 (0.0.0.0)
        │    - Healthcheck: /api/v1/health
        │    - Public URL: https://hashlens-backend.onrender.com
        │
        └──► Web Service 2: hashlens-dashboard (Streamlit / Docker)
             - Port: 8501 (0.0.0.0)
             - Healthcheck: /_stcore/health
             - API_URL: https://hashlens-backend.onrender.com
             - Public URL: https://hashlens-dashboard.onrender.com
```

### 4.2 Step-by-Step Render Deployment Workflow

1. **Push Repository to GitHub:** Ensure your latest commits are pushed to your GitHub repository ([`https://github.com/2300031984/HASHLENS`](https://github.com/2300031984/HASHLENS)).
2. **Create a Render Account:** Sign in at [dashboard.render.com](https://dashboard.render.com).
3. **Deploy Blueprint:**
   - Click **New +** → **Blueprint**.
   - Connect your GitHub repository `2300031984/HASHLENS`.
   - Render automatically detects `render.yaml` and defines both `hashlens-backend` and `hashlens-dashboard` services.
4. **Configure Environment Variables:**
   - For `hashlens-backend`:
     - `APP_ENV`: `production`
     - `ALLOWED_ORIGINS`: `https://hashlens-dashboard.onrender.com` (replace with your actual Render dashboard URL)
     - `ENABLE_HSTS`: `false` (set to `true` after verifying HTTPS routing)
   - For `hashlens-dashboard`:
     - `API_URL`: Set to the backend's public Render URL (`https://hashlens-backend.onrender.com`).
5. **Configure Persistent Disk (Optional):**
   - On Render Free Tier, filesystems are ephemeral (SQLite data resets on container restart/redeploy).
   - To persist SQLite data and evidence reports across redeploys, attach a **Render Persistent Disk** at `/app/data` (size: 1 GB) on the backend service.
6. **Verify Deployment:**
   - Open `https://hashlens-backend.onrender.com/api/v1/health` to confirm HTTP 200 health response.
   - Open `https://hashlens-dashboard.onrender.com` to access the Streamlit forensic interface.
   - Test text hashing, file diffing, integrity chain auditing, and report generation.
