# HashLens Production Deployment & Operations Guide

This guide covers local development setups, Docker container orchestration, production reverse proxy configuration (Nginx / Caddy), PostgreSQL database transition, and HTTPS hardening.

---

## 1. Environment Configuration

Copy `.env.example` to `.env` and configure operational parameters:

```bash
# Core Environment
APP_NAME=HashLens
APP_ENV=production
DEBUG=false

# API Server Binding
API_HOST=0.0.0.0
API_PORT=8000
API_V1_PREFIX=/api/v1

# Security Bounds
MAX_UPLOAD_SIZE=104857600   # 100 MB max upload
CHUNK_SIZE=1048576          # 1 MB default chunk size
RATE_LIMIT_REQUESTS=120     # Max requests/minute per IP
RATE_LIMIT_WINDOW_SECONDS=60
SECRET_KEY=generate-a-strong-random-hex-key-here

# Database Configuration (PostgreSQL / SQLite)
DATABASE_URL=postgresql+psycopg2://hashlens_user:secure_password@postgres:5432/hashlens_db
# Or SQLite: sqlite:////app/data/hashlens.db

# Allowed CORS Origins
ALLOWED_ORIGINS=https://hashlens.yourdomain.com,https://api.hashlens.yourdomain.com
```

---

## 2. Docker & Containerized Deployment

HashLens includes multi-container Docker Compose orchestration with isolated bridge networking and persistent storage volumes:

### 2.1 Build and Launch
```bash
docker compose up --build -d
```

### 2.2 Verify Container Health
```bash
docker compose ps
```

* **FastAPI Backend:** Runs on `http://localhost:8000` (Healthcheck on `/api/v1/health`)
* **Streamlit SOC Dashboard:** Runs on `http://localhost:8501` (Healthcheck on `/_stcore/health`)
* **Container Hardening:** Containers execute as dedicated unprivileged user `hashlens` (UID 10001).

### 2.3 Stop Stack
```bash
docker compose down
```

---

## 3. Production Reverse Proxy (Nginx Architecture)

Deploy Nginx in front of HashLens to handle TLS termination, HTTP/2 or HTTP/3, and DDoS buffering.

```nginx
server {
    listen 80;
    server_name hashlens.yourdomain.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name hashlens.yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/hashlens.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/hashlens.yourdomain.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    # Maximum file upload ceiling matching backend MAX_UPLOAD_SIZE
    client_max_body_size 100M;

    # Dashboard routing (WebSocket support for Streamlit)
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

    # API Routing
    location /api/ {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

---

## 4. Database Transition: SQLite to PostgreSQL

HashLens uses standard SQLAlchemy 2.0 ORM dialect abstractions. Migrating to PostgreSQL requires zero code changes:

1. Deploy PostgreSQL 15+ container or managed instance (RDS, Cloud SQL).
2. Update `.env`:
   ```bash
   DATABASE_URL=postgresql+psycopg2://hashlens_user:secure_password@postgres:5432/hashlens_db
   ```
3. Restart backend container; the application startup hook (`init_db()`) automatically creates all schemas, foreign keys, and indexes.
