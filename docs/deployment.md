# HASHLENS — Deployment & Production Architecture Guide

This document covers executing HASHLENS in local development mode, containerizing it with Docker Compose, deploying with PostgreSQL production persistence, and deploying to cloud platforms like Render.

---

## 1. Environment Variables Reference

| Variable Name | Type | Default | Mode | Description |
| :--- | :--- | :--- | :--- | :--- |
| `APP_NAME` | string | `"HashLens"` | Required | Application brand title. |
| `APP_VERSION` | string | `"1.0.0"` | Required | Platform release version. |
| `APP_ENV` | string | `"development"` | Required | `"development"` vs `"production"`. Production gates tamper simulation and validates secrets. |
| `DEBUG` | boolean | `false` | Development | Enables debug output. Must be `false` in production. |
| `DATABASE_URL` | string | `sqlite:///./data/hashlens.db` | Required | SQLite (`sqlite:///...`) or PostgreSQL (`postgresql+psycopg://user:pass@host:5432/db`). |
| `JWT_SECRET_KEY` | string | *(random)* | Production | Cryptographic secret for signing JWT access tokens. Must be set in production. |
| `JWT_ALGORITHM` | string | `"HS256"` | Required | HMAC SHA-256 algorithm for JWT tokens. |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | int | `60` | Optional | JWT token lifetime in minutes. |
| `API_HOST` | string | `"0.0.0.0"` | Required | Binding IP address for uvicorn backend. |
| `API_PORT` | int | `8000` | Required | Backend service port. |
| `MAX_UPLOAD_SIZE` | int | `104857600` | Optional | Maximum file upload size in bytes (default 100 MB). |
| `RATE_LIMIT_REQUESTS` | int | `120` | Optional | Maximum requests per client IP per window. |
| `RATE_LIMIT_WINDOW_SECONDS` | int | `60` | Optional | Sliding window size for rate limiting. |
| `ENABLE_HSTS` | boolean | `false` | Optional | Enables `Strict-Transport-Security` header in HTTPS production. |
| `ALLOWED_ORIGINS` | list | `["*"]` | Production | Allowed CORS origin URLs. |

---

## 2. Local Python Development (SQLite Mode)

### Prerequisites & Installation
```bash
git clone https://github.com/2300031984/HASHLENS.git
cd HASHLENS

python -m venv venv
# On Windows:
venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate

pip install -r backend/requirements.txt -r dashboard/requirements.txt
```

### Local Execution
```bash
# Terminal 1: Start REST Backend API
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000

# Terminal 2: Start Streamlit Web Dashboard
python -m streamlit run dashboard/app.py --server.port 8501 --server.address 127.0.0.1
```

Access:
- **Streamlit Dashboard:** `http://127.0.0.1:8501`
- **FastAPI OpenAPI Docs:** `http://127.0.0.1:8000/docs`
- **Backend Health Check:** `http://127.0.0.1:8000/api/v1/health`

---

## 3. Docker Compose Stack (PostgreSQL / SQLite Options)

HASHLENS includes multi-container Docker Compose orchestration supporting backend, dashboard, and an optional PostgreSQL 16 container (`postgres`).

### Launching Docker Stack
```bash
# Build and launch all services in detached mode
docker compose up --build -d

# Check service container status
docker compose ps

# View real-time container logs
docker compose logs -f

# Stop and tear down containers
docker compose down
```

---

## 4. Production Deployment & Database Migrations

### Production Database Configuration
Set `DATABASE_URL` to your production PostgreSQL connection string:
```bash
DATABASE_URL=postgresql+psycopg://hashlens_user:YOUR_SECURE_DB_PASSWORD@postgres-host:5432/hashlens_db
```

### Database Auto-Migrations
Database schemas auto-initialize on application startup via SQLAlchemy metadata creation. For explicit Alembic versioned migrations:
```bash
# Run database migrations to head
python -m alembic upgrade head
```

---

## 5. Render Blueprint Deployment

Deploying HASHLENS to Render is automated using `render.yaml`:

1. Connect `https://github.com/2300031984/HASHLENS` to Render.
2. Select **Blueprint** deployment.
3. Configure environment variables for `hashlens-backend` (`APP_ENV=production`, `JWT_SECRET_KEY=YOUR_SECRET`, `DATABASE_URL`).
4. Healthchecks monitor `http://localhost:8000/api/v1/health` and `http://localhost:8501/_stcore/health`.
