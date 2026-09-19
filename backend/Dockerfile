# HashLens Backend Dockerfile
FROM python:3.11-slim as base

# Prevent Python from writing .pyc files and buffer stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Install security updates and build tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy backend requirements and install dependencies
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Create non-privileged service user
RUN groupadd -g 10001 hashlens && \
    useradd -u 10001 -g hashlens -s /bin/bash -m hashlens

# Copy application source code
COPY backend/ /app/backend/
COPY .env.example /app/.env

# Create data and log directories with non-root ownership
RUN mkdir -p /app/data /app/temp /app/data/reports && \
    chown -R hashlens:hashlens /app

USER hashlens

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/api/v1/health || exit 1

CMD ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
