# HashLens Dashboard Dockerfile
FROM python:3.11-slim as base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    STREAMLIT_SERVER_PORT=8501 \
    STREAMLIT_SERVER_ADDRESS=0.0.0.0 \
    STREAMLIT_SERVER_HEADLESS=true

WORKDIR /app

# Install security updates
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY dashboard/requirements.txt .
COPY backend/requirements.txt ./backend_requirements.txt
RUN pip install --no-cache-dir -r requirements.txt -r backend_requirements.txt

# Create non-root user
RUN groupadd -g 10001 hashlens && \
    useradd -u 10001 -g hashlens -s /bin/bash -m hashlens

# Copy code
COPY dashboard/ /app/dashboard/
COPY backend/ /app/backend/
COPY .env.example /app/.env

RUN mkdir -p /app/data /app/temp && chown -R hashlens:hashlens /app

USER hashlens

EXPOSE 8501

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8501/_stcore/health || exit 1

CMD ["streamlit", "run", "dashboard/app.py", "--server.port=8501", "--server.address=0.0.0.0"]
