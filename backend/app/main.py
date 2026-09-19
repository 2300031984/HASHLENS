"""
HashLens Backend Main Application
FastAPI REST API entrypoint for cryptographic hashing, chunk forensics,
version tracking, tamper-evident hash chaining, and evidence reporting.
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from backend.app.core.config import settings
from backend.app.core.logging import logger
from backend.app.core.security import SecurityHeadersMiddleware
from backend.app.db.database import init_db
from backend.app.api.routes import health, hashing, comparison, history, chain, evidence, auth


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown lifecycle management."""
    logger.info(f"Starting {settings.APP_NAME} v{settings.APP_VERSION} ({settings.APP_ENV})")
    settings.ensure_directories()
    init_db()
    logger.info("Database schema initialized and ready.")
    yield
    logger.info("Shutting down HashLens backend.")


app = FastAPI(
    title="HashLens File Integrity & Hash Forensics API",
    description=(
        "Production-grade cybersecurity REST API providing streaming cryptographic hashing "
        "(MD5, SHA-1, SHA-256, SHA-512), chunk-level forensic comparison, 'Why Did My Hash Change?' "
        "root-cause diagnostics, version tracking, tamper-evident audit chaining, and evidence reporting."
    ),
    version=settings.APP_VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url=f"{settings.API_V1_PREFIX}/openapi.json",
    lifespan=lifespan,
)

# 1. Defensive Security Headers & Rate Limiting Middleware
app.add_middleware(SecurityHeadersMiddleware)

# 2. CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


# Global Controlled Exception Handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    req_id = getattr(request.state, "request_id", "unknown")
    logger.error(f"Unhandled server error on {request.url.path}: {str(exc)}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "Internal server error.",
            "detail": "An unexpected error occurred. Incident has been recorded.",
            "request_id": req_id,
        },
    )


# Mount Versioned API Routes under /api/v1
v1_prefix = settings.API_V1_PREFIX
app.include_router(health.router, prefix=v1_prefix)
app.include_router(auth.router, prefix=v1_prefix)
app.include_router(hashing.router, prefix=v1_prefix)
app.include_router(comparison.router, prefix=v1_prefix)
app.include_router(history.router, prefix=v1_prefix)
app.include_router(chain.router, prefix=v1_prefix)
app.include_router(evidence.router, prefix=v1_prefix)


@app.get("/", tags=["Platform"])
def root_endpoint():
    """Root platform metadata."""
    return {
        "platform": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "environment": settings.APP_ENV,
        "documentation": "/docs",
        "api_prefix": settings.API_V1_PREFIX,
        "status": "OPERATIONAL",
    }
