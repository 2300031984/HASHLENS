"""
HashLens Health & Diagnostics Route
Provides runtime health, DB connectivity, and chain integrity status.
"""

import time
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import text

from backend.app.core.config import settings
from backend.app.db.database import get_db
from backend.app.schemas.schemas import HealthResponse
from backend.app.services.chain_service import HashChainService

router = APIRouter(tags=["Health & Status"])
START_TIME = time.time()


@router.get("/health", response_model=HealthResponse)
def get_health(db: Session = Depends(get_db)):
    """Performs deep health check across database and audit chain."""
    # Check DB
    try:
        db.execute(text("SELECT 1"))
        db_status = "healthy"
    except Exception as e:
        db_status = f"unhealthy: {str(e)}"

    # Check Chain
    try:
        audit = HashChainService.verify_chain(db)
        chain_status = audit["status"]
    except Exception:
        chain_status = "error"

    uptime = round(time.time() - START_TIME, 2)

    return {
        "status": "online" if db_status == "healthy" else "degraded",
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "environment": settings.APP_ENV,
        "uptime_seconds": uptime,
        "database": db_status,
        "chain_health": chain_status,
    }
