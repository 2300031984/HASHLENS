"""
HashLens Tamper-Evident Hash Chain Routes
Provides cryptographic audit endpoints, chain block exploration,
and live tamper detection simulation.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.app.api.deps import get_optional_current_user
from backend.app.core.config import settings
from backend.app.db.database import get_db
from backend.app.models.models import ChainRecordModel, UserModel
from backend.app.schemas.schemas import ChainAuditResponse, ChainRecordSchema
from backend.app.services.chain_service import HashChainService

router = APIRouter(tags=["Tamper-Evident Hash Chain"])


@router.get("/chain/status", response_model=ChainAuditResponse)
def get_chain_status(
    current_user: Optional[UserModel] = Depends(get_optional_current_user),
    db: Session = Depends(get_db),
):
    """Audits the tamper-evident hash chain for current user and returns cryptographic health status."""
    user_id = current_user.id if current_user else None
    return HashChainService.verify_chain(db, user_id=user_id)


@router.post("/chain/verify", response_model=ChainAuditResponse)
def verify_chain_endpoint(
    current_user: Optional[UserModel] = Depends(get_optional_current_user),
    db: Session = Depends(get_db),
):
    """Forces an active cryptographic audit across user's chain records."""
    user_id = current_user.id if current_user else None
    return HashChainService.verify_chain(db, user_id=user_id)


@router.get("/chain/records", response_model=List[ChainRecordSchema])
def get_chain_records_endpoint(
    limit: int = Query(default=50, ge=1, le=200),
    current_user: Optional[UserModel] = Depends(get_optional_current_user),
    db: Session = Depends(get_db),
):
    """Retrieves chronological blocks in the user's tamper-evident audit chain."""
    user_id = current_user.id if current_user else None
    return HashChainService.get_records(db, limit=limit, user_id=user_id)


@router.post("/chain/simulate-tamper")
def simulate_tamper_endpoint(
    record_id: str,
    current_user: Optional[UserModel] = Depends(get_optional_current_user),
    db: Session = Depends(get_db),
):
    """
    DEMONSTRATION ONLY: Deliberately alters the payload of a specific record
    to verify that the audit engine detects cryptographic corruption.
    Disabled in production mode.
    """
    if settings.APP_ENV == "production":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Tamper simulation endpoint is disabled in production mode.",
        )

    user_id = current_user.id if current_user else None
    query = db.query(ChainRecordModel).filter(ChainRecordModel.record_id == record_id)
    if user_id is not None:
        query = query.filter(ChainRecordModel.user_id == user_id)

    record = query.first()
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Record '{record_id}' not found.",
        )

    # Invalidate payload
    record.payload_json = '{"tampered_for_demo": true, "unauthorized_change": "MALICIOUS_INJECTION"}'
    db.commit()

    return {
        "message": f"Record {record_id} successfully tampered for demonstration.",
        "record_id": record_id,
        "sequence_num": record.sequence_num,
        "instruction": "Now run /api/v1/chain/verify to observe cryptographic failure detection.",
    }

