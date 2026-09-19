"""
HashLens Version Tracking & Timeline Routes
Provides file lifecycle tracking, chronological timelines, and version management.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.app.api.deps import get_optional_current_user
from backend.app.db.database import get_db
from backend.app.models.models import UserModel
from backend.app.schemas.schemas import (
    TrackedFileSummary,
    FileTimelineResponse,
)
from backend.app.services.history_service import HistoryService

router = APIRouter(tags=["Version Tracking & Timeline"])


@router.get("/files", response_model=List[TrackedFileSummary])
def list_files_endpoint(
    current_user: Optional[UserModel] = Depends(get_optional_current_user),
    db: Session = Depends(get_db),
):
    """Lists tracked assets owned by current user with latest version and integrity status."""
    user_id = current_user.id if current_user else None
    return HistoryService.list_tracked_files(db, user_id=user_id)


@router.get("/files/{file_id}/timeline", response_model=FileTimelineResponse)
def get_timeline_endpoint(
    file_id: str,
    current_user: Optional[UserModel] = Depends(get_optional_current_user),
    db: Session = Depends(get_db),
):
    """Retrieves full version progression timeline for an asset owned by current user."""
    user_id = current_user.id if current_user else None
    try:
        return HistoryService.get_file_timeline(db, file_id, user_id=user_id)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.post("/files/track")
def track_file_version_endpoint(
    fingerprint: Dict[str, Any],
    current_user: Optional[UserModel] = Depends(get_optional_current_user),
    db: Session = Depends(get_db),
):
    """
    Registers a new file baseline or appends a new version to an existing file for current user.
    Logs lifecycle event to the Tamper-Evident Hash Chain.
    """
    user_id = current_user.id if current_user else None
    try:
        return HistoryService.register_or_update_file(db, fingerprint, user_id=user_id)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

