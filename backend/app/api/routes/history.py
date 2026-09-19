"""
HashLens Version Tracking & Timeline Routes
Provides file lifecycle tracking, chronological timelines, and version management.
"""

from typing import Any, Dict, List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.app.db.database import get_db
from backend.app.schemas.schemas import (
    TrackedFileSummary,
    FileTimelineResponse,
)
from backend.app.services.history_service import HistoryService

router = APIRouter(tags=["Version Tracking & Timeline"])


@router.get("/files", response_model=List[TrackedFileSummary])
def list_files_endpoint(db: Session = Depends(get_db)):
    """Lists all tracked assets with latest version and integrity status."""
    return HistoryService.list_tracked_files(db)


@router.get("/files/{file_id}/timeline", response_model=FileTimelineResponse)
def get_timeline_endpoint(file_id: str, db: Session = Depends(get_db)):
    """Retrieves full version progression timeline for an asset."""
    try:
        return HistoryService.get_file_timeline(db, file_id)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.post("/files/track")
def track_file_version_endpoint(
    fingerprint: Dict[str, Any],
    db: Session = Depends(get_db),
):
    """
    Registers a new file baseline or appends a new version to an existing file.
    Logs lifecycle event to the Tamper-Evident Hash Chain.
    """
    try:
        return HistoryService.register_or_update_file(db, fingerprint)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
