"""
HashLens Evidence Report Routes
Generates forensic Evidence Reports, returns Evidence Report Hashes,
and renders printable Evidence Report HTML documents.
"""

from typing import Any, Dict, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from backend.app.db.database import get_db
from backend.app.schemas.schemas import EvidenceGenerateRequest
from backend.app.services.evidence_service import EvidenceService

router = APIRouter(tags=["Evidence Reporting"])


@router.post("/evidence/generate")
def generate_evidence_endpoint(
    payload: EvidenceGenerateRequest,
    db: Session = Depends(get_db),
):
    """
    Generates a forensic Evidence Report with an embedded SHA-256
    'Evidence Report Hash' and registers the event into the tamper-evident chain.
    """
    try:
        report = EvidenceService.generate_report(
            db=db,
            fingerprint=payload.fingerprint,
            comparison_result=payload.comparison_result,
            version_num=payload.version_num or 1,
            analyst_notes=payload.analyst_notes,
        )
        return report
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to generate evidence report: {str(e)}",
        )


@router.get("/evidence/{report_id}")
def get_evidence_report_endpoint(
    report_id: str,
    db: Session = Depends(get_db),
):
    """Retrieves an existing Evidence Report by ID."""
    report = EvidenceService.get_report_by_id(db, report_id)
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evidence report '{report_id}' not found.",
        )
    return report


@router.get("/evidence/{report_id}/html", response_class=HTMLResponse)
def get_evidence_html_report(
    report_id: str,
    db: Session = Depends(get_db),
):
    """Renders a standalone, printable cybersecurity forensic Evidence Report HTML document."""
    report = EvidenceService.get_report_by_id(db, report_id)
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evidence report '{report_id}' not found.",
        )
    html_content = EvidenceService.render_html_report(report)
    return HTMLResponse(content=html_content)
