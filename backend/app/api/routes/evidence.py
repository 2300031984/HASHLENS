"""
HashLens Evidence Report Routes
Generates certified forensic reports, returns Evidence Report Hashes,
and renders printable forensic HTML certificates.
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
    Generates a certified forensic evidence report with an embedded SHA-256
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
    """Retrieves an existing evidence report by ID."""
    report = EvidenceService.get_report_by_id(db, report_id)
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evidence report '{report_id}' not found.",
        )
    return report


@router.get("/evidence/{report_id}/html", response_class=HTMLResponse)
def get_evidence_html_certificate(
    report_id: str,
    db: Session = Depends(get_db),
):
    """Renders a standalone, printable cybersecurity forensic evidence certificate."""
    report = EvidenceService.get_report_by_id(db, report_id)
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evidence report '{report_id}' not found.",
        )
    html_content = EvidenceService.render_html_report(report)
    return HTMLResponse(content=html_content)
