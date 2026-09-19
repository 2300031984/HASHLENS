"""
HashLens File Comparison & Diagnostics Route
Compares two files or fingerprints, identifies chunk discrepancies,
and diagnoses why cryptographic hashes changed.
"""

from typing import Any, Dict, Optional
from fastapi import APIRouter, File, Form, HTTPException, UploadFile, status

from backend.app.core.config import settings
from backend.app.schemas.schemas import CompareRequest, CompareResponse
from backend.app.services.comparison_service import ComparisonEngine
from backend.app.services.fingerprint_service import FingerprintService

router = APIRouter(tags=["Comparison & Forensics"])


@router.post("/compare", response_model=CompareResponse)
def compare_fingerprints_endpoint(payload: CompareRequest):
    """Compares two pre-computed file fingerprints and provides forensic root-cause diagnosis."""
    try:
        return ComparisonEngine.compare_fingerprints(
            fp_a=payload.fingerprint_a,
            fp_b=payload.fingerprint_b,
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unable to compare fingerprints: {str(e)}",
        )


@router.post("/compare/files", response_model=CompareResponse)
async def compare_two_files_endpoint(
    file_a: UploadFile = File(..., description="First file (baseline/original)"),
    file_b: UploadFile = File(..., description="Second file (modified/suspect)"),
    chunk_size: int = Form(default=settings.DEFAULT_CHUNK_SIZE),
):
    """Streams two files simultaneously, extracts fingerprints, and returns forensic comparison diff."""
    try:
        fp_a = FingerprintService.generate_fingerprint_from_stream(
            stream=file_a.file,
            raw_filename=file_a.filename or "file_a",
            chunk_size=chunk_size,
            max_size=settings.MAX_UPLOAD_SIZE,
        )
        fp_b = FingerprintService.generate_fingerprint_from_stream(
            stream=file_b.file,
            raw_filename=file_b.filename or "file_b",
            chunk_size=chunk_size,
            max_size=settings.MAX_UPLOAD_SIZE,
        )
        return ComparisonEngine.compare_fingerprints(fp_a, fp_b)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Comparison failed: {str(e)}")
    finally:
        await file_a.close()
        await file_b.close()
