"""
HashLens Hashing & Fingerprinting Routes
Provides text hashing, streaming file hashing, chunk block mapping, and avalanche metrics.
"""

from typing import Dict, List, Optional
from fastapi import APIRouter, File, Form, HTTPException, UploadFile, status
from pydantic import ValidationError

from backend.app.core.config import settings
from backend.app.schemas.schemas import (
    TextHashRequest,
    TextHashResponse,
    FileFingerprintResponse,
    AvalancheRequest,
    AvalancheResponse,
)
from backend.app.services.fingerprint_service import FingerprintService
from backend.app.services.hashing_engine import (
    HashingEngine,
    SUPPORTED_ALGORITHMS,
    ALGORITHM_METADATA,
)

router = APIRouter(tags=["Hashing & Fingerprinting"])


@router.get("/algorithms")
def list_algorithms():
    """Returns supported cryptographic algorithms and comprehensive security & collision metadata."""
    return {
        "supported_algorithms": SUPPORTED_ALGORITHMS,
        "metadata": ALGORITHM_METADATA,
        "password_security_notice": (
            "IMPORTANT: Raw cryptographic hash functions (MD5, SHA-1, SHA-256, SHA-512) "
            "must NEVER be used for password storage. Passwords must be hashed using memory-hard "
            "adaptive Key Derivation Functions (KDFs) such as Argon2id, bcrypt, or scrypt."
        ),
    }


@router.post("/hash/text", response_model=TextHashResponse)
def hash_text_endpoint(payload: TextHashRequest):
    """Computes cryptographic digests for text input with selected algorithms."""
    try:
        raw_text = payload.text
        encoded_bytes = raw_text.encode("utf-8")
        digests = HashingEngine.hash_text(raw_text, algorithms=payload.algorithms)
        return {
            "input_length_chars": len(raw_text),
            "input_length_bytes": len(encoded_bytes),
            "hashes": digests,
            "algorithms_used": list(digests.keys()),
        }
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/hash/file", response_model=FileFingerprintResponse)
async def hash_file_endpoint(
    file: UploadFile = File(..., description="Binary or text file to analyze"),
    chunk_size: int = Form(default=settings.DEFAULT_CHUNK_SIZE, description="Chunk size in bytes"),
):
    """
    Computes whole-file multi-algorithm digests and sequential chunk-level SHA-256 fingerprints
    using streaming I/O. Does not load entire file into memory.
    """
    if chunk_size < settings.MIN_CHUNK_SIZE or chunk_size > settings.MAX_CHUNK_SIZE:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"chunk_size must be between {settings.MIN_CHUNK_SIZE} and {settings.MAX_CHUNK_SIZE} bytes.",
        )

    try:
        fingerprint = FingerprintService.generate_fingerprint_from_stream(
            stream=file.file,
            raw_filename=file.filename or "uploaded_file",
            chunk_size=chunk_size,
            max_size=settings.MAX_UPLOAD_SIZE,
        )
        return fingerprint
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error processing file stream.")
    finally:
        await file.close()


@router.post("/avalanche", response_model=AvalancheResponse)
def calculate_avalanche_endpoint(payload: AvalancheRequest):
    """Computes bit-flip avalanche metrics between two text inputs for a given hash algorithm."""
    try:
        alg = payload.algorithm.lower().strip()
        h1 = HashingEngine.hash_text(payload.text1, algorithms=[alg])[alg]
        h2 = HashingEngine.hash_text(payload.text2, algorithms=[alg])[alg]

        metrics = HashingEngine.calculate_avalanche(h1, h2)
        return {
            "algorithm": alg,
            "digest1": h1,
            "digest2": h2,
            "total_bits": int(metrics["total_bits"]),
            "flipped_bits": int(metrics["flipped_bits"]),
            "identical_bits": int(metrics["identical_bits"]),
            "flip_percentage": float(metrics["flip_percentage"]),
        }
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
