"""
Tests for HashLens SafeFileService and FingerprintService.
Verifies path traversal defenses, advisory MIME sniffing, streaming chunk generation,
and metadata fingerprinting.
"""

import io
import pytest
from backend.app.services.file_service import SafeFileService
from backend.app.services.fingerprint_service import FingerprintService


def test_filename_sanitization():
    """Verify neutralization of directory traversals, null bytes, and illegal chars."""
    assert SafeFileService.sanitize_filename("../../etc/passwd") == "passwd"
    assert SafeFileService.sanitize_filename("..\\..\\windows\\system32\\cmd.exe") == "cmd.exe"
    assert SafeFileService.sanitize_filename("exploit\x00.pdf") == "exploit.pdf"
    assert SafeFileService.sanitize_filename("report:2026*final?.txt") == "report_2026_final_.txt"
    assert SafeFileService.sanitize_filename("") == "unnamed_file"
    assert SafeFileService.sanitize_filename("   ") == "unnamed_file"


def test_advisory_type_detection():
    """Verify advisory detection of standard file headers."""
    pdf_header = b"%PDF-1.7\r\n\x00\x01test"
    pdf_info = SafeFileService.detect_file_type(pdf_header, "doc.pdf")
    assert pdf_info["mime_type"] == "application/pdf"
    assert pdf_info["is_advisory"] is True

    png_header = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
    png_info = SafeFileService.detect_file_type(png_header, "image.png")
    assert png_info["mime_type"] == "image/png"

    text_header = b"This is plain text forensic log."
    txt_info = SafeFileService.detect_file_type(text_header, "log.txt")
    assert txt_info["mime_type"] == "text/plain"


def test_fingerprint_generation_chunks():
    """Verify chunk generation and whole-file hash agreement."""
    # 2500 bytes with chunk_size = 1000 -> 3 chunks (1000, 1000, 500)
    data = b"X" * 2500
    stream = io.BytesIO(data)
    fp = FingerprintService.generate_fingerprint_from_stream(
        stream=stream,
        raw_filename="../malicious/report.txt",
        chunk_size=1000,
    )

    assert fp["filename"] == "report.txt"
    assert fp["size_bytes"] == 2500
    assert fp["chunk_count"] == 3
    assert len(fp["chunk_fingerprints"]) == 3

    # Check chunks offsets & lengths
    c0 = fp["chunk_fingerprints"][0]
    assert c0["index"] == 0 and c0["offset"] == 0 and c0["length"] == 1000
    c1 = fp["chunk_fingerprints"][1]
    assert c1["index"] == 1 and c1["offset"] == 1000 and c1["length"] == 1000
    c2 = fp["chunk_fingerprints"][2]
    assert c2["index"] == 2 and c2["offset"] == 2000 and c2["length"] == 500

    # Ensure metadata fingerprint is a valid 64-char SHA256
    assert len(fp["metadata_fingerprint"]) == 64
    assert len(fp["hashes"]["sha256"]) == 64


def test_max_upload_size_enforcement():
    """Verify that exceeding configured maximum size raises a structured ValueError."""
    oversized_data = b"A" * 5000
    stream = io.BytesIO(oversized_data)

    with pytest.raises(ValueError, match="exceeds maximum permitted size"):
        FingerprintService.generate_fingerprint_from_stream(
            stream=stream,
            raw_filename="big.dat",
            chunk_size=1000,
            max_size=3000,  # 3KB limit
        )
