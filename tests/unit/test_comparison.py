"""
Tests for HashLens Forensic Comparison & Diagnostic Engine.
Verifies chunk diffing accuracy, change percentages, and deterministic
'Why Did My Hash Change?' rules classification.
"""

import io
import pytest
from backend.app.services.fingerprint_service import FingerprintService
from backend.app.services.comparison_service import ComparisonEngine, ChangeClassification


def test_comparison_identical_files():
    """Verify that identical data generates NO_CHANGE classification."""
    data = b"Standard forensic baseline file data." * 100
    fp1 = FingerprintService.generate_fingerprint_from_stream(io.BytesIO(data), "baseline.txt", chunk_size=500)
    fp2 = FingerprintService.generate_fingerprint_from_stream(io.BytesIO(data), "baseline.txt", chunk_size=500)

    result = ComparisonEngine.compare_fingerprints(fp1, fp2)
    assert result["overall_status"] == "identical"
    assert result["sha256_changed"] is False
    assert result["size_changed"] is False
    assert result["change_percentage"] == 0.0
    assert result["assessment"]["classification"] == ChangeClassification.NO_CHANGE.value


def test_comparison_content_modification():
    """Verify localized modification inside one chunk."""
    # 3 chunks: [chunk 0, chunk 1, chunk 2]
    c0 = b"A" * 1000
    c1 = b"B" * 1000
    c2 = b"C" * 1000

    c1_modified = b"B" * 900 + b"MODIFIED" + b"B" * 92

    data1 = c0 + c1 + c2
    data2 = c0 + c1_modified + c2

    fp1 = FingerprintService.generate_fingerprint_from_stream(io.BytesIO(data1), "report.dat", chunk_size=1000)
    fp2 = FingerprintService.generate_fingerprint_from_stream(io.BytesIO(data2), "report.dat", chunk_size=1000)

    result = ComparisonEngine.compare_fingerprints(fp1, fp2)
    assert result["overall_status"] == "modified"
    assert result["sha256_changed"] is True
    assert result["size_changed"] is False
    assert result["chunks_matching"] == 2
    assert result["chunks_changed"] == 1
    assert result["assessment"]["classification"] == ChangeClassification.CONTENT_MODIFICATION.value


def test_comparison_size_change_append():
    """Verify data appended to the end on exact boundary triggers SIZE_CHANGE with 0 modified common chunks."""
    base = b"A" * 1000  # Exactly 2 chunks of 500 bytes
    appended = base + (b"B" * 500)  # Exactly 3rd chunk

    fp1 = FingerprintService.generate_fingerprint_from_stream(io.BytesIO(base), "log.txt", chunk_size=500)
    fp2 = FingerprintService.generate_fingerprint_from_stream(io.BytesIO(appended), "log.txt", chunk_size=500)

    result = ComparisonEngine.compare_fingerprints(fp1, fp2)
    assert result["sha256_changed"] is True
    assert result["size_changed"] is True
    assert result["chunks_changed"] == 0
    assert result["chunks_added"] == 1
    assert result["assessment"]["classification"] == ChangeClassification.SIZE_CHANGE.value


def test_comparison_size_change_partial_append():
    """Verify data appended to a trailing partial chunk still diagnoses as SIZE_CHANGE."""
    # Chunk 0: 500 bytes of 'A' (intact), Chunk 1: 200 bytes of 'B' (trailing partial)
    base = (b"A" * 500) + (b"B" * 200)
    appended = base + b" extra appended trailing data."

    fp1 = FingerprintService.generate_fingerprint_from_stream(io.BytesIO(base), "log.txt", chunk_size=500)
    fp2 = FingerprintService.generate_fingerprint_from_stream(io.BytesIO(appended), "log.txt", chunk_size=500)

    result = ComparisonEngine.compare_fingerprints(fp1, fp2)
    assert result["sha256_changed"] is True
    assert result["size_changed"] is True
    assert result["assessment"]["classification"] == ChangeClassification.SIZE_CHANGE.value


def test_comparison_major_replacement():
    """Verify completely divergent files trigger MAJOR_REPLACEMENT."""
    data1 = b"Original database dump records." * 50
    data2 = b"Completely unrelated image payload byte array." * 50

    fp1 = FingerprintService.generate_fingerprint_from_stream(io.BytesIO(data1), "file1.bin", chunk_size=500)
    fp2 = FingerprintService.generate_fingerprint_from_stream(io.BytesIO(data2), "file2.bin", chunk_size=500)

    result = ComparisonEngine.compare_fingerprints(fp1, fp2)
    assert result["sha256_changed"] is True
    assert result["chunks_matching"] == 0
    assert result["change_percentage"] == 100.0
    assert result["assessment"]["classification"] == ChangeClassification.MAJOR_REPLACEMENT.value
