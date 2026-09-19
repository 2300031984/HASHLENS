"""
Tests for HashLens Evidence Report Service.
Verifies report creation, self-verifying Evidence Report Hash generation,
database persistence, and HTML certificate rendering.
"""

import io
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.app.db.database import Base
from backend.app.services.fingerprint_service import FingerprintService
from backend.app.services.evidence_service import EvidenceService
from backend.app.services.chain_service import HashChainService


@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, future=True)
    session = Session()
    try:
        yield session
    finally:
        session.close()


def test_generate_evidence_report_and_hash(db_session):
    """Verify evidence report generation produces a valid 64-character SHA-256 evidence report hash."""
    data = b"Forensic evidence data payload for certification."
    fp = FingerprintService.generate_fingerprint_from_stream(io.BytesIO(data), "case_evidence.bin")

    report = EvidenceService.generate_report(
        db=db_session,
        fingerprint=fp,
        version_num=1,
        analyst_notes="Integrity test case.",
    )

    assert "report_id" in report
    assert report["report_id"].startswith("HL-EV-")
    assert "evidence_report_hash" in report
    assert len(report["evidence_report_hash"]) == 64
    assert report["file_metadata"]["filename"] == "case_evidence.bin"
    assert report["cryptographic_hashes"]["sha256"] == fp["hashes"]["sha256"]

    # Verify retrieval from database
    retrieved = EvidenceService.get_report_by_id(db_session, report["report_id"])
    assert retrieved is not None
    assert retrieved["evidence_report_hash"] == report["evidence_report_hash"]

    # Verify HTML rendering contains key evidence
    html = EvidenceService.render_html_report(report)
    assert report["report_id"] in html
    assert report["evidence_report_hash"] in html
    assert "AUTHENTIC EVIDENCE" in html

    # Verify event was recorded in Tamper-Evident Hash Chain
    chain_audit = HashChainService.verify_chain(db_session)
    assert chain_audit["valid"] is True
    assert chain_audit["total_records"] == 1


def test_evidence_report_hash_determinism_and_mutation():
    """
    Verify Section 5 requirements:
    1. Same canonical report -> same digest
    2. Changed report field -> different digest
    3. Changed ordering handled consistently by canonicalization
    4. Independent rehashing / integrity verification
    """
    report_dict = {
        "report_id": "HL-EV-TEST-001",
        "file_metadata": {"filename": "audit.txt", "size_bytes": 1024},
        "cryptographic_hashes": {"sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
        "analyst_notes": "Deterministic test case.",
    }

    # 1. Determinism check
    h1 = EvidenceService.compute_report_hash(report_dict)
    h2 = EvidenceService.compute_report_hash(report_dict)
    assert h1 == h2

    # 2. Key ordering independence (canonicalization test)
    reordered_dict = {
        "analyst_notes": "Deterministic test case.",
        "cryptographic_hashes": {"sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
        "report_id": "HL-EV-TEST-001",
        "file_metadata": {"size_bytes": 1024, "filename": "audit.txt"},
    }
    h_reordered = EvidenceService.compute_report_hash(reordered_dict)
    assert h1 == h_reordered

    # 3. Field mutation alters hash
    mutated_dict = dict(report_dict)
    mutated_dict["analyst_notes"] = "TAMPERED NOTES"
    h_mutated = EvidenceService.compute_report_hash(mutated_dict)
    assert h1 != h_mutated

    # 4. Independent report verification helper
    valid_report = dict(report_dict)
    valid_report["evidence_report_hash"] = h1
    assert EvidenceService.verify_report_integrity(valid_report) is True

    tampered_report = dict(valid_report)
    tampered_report["analyst_notes"] = "MALICIOUS MUTATION"
    assert EvidenceService.verify_report_integrity(tampered_report) is False
