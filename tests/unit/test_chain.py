"""
Tests for HashLens Tamper-Evident Hash Chain & Version History.
Verifies cryptographic linking, chain audit verification, tampering detection,
and sequence gap detection.
"""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from backend.app.db.database import Base
from backend.app.models.models import ChainRecordModel
from backend.app.services.chain_service import HashChainService, GENESIS_PREVIOUS_HASH
from backend.app.services.history_service import HistoryService
from backend.app.services.fingerprint_service import FingerprintService
import io


@pytest.fixture
def in_memory_db():
    """Provides a clean in-memory SQLite session for isolated chain testing."""
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, future=True)
    session = Session()
    try:
        yield session
    finally:
        session.close()


def test_empty_chain_verification(in_memory_db):
    """Verify empty chain is reported as CHAIN_EMPTY and valid."""
    result = HashChainService.verify_chain(in_memory_db)
    assert result["status"] == "CHAIN_EMPTY"
    assert result["valid"] is True
    assert result["total_records"] == 0


def test_chain_sequential_linking_and_validation(in_memory_db):
    """Verify multiple records link sequentially and verify cleanly."""
    r1 = HashChainService.append_event(
        db=in_memory_db,
        event_type="FILE_REGISTERED",
        file_hash="aaa" * 21 + "a",
        metadata={"filename": "doc1.txt"},
    )
    assert r1.sequence_num == 1
    assert r1.previous_record_hash == GENESIS_PREVIOUS_HASH
    assert len(r1.current_record_hash) == 64

    r2 = HashChainService.append_event(
        db=in_memory_db,
        event_type="VERSION_MODIFIED",
        file_hash="bbb" * 21 + "b",
        metadata={"filename": "doc1.txt", "version": 2},
    )
    assert r2.sequence_num == 2
    assert r2.previous_record_hash == r1.current_record_hash

    r3 = HashChainService.append_event(
        db=in_memory_db,
        event_type="INTEGRITY_CHECK",
        file_hash="bbb" * 21 + "b",
    )
    assert r3.sequence_num == 3
    assert r3.previous_record_hash == r2.current_record_hash

    # Verify chain
    audit = HashChainService.verify_chain(in_memory_db)
    assert audit["status"] == "CHAIN_VALID"
    assert audit["valid"] is True
    assert audit["total_records"] == 3
    assert audit["verified_records"] == 3
    assert audit["head_hash"] == r3.current_record_hash


def test_tamper_detection_modified_payload(in_memory_db):
    """Verify that altering a record's payload triggers CHAIN_BROKEN detection."""
    HashChainService.append_event(in_memory_db, "EVENT_1", "111" * 21 + "1")
    r2 = HashChainService.append_event(in_memory_db, "EVENT_2", "222" * 21 + "2")
    HashChainService.append_event(in_memory_db, "EVENT_3", "333" * 21 + "3")

    # Manually tamper with r2's stored payload in the database
    record_to_tamper = (
        in_memory_db.query(ChainRecordModel)
        .filter(ChainRecordModel.record_id == r2.record_id)
        .first()
    )
    record_to_tamper.payload_json = '{"tampered": true}'
    in_memory_db.commit()

    # Audit must detect tampering
    audit = HashChainService.verify_chain(in_memory_db)
    assert audit["status"] == "CHAIN_BROKEN"
    assert audit["valid"] is False
    assert audit["broken_record_id"] == r2.record_id
    assert audit["sequence_num"] == 2
    assert "Content tampering detected" in audit["reason"]


def test_tamper_detection_deleted_record(in_memory_db):
    """Verify that deleting an intermediate record triggers sequence gap detection."""
    HashChainService.append_event(in_memory_db, "EVENT_1", "111" * 21 + "1")
    r2 = HashChainService.append_event(in_memory_db, "EVENT_2", "222" * 21 + "2")
    HashChainService.append_event(in_memory_db, "EVENT_3", "333" * 21 + "3")

    # Delete record 2
    in_memory_db.query(ChainRecordModel).filter(ChainRecordModel.record_id == r2.record_id).delete()
    in_memory_db.commit()

    # Audit must detect gap
    audit = HashChainService.verify_chain(in_memory_db)
    assert audit["status"] == "CHAIN_BROKEN"
    assert audit["valid"] is False
    assert "Sequence gap detected" in audit["reason"]


def test_version_history_progression(in_memory_db):
    """Verify registering a file, adding an identical version, and adding a modified version."""
    content_v1 = b"Version 1 document content."
    fp1 = FingerprintService.generate_fingerprint_from_stream(io.BytesIO(content_v1), "audit.pdf")

    res1 = HistoryService.register_or_update_file(in_memory_db, fp1)
    assert res1["version"] == 1
    assert res1["integrity_status"] == "ORIGINAL"

    # Add same content -> UNCHANGED
    res2 = HistoryService.register_or_update_file(in_memory_db, fp1)
    assert res2["version"] == 2
    assert res2["integrity_status"] == "UNCHANGED"

    # Add modified content -> MODIFIED
    content_v3 = b"Version 3 modified document content."
    fp3 = FingerprintService.generate_fingerprint_from_stream(io.BytesIO(content_v3), "audit.pdf")
    res3 = HistoryService.register_or_update_file(in_memory_db, fp3)
    assert res3["version"] == 3
    assert res3["integrity_status"] == "MODIFIED"

    # Verify timeline
    timeline = HistoryService.get_file_timeline(in_memory_db, res1["file_id"])
    assert timeline["total_versions"] == 3
    assert len(timeline["timeline"]) == 3
    assert timeline["timeline"][0]["integrity_status"] == "ORIGINAL"
    assert timeline["timeline"][1]["integrity_status"] == "UNCHANGED"
    assert timeline["timeline"][2]["integrity_status"] == "MODIFIED"

    # Verify chain records were recorded for all 3
    chain_audit = HashChainService.verify_chain(in_memory_db)
    assert chain_audit["status"] == "CHAIN_VALID"
    assert chain_audit["total_records"] == 3
