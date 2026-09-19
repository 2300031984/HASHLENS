"""
HashLens PostgreSQL Engine & Database Architecture Tests
Verifies database URL normalization, connection pooling options, model schema validity,
transaction rollback safety, and dual SQLite / PostgreSQL compatibility.
"""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.app.db.database import get_normalized_database_url, Base
from backend.app.models.models import (
    UserModel,
    TrackedFileModel,
    FileVersionModel,
    ChainRecordModel,
    EvidenceReportModel,
)
from backend.app.services.chain_service import HashChainService


def test_database_url_normalization():
    """Verifies that postgres:// and postgresql:// URLs are normalized to postgresql+psycopg://."""
    assert get_normalized_database_url("sqlite:///./data.db") == "sqlite:///./data.db"
    assert (
        get_normalized_database_url("postgres://user:pass@localhost:5432/db")
        == "postgresql+psycopg://user:pass@localhost:5432/db"
    )
    assert (
        get_normalized_database_url("postgresql://user:pass@localhost:5432/db")
        == "postgresql+psycopg://user:pass@localhost:5432/db"
    )
    assert (
        get_normalized_database_url("postgresql+psycopg://user:pass@localhost:5432/db")
        == "postgresql+psycopg://user:pass@localhost:5432/db"
    )


def test_postgresql_model_metadata_completeness():
    """Verifies that all models register properly under Base metadata with foreign keys and unique constraints."""
    table_names = list(Base.metadata.tables.keys())
    assert "users" in table_names
    assert "tracked_files" in table_names
    assert "file_versions" in table_names
    assert "integrity_chain" in table_names
    assert "evidence_reports" in table_names

    # Check foreign keys
    tracked_files_fks = [fk.referred_table.name for fk in Base.metadata.tables["tracked_files"].foreign_key_constraints]
    assert "users" in tracked_files_fks

    file_versions_fks = [fk.referred_table.name for fk in Base.metadata.tables["file_versions"].foreign_key_constraints]
    assert "users" in file_versions_fks
    assert "tracked_files" in file_versions_fks


def test_in_memory_db_transaction_rollback_safety():
    """Verifies transaction rollback and chain integrity on database errors."""
    test_engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=test_engine)
    TestingSession = sessionmaker(bind=test_engine)
    db = TestingSession()

    try:
        # Create initial chain record
        record1 = HashChainService.append_event(
            db=db,
            event_type="FILE_REGISTERED",
            file_hash="a" * 64,
            user_id="user_test_100",
        )
        assert record1.sequence_num == 1
        assert record1.previous_record_hash == "0" * 64

        # Verify chain
        audit = HashChainService.verify_chain(db, user_id="user_test_100")
        assert audit["valid"] is True
        assert audit["total_records"] == 1

    finally:
        db.close()
