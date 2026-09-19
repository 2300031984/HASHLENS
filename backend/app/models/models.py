"""
HashLens ORM Models
Declarative schemas for tracked assets, version logs, tamper-evident hash chain records,
and cryptographic evidence reports.
"""

from sqlalchemy import Column, Integer, String, Text, ForeignKey
from sqlalchemy.orm import relationship
from backend.app.db.database import Base


class TrackedFileModel(Base):
    __tablename__ = "tracked_files"

    id = Column(String(64), primary_key=True, index=True)
    filename = Column(String(255), nullable=False, index=True)
    file_type = Column(String(100), nullable=False)
    created_at = Column(String(50), nullable=False)
    updated_at = Column(String(50), nullable=False)

    versions = relationship(
        "FileVersionModel",
        back_populates="tracked_file",
        cascade="all, delete-orphan",
        order_by="FileVersionModel.version_num.asc()",
    )


class FileVersionModel(Base):
    __tablename__ = "file_versions"

    id = Column(String(64), primary_key=True, index=True)
    file_id = Column(String(64), ForeignKey("tracked_files.id", ondelete="CASCADE"), nullable=False, index=True)
    version_num = Column(Integer, nullable=False)
    timestamp = Column(String(50), nullable=False)
    size_bytes = Column(Integer, nullable=False)
    size_human = Column(String(50), nullable=False)
    md5 = Column(String(32), nullable=False)
    sha1 = Column(String(40), nullable=False)
    sha256 = Column(String(64), nullable=False, index=True)
    sha512 = Column(String(128), nullable=False)
    chunk_size = Column(Integer, nullable=False)
    chunk_count = Column(Integer, nullable=False)
    chunk_fingerprints_json = Column(Text, nullable=False)
    metadata_fingerprint = Column(String(64), nullable=False)
    integrity_status = Column(String(50), nullable=False)  # ORIGINAL, UNCHANGED, MODIFIED
    change_summary = Column(Text, nullable=True)

    tracked_file = relationship("TrackedFileModel", back_populates="versions")


class ChainRecordModel(Base):
    __tablename__ = "integrity_chain"

    id = Column(Integer, primary_key=True, autoincrement=True, index=True)
    record_id = Column(String(64), unique=True, nullable=False, index=True)
    sequence_num = Column(Integer, unique=True, nullable=False, index=True)
    timestamp = Column(String(50), nullable=False)
    event_type = Column(String(50), nullable=False, index=True)
    file_id = Column(String(64), nullable=True, index=True)
    file_hash = Column(String(64), nullable=False)
    previous_record_hash = Column(String(64), nullable=False)
    current_record_hash = Column(String(64), nullable=False)
    payload_json = Column(Text, nullable=False)


class EvidenceReportModel(Base):
    __tablename__ = "evidence_reports"

    id = Column(String(64), primary_key=True, index=True)
    report_id = Column(String(64), unique=True, nullable=False, index=True)
    generated_at = Column(String(50), nullable=False)
    file_id = Column(String(64), nullable=True, index=True)
    report_hash = Column(String(64), nullable=False, index=True)
    report_json = Column(Text, nullable=False)
