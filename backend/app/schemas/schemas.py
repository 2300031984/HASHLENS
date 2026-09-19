"""
HashLens Pydantic Schemas
Strict request and response schemas for REST API validation.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class TextHashRequest(BaseModel):
    text: str = Field(..., min_length=0, max_length=1_000_000, description="Raw text string to hash.")
    algorithms: Optional[List[str]] = Field(
        default=None,
        description="Optional subset of algorithms (md5, sha1, sha256, sha512). Defaults to all 4.",
    )


class TextHashResponse(BaseModel):
    input_length_chars: int
    input_length_bytes: int
    hashes: Dict[str, str]
    algorithms_used: List[str]


class AvalancheRequest(BaseModel):
    text1: str = Field(..., min_length=1, max_length=10_000)
    text2: str = Field(..., min_length=1, max_length=10_000)
    algorithm: str = Field(default="sha256")


class AvalancheResponse(BaseModel):
    algorithm: str
    digest1: str
    digest2: str
    total_bits: int
    flipped_bits: int
    identical_bits: int
    flip_percentage: float


class ChunkFingerprintSchema(BaseModel):
    index: int
    offset: int
    length: int
    sha256: str


class FileFingerprintResponse(BaseModel):
    filename: str
    original_filename: str
    size_bytes: int
    size_human: str
    extension: str
    mime_type: str
    file_category: str
    is_type_advisory: bool
    hashes: Dict[str, str]
    chunk_size: int
    chunk_count: int
    chunk_fingerprints: List[ChunkFingerprintSchema]
    timestamp: str
    metadata_fingerprint: str
    tracked_version_info: Optional[Dict[str, Any]] = None


class CompareRequest(BaseModel):
    # For comparing two tracked file versions by ID or raw fingerprints
    fingerprint_a: Dict[str, Any]
    fingerprint_b: Dict[str, Any]


class DiagnosticAssessmentSchema(BaseModel):
    classification: str
    summary: str
    evidence_points: List[str]


class CompareResponse(BaseModel):
    overall_status: str
    sha256_changed: bool
    sha512_changed: bool
    md5_changed: bool
    sha1_changed: bool
    size_changed: bool
    size_delta_bytes: int
    size_delta_human: str
    file_type_changed: bool
    type_a: str
    type_b: str
    total_chunks_a: int
    total_chunks_b: int
    chunks_matching: int
    chunks_changed: int
    chunks_added: int
    chunks_removed: int
    change_percentage: float
    chunk_diffs: List[Dict[str, Any]]
    assessment: DiagnosticAssessmentSchema


class TrackedFileSummary(BaseModel):
    file_id: str
    filename: str
    file_type: str
    created_at: str
    updated_at: str
    latest_version: int
    latest_sha256: Optional[str]
    latest_status: str


class TimelineNode(BaseModel):
    version_id: str
    version_num: int
    timestamp: str
    size_bytes: int
    size_human: str
    sha256: str
    md5: str
    integrity_status: str
    change_summary: Optional[str]
    chunk_count: int


class FileTimelineResponse(BaseModel):
    file_id: str
    filename: str
    file_type: str
    created_at: str
    updated_at: str
    total_versions: int
    timeline: List[TimelineNode]


class ChainRecordSchema(BaseModel):
    id: int
    record_id: str
    sequence_num: int
    timestamp: str
    event_type: str
    file_id: Optional[str]
    file_hash: str
    previous_record_hash: str
    current_record_hash: str


class ChainAuditResponse(BaseModel):
    status: str
    valid: bool
    total_records: int
    verified_records: int
    head_hash: Optional[str] = None
    genesis_hash: Optional[str] = None
    failure_type: Optional[str] = None
    broken_record_id: Optional[str] = None
    sequence_num: Optional[int] = None
    reason: Optional[str] = None
    message: Optional[str] = None


class EvidenceGenerateRequest(BaseModel):
    fingerprint: Dict[str, Any]
    comparison_result: Optional[Dict[str, Any]] = None
    version_num: Optional[int] = 1
    analyst_notes: Optional[str] = None


class HealthResponse(BaseModel):
    status: str
    app: str
    version: str
    environment: str
    uptime_seconds: float
    database: str
    chain_health: str
