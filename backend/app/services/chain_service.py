"""
HashLens Tamper-Evident Hash Chain Service
Maintains a mathematically linked audit log: H_n = SHA256(canonical(record_n) + H_{n-1}).
Provides cryptographically robust integrity verification and pinpoint fault localization.
"""

import hashlib
import hmac
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session
from backend.app.models.models import ChainRecordModel


GENESIS_PREVIOUS_HASH = "0" * 64


class HashChainService:
    """Implements cryptographic tamper-evident history chaining and verification."""

    @staticmethod
    def compute_record_hash(
        sequence_num: int,
        record_id: str,
        timestamp: str,
        event_type: str,
        file_id: Optional[str],
        file_hash: str,
        payload: Dict[str, Any],
        previous_hash: str,
    ) -> str:
        """
        Computes deterministic SHA-256 digest of canonical record payload concatenated
        with the previous record's hash digest.
        """
        canonical_content = {
            "sequence_num": sequence_num,
            "record_id": record_id,
            "timestamp": timestamp,
            "event_type": event_type,
            "file_id": file_id or "",
            "file_hash": file_hash,
            "payload": payload,
        }
        canonical_json = json.dumps(canonical_content, sort_keys=True)
        combined_payload = canonical_json.encode("utf-8") + previous_hash.encode("utf-8")
        return hashlib.sha256(combined_payload).hexdigest()

    @classmethod
    def append_event(
        cls,
        db: Session,
        event_type: str,
        file_hash: str,
        file_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ChainRecordModel:
        """
        Appends an event to the tamper-evident hash chain.
        Ensures cryptographic continuity from the head of the chain.
        """
        last_record = (
            db.query(ChainRecordModel)
            .order_by(ChainRecordModel.sequence_num.desc())
            .first()
        )

        if last_record is None:
            sequence_num = 1
            previous_hash = GENESIS_PREVIOUS_HASH
        else:
            sequence_num = last_record.sequence_num + 1
            previous_hash = last_record.current_record_hash

        record_id = uuid.uuid4().hex
        timestamp = datetime.now(timezone.utc).isoformat()
        payload = metadata or {}

        current_hash = cls.compute_record_hash(
            sequence_num=sequence_num,
            record_id=record_id,
            timestamp=timestamp,
            event_type=event_type,
            file_id=file_id,
            file_hash=file_hash,
            payload=payload,
            previous_hash=previous_hash,
        )

        record = ChainRecordModel(
            record_id=record_id,
            sequence_num=sequence_num,
            timestamp=timestamp,
            event_type=event_type,
            file_id=file_id,
            file_hash=file_hash,
            previous_record_hash=previous_hash,
            current_record_hash=current_hash,
            payload_json=json.dumps(payload),
        )

        db.add(record)
        db.commit()
        db.refresh(record)
        return record

    @classmethod
    def verify_chain(cls, db: Session) -> Dict[str, Any]:
        """
        Audits every record in the tamper-evident chain.
        Detects any:
          - Modified payload
          - Tampered or broken current_record_hash
          - Broken previous_record_hash pointer
          - Sequence deletion or insertion
        Returns CHAIN_VALID or CHAIN_BROKEN with pinpoint diagnosis.
        """
        records: List[ChainRecordModel] = (
            db.query(ChainRecordModel)
            .order_by(ChainRecordModel.sequence_num.asc())
            .all()
        )

        if not records:
            return {
                "status": "CHAIN_EMPTY",
                "valid": True,
                "total_records": 0,
                "verified_records": 0,
                "head_hash": GENESIS_PREVIOUS_HASH,
                "message": "Chain is empty. No integrity records registered yet.",
            }

        expected_previous_hash = GENESIS_PREVIOUS_HASH
        expected_sequence = 1

        for idx, record in enumerate(records):
            # 1. Verify sequence continuity
            if record.sequence_num != expected_sequence:
                return {
                    "status": "CHAIN_BROKEN",
                    "valid": False,
                    "failure_type": "SEQUENCE_GAP_OR_DELETION",
                    "broken_record_id": record.record_id,
                    "sequence_num": record.sequence_num,
                    "expected_sequence": expected_sequence,
                    "reason": (
                        f"Sequence gap detected at record {record.record_id}. "
                        f"Expected sequence {expected_sequence}, found {record.sequence_num}. "
                        "A record may have been deleted or inserted out of order."
                    ),
                    "total_records": len(records),
                    "verified_records": idx,
                }

            # 2. Verify previous-hash reference
            if not hmac.compare_digest(record.previous_record_hash, expected_previous_hash):
                return {
                    "status": "CHAIN_BROKEN",
                    "valid": False,
                    "failure_type": "BROKEN_LINK_REFERENCE",
                    "broken_record_id": record.record_id,
                    "sequence_num": record.sequence_num,
                    "reason": (
                        f"Cryptographic link broken at record {record.record_id} (seq {record.sequence_num}). "
                        f"Previous hash reference '{record.previous_record_hash}' does not match "
                        f"expected digest '{expected_previous_hash}'."
                    ),
                    "total_records": len(records),
                    "verified_records": idx,
                }

            # 3. Recompute and verify current record hash
            try:
                payload = json.loads(record.payload_json)
            except Exception:
                payload = {}

            recalculated_hash = cls.compute_record_hash(
                sequence_num=record.sequence_num,
                record_id=record.record_id,
                timestamp=record.timestamp,
                event_type=record.event_type,
                file_id=record.file_id,
                file_hash=record.file_hash,
                payload=payload,
                previous_hash=record.previous_record_hash,
            )

            if not hmac.compare_digest(record.current_record_hash, recalculated_hash):
                return {
                    "status": "CHAIN_BROKEN",
                    "valid": False,
                    "failure_type": "PAYLOAD_TAMPERED",
                    "broken_record_id": record.record_id,
                    "sequence_num": record.sequence_num,
                    "reason": (
                        f"Content tampering detected in record {record.record_id} (seq {record.sequence_num}). "
                        f"Stored digest '{record.current_record_hash}' differs from "
                        f"recalculated canonical hash '{recalculated_hash}'."
                    ),
                    "total_records": len(records),
                    "verified_records": idx,
                }

            expected_previous_hash = record.current_record_hash
            expected_sequence += 1

        return {
            "status": "CHAIN_VALID",
            "valid": True,
            "total_records": len(records),
            "verified_records": len(records),
            "head_hash": records[-1].current_record_hash,
            "genesis_hash": records[0].previous_record_hash,
            "message": f"Tamper-Evident Hash Chain verified intact across all {len(records)} audit records.",
        }

    @classmethod
    def get_records(cls, db: Session, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieves recent chain records for dashboard and API display."""
        records = (
            db.query(ChainRecordModel)
            .order_by(ChainRecordModel.sequence_num.desc())
            .limit(limit)
            .all()
        )
        output = []
        for r in records:
            output.append({
                "id": r.id,
                "record_id": r.record_id,
                "sequence_num": r.sequence_num,
                "timestamp": r.timestamp,
                "event_type": r.event_type,
                "file_id": r.file_id,
                "file_hash": r.file_hash,
                "previous_record_hash": r.previous_record_hash,
                "current_record_hash": r.current_record_hash,
            })
        return output
