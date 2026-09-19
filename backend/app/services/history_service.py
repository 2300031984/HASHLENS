"""
HashLens File Version History Service
Manages tracked file baselines, sequential versions, integrity statuses,
and automatically commits lifecycle events to the Tamper-Evident Hash Chain.
"""

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session

from backend.app.models.models import TrackedFileModel, FileVersionModel
from backend.app.services.chain_service import HashChainService
from backend.app.services.comparison_service import ComparisonEngine


class HistoryService:
    """Orchestrates file versioning, timeline tracking, and tamper-evident audit logs."""

    @classmethod
    def register_or_update_file(
        cls,
        db: Session,
        fingerprint: Dict[str, Any],
        custom_filename: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Registers a new file baseline (Version 1) or updates an existing tracked file with a new version.
        Compares with previous version if present, updates integrity status,
        and logs the event into the Tamper-Evident Hash Chain.
        """
        target_filename = custom_filename or fingerprint["filename"]

        # Check if file with same filename is already tracked
        tracked_file = (
            db.query(TrackedFileModel)
            .filter(TrackedFileModel.filename == target_filename)
            .first()
        )

        now_iso = datetime.now(timezone.utc).isoformat()

        if tracked_file is None:
            # 1. New tracked file registration (Version 1 - ORIGINAL)
            file_id = uuid.uuid4().hex
            tracked_file = TrackedFileModel(
                id=file_id,
                filename=target_filename,
                file_type=fingerprint.get("mime_type", "application/octet-stream"),
                created_at=now_iso,
                updated_at=now_iso,
            )
            db.add(tracked_file)
            db.flush()

            v1_id = uuid.uuid4().hex
            v1 = FileVersionModel(
                id=v1_id,
                file_id=file_id,
                version_num=1,
                timestamp=fingerprint.get("timestamp", now_iso),
                size_bytes=fingerprint["size_bytes"],
                size_human=fingerprint["size_human"],
                md5=fingerprint["hashes"]["md5"],
                sha1=fingerprint["hashes"]["sha1"],
                sha256=fingerprint["hashes"]["sha256"],
                sha512=fingerprint["hashes"]["sha512"],
                chunk_size=fingerprint["chunk_size"],
                chunk_count=fingerprint["chunk_count"],
                chunk_fingerprints_json=json.dumps(fingerprint["chunk_fingerprints"]),
                metadata_fingerprint=fingerprint["metadata_fingerprint"],
                integrity_status="ORIGINAL",
                change_summary="Initial baseline registered.",
            )
            db.add(v1)
            db.commit()

            # Record in Tamper-Evident Hash Chain
            HashChainService.append_event(
                db=db,
                event_type="FILE_REGISTERED",
                file_hash=fingerprint["hashes"]["sha256"],
                file_id=file_id,
                metadata={
                    "filename": target_filename,
                    "version": 1,
                    "size_bytes": fingerprint["size_bytes"],
                    "status": "ORIGINAL",
                },
            )

            return {
                "file_id": file_id,
                "filename": target_filename,
                "version": 1,
                "integrity_status": "ORIGINAL",
                "message": f"New file baseline registered as Version 1.",
                "sha256": fingerprint["hashes"]["sha256"],
                "version_id": v1_id,
            }

        else:
            # 2. Existing tracked file: fetch highest version
            latest_version = (
                db.query(FileVersionModel)
                .filter(FileVersionModel.file_id == tracked_file.id)
                .order_by(FileVersionModel.version_num.desc())
                .first()
            )

            new_version_num = (latest_version.version_num + 1) if latest_version else 1

            # Check if identical to latest version
            if latest_version and latest_version.sha256 == fingerprint["hashes"]["sha256"]:
                integrity_status = "UNCHANGED"
                change_summary = f"Identical to Version {latest_version.version_num} (SHA-256 match)."
            else:
                integrity_status = "MODIFIED"
                # If we have previous chunks, run comparison diagnosis
                if latest_version:
                    prev_fp = {
                        "filename": tracked_file.filename,
                        "size_bytes": latest_version.size_bytes,
                        "mime_type": tracked_file.file_type,
                        "hashes": {
                            "md5": latest_version.md5,
                            "sha1": latest_version.sha1,
                            "sha256": latest_version.sha256,
                            "sha512": latest_version.sha512,
                        },
                        "chunk_fingerprints": json.loads(latest_version.chunk_fingerprints_json),
                        "metadata_fingerprint": latest_version.metadata_fingerprint,
                    }
                    comp = ComparisonEngine.compare_fingerprints(prev_fp, fingerprint)
                    change_summary = comp["assessment"]["summary"]
                else:
                    change_summary = "Modified content registered."

            v_id = uuid.uuid4().hex
            new_v = FileVersionModel(
                id=v_id,
                file_id=tracked_file.id,
                version_num=new_version_num,
                timestamp=fingerprint.get("timestamp", now_iso),
                size_bytes=fingerprint["size_bytes"],
                size_human=fingerprint["size_human"],
                md5=fingerprint["hashes"]["md5"],
                sha1=fingerprint["hashes"]["sha1"],
                sha256=fingerprint["hashes"]["sha256"],
                sha512=fingerprint["hashes"]["sha512"],
                chunk_size=fingerprint["chunk_size"],
                chunk_count=fingerprint["chunk_count"],
                chunk_fingerprints_json=json.dumps(fingerprint["chunk_fingerprints"]),
                metadata_fingerprint=fingerprint["metadata_fingerprint"],
                integrity_status=integrity_status,
                change_summary=change_summary,
            )

            tracked_file.updated_at = now_iso
            db.add(new_v)
            db.commit()

            # Append to Tamper-Evident Hash Chain
            event_type = "VERSION_UNCHANGED" if integrity_status == "UNCHANGED" else "VERSION_MODIFIED"
            HashChainService.append_event(
                db=db,
                event_type=event_type,
                file_hash=fingerprint["hashes"]["sha256"],
                file_id=tracked_file.id,
                metadata={
                    "filename": target_filename,
                    "version": new_version_num,
                    "size_bytes": fingerprint["size_bytes"],
                    "status": integrity_status,
                },
            )

            return {
                "file_id": tracked_file.id,
                "filename": target_filename,
                "version": new_version_num,
                "integrity_status": integrity_status,
                "change_summary": change_summary,
                "message": f"Version {new_version_num} recorded with status '{integrity_status}'.",
                "sha256": fingerprint["hashes"]["sha256"],
                "version_id": v_id,
            }

    @classmethod
    def get_file_timeline(cls, db: Session, file_id: str) -> Dict[str, Any]:
        """Retrieves full version progression timeline for a tracked file."""
        tracked_file = db.query(TrackedFileModel).filter(TrackedFileModel.id == file_id).first()
        if not tracked_file:
            raise ValueError(f"Tracked file not found: {file_id}")

        versions = (
            db.query(FileVersionModel)
            .filter(FileVersionModel.file_id == file_id)
            .order_by(FileVersionModel.version_num.asc())
            .all()
        )

        timeline_nodes = []
        for v in versions:
            timeline_nodes.append({
                "version_id": v.id,
                "version_num": v.version_num,
                "timestamp": v.timestamp,
                "size_bytes": v.size_bytes,
                "size_human": v.size_human,
                "sha256": v.sha256,
                "md5": v.md5,
                "integrity_status": v.integrity_status,
                "change_summary": v.change_summary,
                "chunk_count": v.chunk_count,
            })

        return {
            "file_id": tracked_file.id,
            "filename": tracked_file.filename,
            "file_type": tracked_file.file_type,
            "created_at": tracked_file.created_at,
            "updated_at": tracked_file.updated_at,
            "total_versions": len(versions),
            "timeline": timeline_nodes,
        }

    @classmethod
    def list_tracked_files(cls, db: Session) -> List[Dict[str, Any]]:
        """Lists all tracked files with their latest version metadata."""
        files = db.query(TrackedFileModel).order_by(TrackedFileModel.updated_at.desc()).all()
        results = []
        for f in files:
            latest = (
                db.query(FileVersionModel)
                .filter(FileVersionModel.file_id == f.id)
                .order_by(FileVersionModel.version_num.desc())
                .first()
            )
            results.append({
                "file_id": f.id,
                "filename": f.filename,
                "file_type": f.file_type,
                "created_at": f.created_at,
                "updated_at": f.updated_at,
                "latest_version": latest.version_num if latest else 0,
                "latest_sha256": latest.sha256 if latest else None,
                "latest_status": latest.integrity_status if latest else "UNKNOWN",
            })
        return results
