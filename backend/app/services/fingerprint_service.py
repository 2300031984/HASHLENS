"""
HashLens Forensic Fingerprint Service
Performs streaming file analysis, calculating multi-algorithm digests,
chunk-level SHA-256 block maps, and metadata fingerprints in a single streaming pass.
"""

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, BinaryIO, Dict, List, Optional

from backend.app.services.file_service import SafeFileService
from backend.app.services.hashing_engine import HashingEngine, HashAlgorithm


class FingerprintService:
    """Computes comprehensive forensic fingerprints with chunk-level granularity."""

    @classmethod
    def generate_fingerprint_from_stream(
        cls,
        stream: BinaryIO,
        raw_filename: str,
        chunk_size: int = 1048576,  # 1 MiB default
        max_size: int = 104857600,   # 100 MiB default
    ) -> Dict[str, Any]:
        """
        Process stream in sequential chunks, computing whole-file digests and chunk fingerprints
        in a single memory-efficient pass.
        """
        if chunk_size <= 0:
            raise ValueError(f"chunk_size must be positive, got {chunk_size}")

        clean_filename = SafeFileService.sanitize_filename(raw_filename)

        # Whole-file hashers (legacy hashes marked non-security for forensic checksums)
        md5_hasher = hashlib.md5(usedforsecurity=False)
        sha1_hasher = hashlib.sha1(usedforsecurity=False)
        sha256_hasher = hashlib.sha256()
        sha512_hasher = hashlib.sha512()

        chunk_fingerprints: List[Dict[str, Any]] = []
        total_bytes = 0
        chunk_index = 0
        header_sample = b""

        while True:
            chunk = stream.read(chunk_size)
            if not chunk:
                break

            chunk_len = len(chunk)
            total_bytes += chunk_len

            if total_bytes > max_size:
                raise ValueError(
                    f"Uploaded content exceeds maximum permitted size of {max_size} bytes ({max_size / (1024*1024):.1f} MB)."
                )

            # Capture header bytes for advisory type sniffing
            if chunk_index == 0:
                header_sample = chunk[:1024]

            # Update whole-file digests
            md5_hasher.update(chunk)
            sha1_hasher.update(chunk)
            sha256_hasher.update(chunk)
            sha512_hasher.update(chunk)

            # Chunk-level SHA-256
            chunk_hash = hashlib.sha256(chunk).hexdigest()
            chunk_fingerprints.append({
                "index": chunk_index,
                "offset": total_bytes - chunk_len,
                "length": chunk_len,
                "sha256": chunk_hash,
            })

            chunk_index += 1

        # Handle empty stream case (0 chunks, 0 bytes)
        if total_bytes == 0:
            file_type_info = SafeFileService.detect_file_type(b"", clean_filename)
        else:
            file_type_info = SafeFileService.detect_file_type(header_sample, clean_filename)

        hashes = {
            HashAlgorithm.MD5.value: md5_hasher.hexdigest(),
            HashAlgorithm.SHA1.value: sha1_hasher.hexdigest(),
            HashAlgorithm.SHA256.value: sha256_hasher.hexdigest(),
            HashAlgorithm.SHA512.value: sha512_hasher.hexdigest(),
        }

        timestamp = datetime.now(timezone.utc).isoformat()

        # Build canonical metadata for metadata fingerprinting
        metadata_payload = {
            "filename": clean_filename,
            "size_bytes": total_bytes,
            "mime_type": file_type_info["mime_type"],
            "extension": file_type_info["extension"],
            "sha256": hashes["sha256"],
            "chunk_count": len(chunk_fingerprints),
            "chunk_size": chunk_size,
        }
        canonical_meta_str = json.dumps(metadata_payload, sort_keys=True)
        metadata_fingerprint = hashlib.sha256(canonical_meta_str.encode("utf-8")).hexdigest()

        return {
            "filename": clean_filename,
            "original_filename": raw_filename,
            "size_bytes": total_bytes,
            "size_human": cls.format_bytes(total_bytes),
            "extension": file_type_info["extension"],
            "mime_type": file_type_info["mime_type"],
            "file_category": file_type_info["category"],
            "is_type_advisory": file_type_info["is_advisory"],
            "hashes": hashes,
            "chunk_size": chunk_size,
            "chunk_count": len(chunk_fingerprints),
            "chunk_fingerprints": chunk_fingerprints,
            "timestamp": timestamp,
            "metadata_fingerprint": metadata_fingerprint,
        }

    @classmethod
    def generate_fingerprint_from_file(
        cls,
        file_path: Path | str,
        chunk_size: int = 1048576,
        max_size: int = 104857600,
    ) -> Dict[str, Any]:
        """Compute forensic fingerprint for file on disk."""
        path = Path(file_path)
        if not path.is_file():
            raise FileNotFoundError(f"File not found: {file_path}")

        with open(path, "rb") as f:
            return cls.generate_fingerprint_from_stream(
                stream=f,
                raw_filename=path.name,
                chunk_size=chunk_size,
                max_size=max_size,
            )

    @staticmethod
    def format_bytes(num_bytes: int) -> str:
        """Formats byte count into human-readable representation."""
        for unit in ["B", "KiB", "MiB", "GiB", "TiB"]:
            if abs(num_bytes) < 1024.0:
                return f"{num_bytes:3.1f} {unit}" if unit != "B" else f"{num_bytes} B"
            num_bytes /= 1024.0
        return f"{num_bytes:.1f} PiB"
