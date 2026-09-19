"""
HashLens Safe File Service
Handles secure temporary file processing, filename sanitization,
directory traversal defense, and advisory MIME/magic signature identification.
"""

import os
import re
import mimetypes
from pathlib import Path
from typing import BinaryIO, Dict, Optional, Tuple


# Known magic byte signatures for advisory forensic identification
# Format: (bytes_prefix, offset, mime_type, human_category)
MAGIC_SIGNATURES = [
    (b"%PDF-", 0, "application/pdf", "PDF Document"),
    (b"PK\x03\x04", 0, "application/zip", "ZIP Archive / Office Open XML"),
    (b"\x89PNG\r\n\x1a\n", 0, "image/png", "PNG Image"),
    (b"\xff\xd8\xff", 0, "image/jpeg", "JPEG Image"),
    (b"GIF87a", 0, "image/gif", "GIF Image"),
    (b"GIF89a", 0, "image/gif", "GIF Image"),
    (b"\x7fELF", 0, "application/x-executable", "ELF Unix Executable/Binary"),
    (b"MZ", 0, "application/x-dosexec", "PE / Windows Executable"),
    (b"\x1f\x8b\x08", 0, "application/gzip", "GZIP Compressed Archive"),
    (b"7z\xbc\xaf\x27\x1c", 0, "application/x-7z-compressed", "7-Zip Archive"),
    (b"ustar", 257, "application/x-tar", "TAR Archive"),
]


class SafeFileService:
    """Provides secure file validation, sanitization, and signature sniffing."""

    @staticmethod
    def sanitize_filename(raw_name: str) -> str:
        """
        Strips dangerous path traversals (../, ..\\), null bytes, and control characters.
        Returns a clean base filename.
        """
        if not raw_name:
            return "unnamed_file"

        # Remove null bytes
        cleaned = raw_name.replace("\x00", "")

        # Extract only the base name (prevents ../ and absolute paths)
        cleaned = os.path.basename(cleaned)
        cleaned = Path(cleaned).name

        # Strip illegal characters across Windows and Unix
        cleaned = re.sub(r'[\/\\:\*\?"<>\|\x00-\x1f]', "_", cleaned)
        cleaned = cleaned.strip(". ")

        return cleaned if cleaned else "unnamed_file"

    @staticmethod
    def detect_file_type(header_bytes: bytes, filename: str) -> Dict[str, str]:
        """
        Advisory detection of file type using magic byte signatures and filename extension.
        Treats detection strictly as advisory, never trusting client-supplied headers.
        """
        detected_mime = "application/octet-stream"
        detected_category = "Binary / Unknown"

        # 1. Check known magic signatures
        for magic, offset, mime, category in MAGIC_SIGNATURES:
            if len(header_bytes) >= offset + len(magic):
                if header_bytes[offset : offset + len(magic)] == magic:
                    detected_mime = mime
                    detected_category = category
                    break

        # 2. Check if text-based
        if detected_mime == "application/octet-stream" and header_bytes:
            try:
                header_bytes.decode("utf-8")
                detected_mime = "text/plain"
                detected_category = "Text Document (UTF-8)"
                # Sub-check for JSON
                stripped = header_bytes.strip()
                if (stripped.startswith(b"{") and stripped.endswith(b"}")) or (
                    stripped.startswith(b"[") and stripped.endswith(b"]")
                ):
                    detected_mime = "application/json"
                    detected_category = "JSON Document"
            except UnicodeDecodeError:
                pass

        # 3. Fallback to extension hint if magic is generic
        ext = Path(filename).suffix.lower()
        guessed_type, _ = mimetypes.guess_type(filename)
        if guessed_type and detected_mime == "application/octet-stream":
            detected_mime = guessed_type
            detected_category = f"File ({ext.upper() if ext else 'Unknown'})"

        return {
            "mime_type": detected_mime,
            "category": detected_category,
            "extension": ext if ext else "none",
            "is_advisory": True,
        }

    @staticmethod
    def validate_file_path_safety(base_dir: Path, target_path: Path) -> bool:
        """
        Verifies that target_path resolves strictly within base_dir (prevents symlink/path traversal escapes).
        """
        try:
            resolved_base = base_dir.resolve()
            resolved_target = target_path.resolve()
            return resolved_target == resolved_base or resolved_base in resolved_target.parents
        except Exception:
            return False
