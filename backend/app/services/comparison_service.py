"""
HashLens Forensic Comparison & Diagnostic Engine
Provides chunk-level diffing, change percentage calculation,
and deterministic forensic assessment of 'Why Did My Hash Change?'.
"""

from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


class ChangeClassification(str, Enum):
    NO_CHANGE = "NO_CHANGE"
    CONTENT_MODIFICATION = "CONTENT_MODIFICATION"
    SIZE_CHANGE = "SIZE_CHANGE"
    STRUCTURAL_CHANGE = "STRUCTURAL_CHANGE"
    METADATA_CHANGE = "METADATA_CHANGE"
    FILE_TYPE_CHANGE = "FILE_TYPE_CHANGE"
    MAJOR_REPLACEMENT = "MAJOR_REPLACEMENT"
    INCONCLUSIVE = "INCONCLUSIVE"


class ComparisonEngine:
    """Compares forensic fingerprints and diagnoses root causes of cryptographic hash divergence."""

    @classmethod
    def compare_fingerprints(
        cls,
        fp_a: Dict[str, Any],
        fp_b: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Performs deep forensic comparison between two file fingerprints.
        Returns a structured comparison report including chunk diffs and deterministic diagnosis.
        """
        # 1. Whole-file digest comparison
        sha256_a = fp_a["hashes"]["sha256"]
        sha256_b = fp_b["hashes"]["sha256"]
        sha256_changed = sha256_a != sha256_b

        sha512_a = fp_a["hashes"]["sha512"]
        sha512_b = fp_b["hashes"]["sha512"]
        sha512_changed = sha512_a != sha512_b

        md5_changed = fp_a["hashes"]["md5"] != fp_b["hashes"]["md5"]
        sha1_changed = fp_a["hashes"]["sha1"] != fp_b["hashes"]["sha1"]

        # 2. Size & type comparison
        size_a = fp_a["size_bytes"]
        size_b = fp_b["size_bytes"]
        size_delta = size_b - size_a
        size_changed = size_delta != 0

        mime_a = fp_a.get("mime_type", "application/octet-stream")
        mime_b = fp_b.get("mime_type", "application/octet-stream")
        type_changed = mime_a != mime_b

        # 3. Chunk-level analysis
        chunks_a: List[Dict[str, Any]] = fp_a.get("chunk_fingerprints", [])
        chunks_b: List[Dict[str, Any]] = fp_b.get("chunk_fingerprints", [])
        count_a = len(chunks_a)
        count_b = len(chunks_b)

        min_len = min(count_a, count_b)
        max_len = max(count_a, count_b)

        matching_indices: List[int] = []
        changed_indices: List[int] = []
        chunk_diff_details: List[Dict[str, Any]] = []

        for i in range(min_len):
            c_a = chunks_a[i]
            c_b = chunks_b[i]
            if c_a["sha256"] == c_b["sha256"]:
                matching_indices.append(i)
                chunk_diff_details.append({
                    "index": i,
                    "status": "UNCHANGED",
                    "offset_a": c_a["offset"],
                    "offset_b": c_b["offset"],
                    "sha256_a": c_a["sha256"],
                    "sha256_b": c_b["sha256"],
                })
            else:
                changed_indices.append(i)
                chunk_diff_details.append({
                    "index": i,
                    "status": "MODIFIED",
                    "offset_a": c_a["offset"],
                    "offset_b": c_b["offset"],
                    "sha256_a": c_a["sha256"],
                    "sha256_b": c_b["sha256"],
                })

        added_indices: List[int] = []
        removed_indices: List[int] = []

        if count_b > count_a:
            for i in range(count_a, count_b):
                added_indices.append(i)
                chunk_diff_details.append({
                    "index": i,
                    "status": "ADDED",
                    "offset_a": None,
                    "offset_b": chunks_b[i]["offset"],
                    "sha256_a": None,
                    "sha256_b": chunks_b[i]["sha256"],
                })
        elif count_a > count_b:
            for i in range(count_b, count_a):
                removed_indices.append(i)
                chunk_diff_details.append({
                    "index": i,
                    "status": "REMOVED",
                    "offset_a": chunks_a[i]["offset"],
                    "offset_b": None,
                    "sha256_a": chunks_a[i]["sha256"],
                    "sha256_b": None,
                })

        matching_count = len(matching_indices)
        changed_count = len(changed_indices)
        added_count = len(added_indices)
        removed_count = len(removed_indices)

        # Shift detection for structural changes (e.g. chunk was inserted/moved)
        set_hashes_a = {c["sha256"] for c in chunks_a}
        set_hashes_b = {c["sha256"] for c in chunks_b}
        shared_content_hashes = set_hashes_a.intersection(set_hashes_b)

        # Shift detected if chunks match hashes out-of-order
        is_shifted = False
        if not sha256_changed:
            is_shifted = False
        elif shared_content_hashes and len(shared_content_hashes) > matching_count:
            is_shifted = True

        # Compute change percentage
        if max_len == 0:
            change_percentage = 0.0
        else:
            diff_metric = changed_count + added_count + removed_count
            change_percentage = round((diff_metric / max_len) * 100, 2)
            if change_percentage > 100.0:
                change_percentage = 100.0

        meta_a = fp_a.get("metadata_fingerprint", "")
        meta_b = fp_b.get("metadata_fingerprint", "")
        name_a = fp_a.get("filename", "")
        name_b = fp_b.get("filename", "")

        # Deterministic 'Why Did My Hash Change?' rules assessment
        classification, explanation, evidence = cls._diagnose_change(
            sha256_changed=sha256_changed,
            size_delta=size_delta,
            type_changed=type_changed,
            mime_a=mime_a,
            mime_b=mime_b,
            count_a=count_a,
            count_b=count_b,
            matching_count=matching_count,
            changed_count=changed_count,
            changed_indices=changed_indices,
            added_count=added_count,
            removed_count=removed_count,
            is_shifted=is_shifted,
            fp_a_name=name_a,
            fp_b_name=name_b,
            meta_a=meta_a,
            meta_b=meta_b,
        )

        overall_status = "identical" if not sha256_changed else "modified"
        if not sha256_changed and meta_a != meta_b:
            overall_status = "metadata_modified"

        return {
            "overall_status": overall_status,
            "sha256_changed": sha256_changed,
            "sha512_changed": sha512_changed,
            "md5_changed": md5_changed,
            "sha1_changed": sha1_changed,
            "size_changed": size_changed,
            "size_delta_bytes": size_delta,
            "size_delta_human": cls._format_delta(size_delta),
            "file_type_changed": type_changed,
            "type_a": mime_a,
            "type_b": mime_b,
            "total_chunks_a": count_a,
            "total_chunks_b": count_b,
            "chunks_matching": matching_count,
            "chunks_changed": changed_count,
            "chunks_added": added_count,
            "chunks_removed": removed_count,
            "change_percentage": change_percentage,
            "chunk_diffs": chunk_diff_details,
            "assessment": {
                "classification": classification.value,
                "summary": explanation,
                "evidence_points": evidence,
            },
        }

    @classmethod
    def _diagnose_change(
        cls,
        sha256_changed: bool,
        size_delta: int,
        type_changed: bool,
        mime_a: str,
        mime_b: str,
        count_a: int,
        count_b: int,
        matching_count: int,
        changed_count: int,
        changed_indices: List[int],
        added_count: int,
        removed_count: int,
        is_shifted: bool,
        fp_a_name: str,
        fp_b_name: str,
        meta_a: str,
        meta_b: str,
    ) -> Tuple[ChangeClassification, str, List[str]]:
        """Applies deterministic rules to classify the root cause of hash changes."""
        evidence: List[str] = []

        # Case 1: No cryptographic change in content
        if not sha256_changed:
            if meta_a != meta_b or fp_a_name != fp_b_name:
                evidence.append(f"Content SHA-256 digests are completely identical.")
                evidence.append(f"Container metadata differs (Filename or Timestamp).")
                return (
                    ChangeClassification.METADATA_CHANGE,
                    "File content is bitwise identical. Only file metadata or naming changed.",
                    evidence,
                )
            evidence.append("All cryptographic digests (MD5, SHA-1, SHA-256, SHA-512) match.")
            evidence.append("File sizes and chunk hashes are 100% identical.")
            return (
                ChangeClassification.NO_CHANGE,
                "No integrity change detected. Both files are bitwise identical.",
                evidence,
            )

        # Record evidence for changed files
        evidence.append("Cryptographic SHA-256 digest changed.")
        if size_delta != 0:
            evidence.append(f"File size changed by {cls._format_delta(size_delta)}.")
        else:
            evidence.append("File size remained exactly unchanged.")

        if type_changed:
            evidence.append(f"Advisory file type shifted from '{mime_a}' to '{mime_b}'.")

        evidence.append(
            f"Chunk comparison: {matching_count} unchanged, {changed_count} modified, "
            f"{added_count} added, {removed_count} removed."
        )

        # Case 2: File type changed with no chunk overlap
        if type_changed and matching_count == 0:
            return (
                ChangeClassification.FILE_TYPE_CHANGE,
                f"File format and header signature changed from {mime_a} to {mime_b} with zero chunk overlap.",
                evidence,
            )

        # Case 3: Complete replacement
        if matching_count == 0 and not is_shifted:
            return (
                ChangeClassification.MAJOR_REPLACEMENT,
                "0% chunk alignment detected. The file appears to have been entirely overwritten or replaced.",
                evidence,
            )

        # Case 4: Shift / structural insertion
        if is_shifted:
            evidence.append("Identical chunk hashes detected at displaced offsets.")
            return (
                ChangeClassification.STRUCTURAL_CHANGE,
                "Structural block displacement detected: chunks exist in both files but at shifted offsets (insertion/deletion).",
                evidence,
            )

        # Case 5: Append / Truncate
        # (a) Exact boundary append or truncate (0 changed base chunks, added or removed chunks)
        if changed_count == 0 and (added_count > 0 or removed_count > 0):
            action = "appended to" if added_count > 0 else "truncated from"
            evidence.append(f"All {matching_count} base chunks are identical; data was {action} the end of the file.")
            return (
                ChangeClassification.SIZE_CHANGE,
                f"Prefix data is untouched; content was {action} the end of the file.",
                evidence,
            )

        # (b) Partial last chunk extension append
        if count_a > 0 and changed_count == 1 and changed_indices == [count_a - 1] and size_delta > 0:
            evidence.append(f"All {matching_count} preceding chunks are identical; data was appended to the end of the file.")
            return (
                ChangeClassification.SIZE_CHANGE,
                "Prefix data is untouched; content was appended to the trailing chunk at the end of the file.",
                evidence,
            )

        # Case 6: Localized content modification
        if matching_count > 0 and changed_count > 0:
            return (
                ChangeClassification.CONTENT_MODIFICATION,
                f"Targeted content modification: {changed_count} chunk(s) modified while {matching_count} chunk(s) remained intact.",
                evidence,
            )

        # Fallback: Inconclusive
        return (
            ChangeClassification.INCONCLUSIVE,
            "Forensic evidence indicates divergence, but the exact mutation pattern cannot be categorized with confidence.",
            evidence,
        )

    @staticmethod
    def _format_delta(delta: int) -> str:
        """Formats byte delta with explicit positive or negative sign."""
        sign = "+" if delta > 0 else ""
        for unit in ["B", "KiB", "MiB", "GiB"]:
            if abs(delta) < 1024.0:
                return f"{sign}{delta:3.1f} {unit}" if unit != "B" else f"{sign}{delta} B"
            delta /= 1024.0
        return f"{sign}{delta:.1f} PiB"
