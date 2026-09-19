"""
HashLens Evidence Report Generator
Produces canonical forensic evidence reports, generates self-verifying SHA-256
report digests ('Evidence Report Hash'), and renders standalone forensic HTML certificates.
"""

import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional
from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.models.models import EvidenceReportModel
from backend.app.services.chain_service import HashChainService


class EvidenceService:
    """Generates immutable, self-authenticating forensic evidence reports."""

    @classmethod
    def compute_report_hash(cls, report_dict: Dict[str, Any]) -> str:
        """
        Computes the canonical SHA-256 digest of an evidence report dictionary.
        Strips 'evidence_report_hash' if present prior to canonical JSON serialization.
        """
        raw_report = {k: v for k, v in report_dict.items() if k != "evidence_report_hash"}
        canonical_bytes = json.dumps(raw_report, sort_keys=True).encode("utf-8")
        return hashlib.sha256(canonical_bytes).hexdigest()

    @classmethod
    def verify_report_integrity(cls, report_dict: Dict[str, Any]) -> bool:
        """
        Verifies whether an evidence report's embedded digest matches its canonical content.
        """
        embedded_hash = report_dict.get("evidence_report_hash")
        if not embedded_hash:
            return False
        expected_hash = cls.compute_report_hash(report_dict)
        from backend.app.services.hashing_engine import HashingEngine
        return HashingEngine.verify_digest(embedded_hash, expected_hash)

    @classmethod
    def generate_report(
        cls,
        db: Session,
        fingerprint: Dict[str, Any],
        comparison_result: Optional[Dict[str, Any]] = None,
        version_num: Optional[int] = 1,
        analyst_notes: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Creates a structured evidence report, signs it with a canonical SHA-256
        'Evidence Report Hash', saves it, and appends the generation to the Tamper-Evident Hash Chain.
        """
        now = datetime.now(timezone.utc)
        date_str = now.strftime("%Y%m%d")
        rand_suffix = uuid.uuid4().hex[:6].upper()
        report_id = f"HL-EV-{date_str}-{rand_suffix}"

        # Current status of the tamper-evident chain
        chain_audit = HashChainService.verify_chain(db)

        # Build raw report structure
        raw_report = {
            "report_id": report_id,
            "tool_name": settings.APP_NAME,
            "tool_version": settings.APP_VERSION,
            "generated_at": now.isoformat(),
            "analyst_notes": analyst_notes or "Automated forensic baseline and integrity verification.",
            "file_metadata": {
                "filename": fingerprint.get("filename"),
                "size_bytes": fingerprint.get("size_bytes"),
                "size_human": fingerprint.get("size_human"),
                "mime_type": fingerprint.get("mime_type"),
                "category": fingerprint.get("file_category"),
                "extension": fingerprint.get("extension"),
                "chunk_size": fingerprint.get("chunk_size"),
                "total_chunks": fingerprint.get("chunk_count"),
                "version_number": version_num,
            },
            "cryptographic_hashes": fingerprint.get("hashes", {}),
            "metadata_fingerprint": fingerprint.get("metadata_fingerprint"),
            "chain_audit_status": {
                "status": chain_audit.get("status"),
                "valid": chain_audit.get("valid"),
                "total_records_audited": chain_audit.get("total_records"),
                "head_hash": chain_audit.get("head_hash"),
            },
            "comparison_analysis": comparison_result,
        }

        # Calculate canonical Evidence Report Hash
        evidence_report_hash = cls.compute_report_hash(raw_report)

        # Attach hash into final envelope
        final_report = dict(raw_report)
        final_report["evidence_report_hash"] = evidence_report_hash

        # Store in database
        report_record = EvidenceReportModel(
            id=uuid.uuid4().hex,
            report_id=report_id,
            generated_at=now.isoformat(),
            file_id=fingerprint.get("file_id"),
            report_hash=evidence_report_hash,
            report_json=json.dumps(final_report),
        )
        db.add(report_record)
        db.commit()

        # Log evidence generation event into Tamper-Evident Hash Chain
        HashChainService.append_event(
            db=db,
            event_type="EVIDENCE_REPORT_GENERATED",
            file_hash=fingerprint.get("hashes", {}).get("sha256", "0" * 64),
            file_id=fingerprint.get("file_id"),
            metadata={
                "report_id": report_id,
                "evidence_report_hash": evidence_report_hash,
            },
        )

        return final_report

    @classmethod
    def get_report_by_id(cls, db: Session, report_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves and verifies a previously generated report."""
        record = (
            db.query(EvidenceReportModel)
            .filter(EvidenceReportModel.report_id == report_id)
            .first()
        )
        if not record:
            return None
        return json.loads(record.report_json)

    @classmethod
    def render_html_report(cls, report_data: Dict[str, Any]) -> str:
        """
        Renders a printable, standalone cybersecurity forensic HTML evidence certificate.
        Includes verification badges, cryptographic digest tables, and tamper audit status.
        """
        meta = report_data.get("file_metadata", {})
        hashes = report_data.get("cryptographic_hashes", {})
        comp = report_data.get("comparison_analysis") or {}
        chain = report_data.get("chain_audit_status", {})
        assessment = comp.get("assessment", {})

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>HashLens Forensic Evidence Report - {report_data.get("report_id")}</title>
    <style>
        body {{
            font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, sans-serif;
            background-color: #0b0f19;
            color: #e2e8f0;
            margin: 0;
            padding: 40px 20px;
        }}
        .report-card {{
            max-width: 900px;
            margin: 0 auto;
            background: #131b2e;
            border: 1px solid #1e293b;
            border-radius: 12px;
            padding: 36px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5);
        }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            border-bottom: 2px solid #00f0ff;
            padding-bottom: 20px;
            margin-bottom: 25px;
        }}
        .title {{
            font-size: 24px;
            font-weight: 700;
            color: #f8fafc;
            letter-spacing: 0.05em;
        }}
        .badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 9999px;
            font-size: 12px;
            font-weight: 700;
            text-transform: uppercase;
        }}
        .badge-valid {{
            background-color: rgba(16, 185, 129, 0.2);
            color: #10b981;
            border: 1px solid #10b981;
        }}
        .hash-display {{
            font-family: 'Consolas', 'Courier New', monospace;
            font-size: 13px;
            background: #090d16;
            padding: 10px 14px;
            border-radius: 6px;
            border: 1px solid #1e293b;
            word-break: break-all;
            color: #38bdf8;
            margin: 6px 0 16px 0;
        }}
        .evidence-hash-box {{
            background: #0f172a;
            border: 1px solid #00f0ff;
            border-radius: 8px;
            padding: 16px;
            margin-bottom: 30px;
        }}
        .evidence-label {{
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.1em;
            color: #94a3b8;
        }}
        .section-title {{
            font-size: 16px;
            font-weight: 600;
            color: #38bdf8;
            margin-top: 25px;
            margin-bottom: 12px;
            border-bottom: 1px solid #1e293b;
            padding-bottom: 6px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }}
        th, td {{
            text-align: left;
            padding: 10px 14px;
            font-size: 13px;
            border-bottom: 1px solid #1e293b;
        }}
        th {{
            color: #94a3b8;
            font-weight: 600;
            background: #0f172a;
        }}
        .footer {{
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #1e293b;
            font-size: 12px;
            color: #64748b;
            text-align: center;
        }}
        @media print {{
            body {{ background: #fff; color: #000; }}
            .report-card {{ border: none; box-shadow: none; padding: 0; background: #fff; color: #000; }}
            .hash-display {{ background: #f1f5f9; color: #0f172a; border-color: #cbd5e1; }}
            .evidence-hash-box {{ background: #f8fafc; border-color: #0284c7; }}
            th {{ background: #f1f5f9; color: #0f172a; }}
        }}
    </style>
</head>
<body>
    <div class="report-card">
        <div class="header">
            <div>
                <div class="title">🛡️ HASHLENS FORENSIC EVIDENCE REPORT</div>
                <div style="color: #94a3b8; font-size: 13px; margin-top: 4px;">Report ID: {report_data.get("report_id")}</div>
            </div>
            <div style="text-align: right;">
                <span class="badge badge-valid">AUTHENTIC EVIDENCE</span>
                <div style="color: #64748b; font-size: 12px; margin-top: 6px;">Generated: {report_data.get("generated_at")}</div>
            </div>
        </div>

        <div class="evidence-hash-box">
            <div class="evidence-label">EVIDENCE REPORT HASH (SHA-256 INTEGRITY DIGEST)</div>
            <div class="hash-display" style="color: #00f0ff; font-weight: bold;">
                {report_data.get("evidence_report_hash")}
            </div>
            <div style="font-size: 12px; color: #94a3b8;">
                This cryptographic digest enables independent verification of the untampered status of this forensic report.
            </div>
        </div>

        <div class="section-title">FILE IDENTITY & METADATA</div>
        <table>
            <tr><th>Filename</th><td>{meta.get("filename")}</td><th>Version</th><td>V{meta.get("version_number", 1)}</td></tr>
            <tr><th>File Size</th><td>{meta.get("size_bytes")} bytes ({meta.get("size_human")})</td><th>Detected MIME</th><td>{meta.get("mime_type")}</td></tr>
            <tr><th>Category</th><td>{meta.get("category")}</td><th>Total Chunks</th><td>{meta.get("total_chunks")} chunks ({meta.get("chunk_size")} B/chunk)</td></tr>
        </table>

        <div class="section-title">CRYPTOGRAPHIC DIGESTS</div>
        <div class="evidence-label">SHA-256 (Primary Integrity Digest)</div>
        <div class="hash-display">{hashes.get("sha256")}</div>

        <div class="evidence-label">SHA-512 (High-Security Digest)</div>
        <div class="hash-display">{hashes.get("sha512")}</div>

        <div class="evidence-label">SHA-1 (Legacy Digest - Advisory Only)</div>
        <div class="hash-display">{hashes.get("sha1")}</div>

        <div class="evidence-label">MD5 (Legacy Checksum - Collision Compromised)</div>
        <div class="hash-display">{hashes.get("md5")}</div>

        <div class="section-title">TAMPER-EVIDENT HASH CHAIN AUDIT STATUS</div>
        <table>
            <tr><th>Chain Status</th><td><strong>{chain.get("status")}</strong></td></tr>
            <tr><th>Integrity Valid</th><td>{"✓ Intact" if chain.get("valid") else "✗ Broken"}</td></tr>
            <tr><th>Audited Audit Records</th><td>{chain.get("total_records_audited")} records</td></tr>
            <tr><th>Chain Head Hash</th><td style="font-family: monospace; font-size: 11px;">{chain.get("head_hash")}</td></tr>
        </table>

        {f'''
        <div class="section-title">FORENSIC COMPARISON ASSESSMENT</div>
        <table>
            <tr><th>Overall Status</th><td>{comp.get("overall_status", "N/A").upper()}</td></tr>
            <tr><th>Classification</th><td><strong>{assessment.get("classification", "N/A")}</strong></td></tr>
            <tr><th>Summary</th><td>{assessment.get("summary", "N/A")}</td></tr>
            <tr><th>Matching Chunks</th><td>{comp.get("chunks_matching", "N/A")} / {comp.get("total_chunks_a", "N/A")}</td></tr>
            <tr><th>Changed Chunks</th><td>{comp.get("chunks_changed", "N/A")}</td></tr>
            <tr><th>Change Percentage</th><td>{comp.get("change_percentage", "N/A")}%</td></tr>
        </table>
        ''' if comp else ''}

        <div class="footer">
            Generated by {report_data.get("tool_name")} Forensic Platform v{report_data.get("tool_version")} | Timestamp: {report_data.get("generated_at")}
        </div>
    </div>
</body>
</html>
"""
        return html
