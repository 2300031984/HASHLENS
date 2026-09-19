"""
HashLens Command Line Interface (CLI)
Provides forensic hashing, file comparison, chain auditing,
and evidence report generation directly from the terminal using core services.
"""

import argparse
import io
import json
import sys
from pathlib import Path
from typing import Optional

from backend.app.core.config import settings
from backend.app.db.database import init_db, SessionLocal
from backend.app.services.chain_service import HashChainService
from backend.app.services.comparison_service import ComparisonEngine
from backend.app.services.evidence_service import EvidenceService
from backend.app.services.fingerprint_service import FingerprintService
from backend.app.services.hashing_engine import HashingEngine


if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass


def cmd_hash_text(args):
    """Computes cryptographic hashes for text."""
    digests = HashingEngine.hash_text(args.text)
    print("\n" + "=" * 60)
    print("HASHLENS TEXT FORENSIC HASHES")
    print("=" * 60)
    print(f"Input text   : \"{args.text}\" ({len(args.text)} chars, {len(args.text.encode('utf-8'))} bytes)")
    print("-" * 60)
    for alg, digest in digests.items():
        print(f"{alg.upper():<8} : {digest}")
    print("=" * 60 + "\n")


def cmd_hash_file(args):
    """Computes streaming cryptographic fingerprint for a file."""
    path = Path(args.file)
    if not path.is_file():
        print(f"[-] Error: File not found: {args.file}", file=sys.stderr)
        sys.exit(1)

    fp = FingerprintService.generate_fingerprint_from_file(
        file_path=path,
        chunk_size=args.chunk_size,
    )
    print("\n" + "=" * 65)
    print(f"[FILE FINGERPRINT] {fp['filename']}")
    print("=" * 65)
    print(f"File Size      : {fp['size_bytes']} bytes ({fp['size_human']})")
    print(f"Detected Type  : {fp['mime_type']} ({fp['file_category']})")
    print(f"Total Chunks   : {fp['chunk_count']} chunks (chunk size: {fp['chunk_size']} bytes)")
    print("-" * 65)
    print(f"MD5            : {fp['hashes']['md5']}")
    print(f"SHA-1          : {fp['hashes']['sha1']}")
    print(f"SHA-256        : {fp['hashes']['sha256']}")
    print(f"SHA-512        : {fp['hashes']['sha512']}")
    print("-" * 65)
    print(f"Metadata Hash  : {fp['metadata_fingerprint']}")
    print("=" * 65 + "\n")


def cmd_compare(args):
    """Performs chunk-level comparison and forensic diagnosis between two files."""
    p1 = Path(args.file1)
    p2 = Path(args.file2)
    if not p1.is_file() or not p2.is_file():
        print("[-] Error: Both files must exist.", file=sys.stderr)
        sys.exit(1)

    fp1 = FingerprintService.generate_fingerprint_from_file(p1, chunk_size=args.chunk_size)
    fp2 = FingerprintService.generate_fingerprint_from_file(p2, chunk_size=args.chunk_size)

    comp = ComparisonEngine.compare_fingerprints(fp1, fp2)
    assessment = comp["assessment"]

    print("\n" + "=" * 65)
    print(f"[FORENSIC COMPARISON] File A vs File B")
    print("=" * 65)
    print(f"File A         : {p1.name} ({fp1['size_human']})")
    print(f"File B         : {p2.name} ({fp2['size_human']})")
    print(f"Overall Status : {comp['overall_status'].upper()}")
    print(f"SHA-256 Delta  : {'CHANGED' if comp['sha256_changed'] else 'IDENTICAL'}")
    print(f"Size Delta     : {comp['size_delta_human']}")
    print(f"Chunks Diff    : {comp['chunks_matching']} matching, {comp['chunks_changed']} modified, {comp['chunks_added']} added")
    print(f"Change %       : {comp['change_percentage']}%")
    print("-" * 65)
    print(f"ASSESSMENT     : {assessment['classification']}")
    print(f"SUMMARY        : {assessment['summary']}")
    print("Evidence:")
    for pt in assessment["evidence_points"]:
        print(f"  * {pt}")
    print("=" * 65 + "\n")


def cmd_verify_chain(args):
    """Performs active cryptographic audit on the Tamper-Evident Hash Chain."""
    init_db()
    db = SessionLocal()
    try:
        audit = HashChainService.verify_chain(db)
        print("\n" + "=" * 65)
        print("[TAMPER-EVIDENT HASH CHAIN AUDIT]")
        print("=" * 65)
        print(f"Status           : {audit['status']}")
        print(f"Cryptographically Valid : {audit['valid']}")
        print(f"Total Records    : {audit['total_records']}")
        print(f"Verified Records : {audit['verified_records']}")
        if audit.get("head_hash"):
            print(f"Head Hash        : {audit['head_hash']}")
        if not audit["valid"]:
            print(f"Failure Type     : {audit.get('failure_type')}")
            print(f"Broken Record ID : {audit.get('broken_record_id')}")
            print(f"Reason           : {audit.get('reason')}")
        print("=" * 65 + "\n")
    finally:
        db.close()


def cmd_generate_report(args):
    """Generates an Evidence Report and Evidence Report Hash."""
    path = Path(args.file)
    if not path.is_file():
        print(f"[-] Error: File not found: {args.file}", file=sys.stderr)
        sys.exit(1)

    init_db()
    db = SessionLocal()
    try:
        fp = FingerprintService.generate_fingerprint_from_file(path)
        report = EvidenceService.generate_report(
            db=db,
            fingerprint=fp,
            version_num=1,
            analyst_notes=args.notes or "Generated via HashLens CLI.",
        )
        print("\n" + "=" * 65)
        print(f"[EVIDENCE REPORT GENERATED] {report['report_id']}")
        print("=" * 65)
        print(f"File Target          : {path.name}")
        print(f"Evidence Report Hash : {report['evidence_report_hash']}")
        print(f"Timestamp            : {report['generated_at']}")
        print(f"Tamper-Evident Chain : Valid ({report['chain_audit_status']['total_records_audited']} records)")
        print("=" * 65)

        if args.html:
            html = EvidenceService.render_html_report(report)
            out_path = Path(args.html)
            out_path.write_text(html, encoding="utf-8")
            print(f"[+] Forensic HTML Certificate saved to: {out_path.resolve()}\n")
        else:
            print("")
    finally:
        db.close()


def main():
    parser = argparse.ArgumentParser(
        prog="hashlens",
        description="HashLens: File Integrity & Hash Forensics Platform CLI",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # hash text
    p_text = subparsers.add_parser("hash-text", help="Hash a string of text")
    p_text.add_argument("text", help="Text to hash")
    p_text.set_defaults(func=cmd_hash_text)

    # hash file
    p_file = subparsers.add_parser("hash-file", help="Hash and fingerprint a file")
    p_file.add_argument("file", help="Path to file")
    p_file.add_argument("--chunk-size", type=int, default=settings.DEFAULT_CHUNK_SIZE, help="Chunk size in bytes")
    p_file.set_defaults(func=cmd_hash_file)

    # compare
    p_comp = subparsers.add_parser("compare", help="Forensically compare two files")
    p_comp.add_argument("file1", help="First file")
    p_comp.add_argument("file2", help="Second file")
    p_comp.add_argument("--chunk-size", type=int, default=settings.DEFAULT_CHUNK_SIZE, help="Chunk size in bytes")
    p_comp.set_defaults(func=cmd_compare)

    # verify-chain
    p_chain = subparsers.add_parser("verify-chain", help="Audit the Tamper-Evident Hash Chain")
    p_chain.set_defaults(func=cmd_verify_chain)

    # generate-report
    p_rep = subparsers.add_parser("generate-report", help="Generate certified evidence report for a file")
    p_rep.add_argument("file", help="Path to target file")
    p_rep.add_argument("--notes", help="Optional analyst notes")
    p_rep.add_argument("--html", help="Optional path to output HTML certificate")
    p_rep.set_defaults(func=cmd_generate_report)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
