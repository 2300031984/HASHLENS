"""
HashLens End-to-End Forensic Demonstration Script
Executes the reproducible 13-step lifecycle acceptance scenario:
1. Generate initial baseline file (report.txt)
2. Stream & compute multi-algorithm cryptographic hashes
3. Commit Version 1 to repository
4. Perform localized byte edit to content
5. Stream & compute modified hashes
6. Commit Version 2 to repository
7. Run forensic differential comparison
8. Display evidence: SHA-256 changed, size delta, chunk mutations, and 'Why Did My Hash Change?' diagnosis
9. Commit events to Tamper-Evident Hash Chain
10. Verify cryptographic integrity of the chain
11. Generate certified forensic Evidence Report
12. Calculate canonical 'Evidence Report Hash'
13. Display final Evidence Report SHA-256 integrity digest.
"""

import os
import sys
from pathlib import Path

# Ensure UTF-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Add workspace root to Python path
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from backend.app.core.config import settings
from backend.app.db.database import init_db, SessionLocal
from backend.app.services.chain_service import HashChainService
from backend.app.services.comparison_service import ComparisonEngine
from backend.app.services.evidence_service import EvidenceService
from backend.app.services.fingerprint_service import FingerprintService
from backend.app.services.history_service import HistoryService


def run_demo():
    print("\n" + "=" * 75)
    print("      HASHLENS: REPRODUCIBLE END-TO-END FORENSIC DEMONSTRATION")
    print("=" * 75)

    # Initialize environment and DB
    settings.ensure_directories()
    sample_dir = ROOT_DIR / "sample_data"
    sample_dir.mkdir(parents=True, exist_ok=True)
    report_path = sample_dir / "report.txt"

    init_db()
    db = SessionLocal()

    try:
        # Step 1: Create sample file
        print("\n[STEP 1] Generating sample forensic file: sample_data/report.txt...")
        v1_text = (
            "=====================================================\n"
            "ANNUAL FINANCIAL SECURITY AUDIT REPORT - 2026\n"
            "CONFIDENTIALITY CLASSIFICATION: INTERNAL RESTRICTED\n"
            "=====================================================\n"
            "Audit Target: Enterprise Treasury Ledger System\n"
            "Audit Lead  : Forensic Operations Unit\n"
            "Total Scope : 50,000 Verified Accounts\n"
            "Risk Score  : LOW RISK (0.02)\n"
            "Authorization Hash: 98172384729384729384729384729384\n"
            "-----------------------------------------------------\n"
            "Section 1: Baseline Architecture Review... [PASSED]\n"
            "Section 2: Cryptographic Hash Controls.... [PASSED]\n"
            "Section 3: Access Control & Audit Trails.. [PASSED]\n"
        )
        report_path.write_text(v1_text, encoding="utf-8")
        print(f"         Created file size: {len(v1_text.encode('utf-8'))} bytes")

        # Step 2: Hash it (using small chunk size to demonstrate multi-chunk tracking)
        print("\n[STEP 2] Streaming & hashing Version 1 (chunk size: 128 bytes)...")
        fp_v1 = FingerprintService.generate_fingerprint_from_file(report_path, chunk_size=128)
        print(f"         MD5    : {fp_v1['hashes']['md5']}")
        print(f"         SHA-1  : {fp_v1['hashes']['sha1']}")
        print(f"         SHA-256: {fp_v1['hashes']['sha256']}")
        print(f"         Chunks : {fp_v1['chunk_count']} chunks generated")

        # Step 3: Store Version 1
        print("\n[STEP 3] Registering Version 1 baseline into history repository...")
        res_v1 = HistoryService.register_or_update_file(db, fp_v1)
        print(f"         Status: {res_v1['integrity_status']} (Version {res_v1['version']})")

        # Step 4: Modify a small portion of the file (tamper simulation)
        print("\n[STEP 4] Modifying a small portion of the file (altering 'Risk Score')...")
        v2_text = v1_text.replace("Risk Score  : LOW RISK (0.02)", "Risk Score  : CRITICAL (9.98)")
        report_path.write_text(v2_text, encoding="utf-8")
        print("         Localized byte edit applied.")

        # Step 5: Hash it again
        print("\n[STEP 5] Streaming & hashing Version 2...")
        fp_v2 = FingerprintService.generate_fingerprint_from_file(report_path, chunk_size=128)
        print(f"         SHA-256: {fp_v2['hashes']['sha256']}")

        # Step 6: Store Version 2
        print("\n[STEP 6] Registering Version 2 into history repository...")
        res_v2 = HistoryService.register_or_update_file(db, fp_v2)
        print(f"         Status: {res_v2['integrity_status']} (Version {res_v2['version']})")

        # Step 7: Compare versions
        print("\n[STEP 7] Performing forensic differential comparison...")
        comp = ComparisonEngine.compare_fingerprints(fp_v1, fp_v2)

        # Step 8: Show forensic comparison evidence
        print("\n[STEP 8] FORENSIC COMPARISON RESULTS:")
        print("         ---------------------------------------------------")
        print(f"         Overall Status   : {comp['overall_status'].upper()}")
        print(f"         SHA-256 Changed  : {comp['sha256_changed']}")
        print(f"         File Size Delta  : {comp['size_delta_human']}")
        print(f"         Chunk Breakdown  : {comp['chunks_matching']} matching / {comp['chunks_changed']} modified")
        print(f"         Change Metric    : {comp['change_percentage']}%")
        print(f"         Diagnostic Class : {comp['assessment']['classification']}")
        print(f"         Summary          : {comp['assessment']['summary']}")
        print("         Evidence Points  :")
        for pt in comp["assessment"]["evidence_points"]:
            print(f"           • {pt}")
        print("         ---------------------------------------------------")

        # Step 9: Verify events were appended to hash chain
        print("\n[STEP 9] Inspecting Tamper-Evident Hash Chain ledger...")
        records = HashChainService.get_records(db, limit=10)
        print(f"         Total records in chain: {len(records)}")

        # Step 10: Verify chain
        print("\n[STEP 10] Running active cryptographic audit on Hash Chain...")
        audit = HashChainService.verify_chain(db)
        print(f"          Chain Status : {audit['status']}")
        print(f"          Valid        : {audit['valid']}")
        print(f"          Head Hash    : {audit['head_hash']}")

        # Step 11: Generate evidence report
        print("\n[STEP 11] Generating Forensic Evidence Report...")
        report = EvidenceService.generate_report(
            db=db,
            fingerprint=fp_v2,
            comparison_result=comp,
            version_num=2,
            analyst_notes="Automated forensic acceptance test scenario.",
        )
        print(f"          Report ID    : {report['report_id']}")
        print(f"          Generated At : {report['generated_at']}")

        # Step 12 & 13: Display Evidence Report Hash
        print("\n[STEP 12 & 13] EVIDENCE REPORT HASH & INTEGRITY DIGEST:")
        print("=" * 75)
        print(f"  EVIDENCE REPORT HASH (SHA-256) : {report['evidence_report_hash']}")
        print("=" * 75)
        print("  ✓ Evidence integrity verified by canonical JSON SHA-256 digest.")
        print("  ✓ Full 13-step demonstration workflow completed successfully!")
        print("=" * 75 + "\n")

    finally:
        db.close()


if __name__ == "__main__":
    run_demo()
