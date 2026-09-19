"""
HASHLENS — Performance Smoke Test Script
Measures real processing times for hashing, chunk fingerprinting, and forensic file comparison.
"""

import sys
import time
import tempfile
import os
from pathlib import Path

# Add project root to Python path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.services.hashing_engine import HashingEngine
from backend.app.services.fingerprint_service import FingerprintService
from backend.app.services.comparison_service import ComparisonEngine


def run_performance_smoketest():
    print("===========================================================================")
    print("        HASHLENS: PERFORMANCE SMOKE TEST & BENCHMARK VALIDATION            ")
    print("===========================================================================")

    hashing_engine = HashingEngine()
    fingerprint_service = FingerprintService()
    comparison_engine = ComparisonEngine()

    # 1. Small File Test (10 KB)
    small_data = b"HashLens Performance Benchmark - Small Payload Test. " * 200
    t0 = time.perf_counter()
    small_hashes = hashing_engine.hash_bytes(small_data)
    t1 = time.perf_counter()
    small_time_ms = (t1 - t0) * 1000
    print(f"\n[1] Small File Hashing (Size: {len(small_data):,} bytes):")
    print(f"    - Multi-algorithm hash time : {small_time_ms:.3f} ms")
    print(f"    - SHA-256 digest             : {small_hashes['sha256']}")

    # 2. Moderately Sized File Test (1 MB)
    medium_data = b"A" * (1024 * 1024)  # 1 MB
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(medium_data)
        tmp_path = tmp.name

    try:
        t0 = time.perf_counter()
        with open(tmp_path, "rb") as f:
            medium_hashes, total_bytes = hashing_engine.hash_stream(f)
        t1 = time.perf_counter()
        medium_time_ms = (t1 - t0) * 1000
        print(f"\n[2] Moderately Sized File Hashing (Size: {total_bytes:,} bytes / 1 MB):")
        print(f"    - Streaming multi-hash time : {medium_time_ms:.3f} ms")
        print(f"    - SHA-256 digest             : {medium_hashes['sha256']}")

        # 3. Chunk Fingerprinting Test (1 MB with 64 KB chunk size)
        chunk_size = 64 * 1024
        t0 = time.perf_counter()
        fp_result = fingerprint_service.generate_fingerprint_from_file(tmp_path, chunk_size=chunk_size)
        t1 = time.perf_counter()
        fp_time_ms = (t1 - t0) * 1000
        print(f"\n[3] Chunk Fingerprinting (Size: 1 MB, Chunk Size: 64 KB):")
        print(f"    - Total chunks generated    : {fp_result['chunk_count']}")
        print(f"    - Fingerprint process time  : {fp_time_ms:.3f} ms")

        # 4. Forensic File Comparison Test (1 MB File vs 1 MB File with 1 byte edited)
        modified_data = bytearray(medium_data)
        modified_data[512 * 1024] = ord('B')  # Edit 1 byte in the middle chunk
        with tempfile.NamedTemporaryFile(delete=False) as tmp_mod:
            tmp_mod.write(modified_data)
            tmp_mod_path = tmp_mod.name

        try:
            fp_orig = fingerprint_service.generate_fingerprint_from_file(tmp_path, chunk_size=chunk_size)
            fp_mod = fingerprint_service.generate_fingerprint_from_file(tmp_mod_path, chunk_size=chunk_size)

            t0 = time.perf_counter()
            comp_result = comparison_engine.compare_fingerprints(fp_orig, fp_mod)
            t1 = time.perf_counter()
            comp_time_ms = (t1 - t0) * 1000

            print(f"\n[4] Forensic File Differential Comparison (1 MB vs 1 MB edited):")
            print(f"    - Comparison analysis time  : {comp_time_ms:.3f} ms")
            print(f"    - Diagnostic Classification : {comp_result['assessment']['classification']}")
            print(f"    - Change Percentage         : {comp_result['change_percentage']:.1f}%")

        finally:
            if os.path.exists(tmp_mod_path):
                os.remove(tmp_mod_path)
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)

    print("\n===========================================================================")
    print("[OK] PERFORMANCE SMOKE TEST COMPLETED SUCCESSFULLY")
    print("===========================================================================")


if __name__ == "__main__":
    run_performance_smoketest()
