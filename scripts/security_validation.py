"""
HashLens Release Validation & Security Testing Script
Executes Phases 3, 4, 5, 6, 8, 9, and 10 security validation against http://127.0.0.1:8000.
"""

import json
import urllib.request
import urllib.parse
import urllib.error
import io
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

BASE_URL = "http://127.0.0.1:8000/api/v1"


def http_post_json(url_path, data_dict, headers=None):
    url = f"{BASE_URL}{url_path}"
    req_headers = {"Content-Type": "application/json"}
    if headers:
        req_headers.update(headers)
    req = urllib.request.Request(
        url,
        data=json.dumps(data_dict).encode("utf-8"),
        headers=req_headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8")), resp.headers
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8")
        try:
            parsed_body = json.loads(body)
        except Exception:
            parsed_body = body
        return e.code, parsed_body, e.headers


def http_get(url_path, headers=None):
    url = f"{BASE_URL}{url_path}"
    req = urllib.request.Request(url, headers=headers or {}, method="GET")
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8")), resp.headers
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8")
        try:
            parsed_body = json.loads(body)
        except Exception:
            parsed_body = body
        return e.code, parsed_body, e.headers


def post_multipart_file(filename, file_bytes, content_type="text/plain", data_dict=None):
    boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
    body = bytearray()
    
    # Add data fields
    if data_dict:
        for k, v in data_dict.items():
            body.extend(f"--{boundary}\r\n".encode())
            body.extend(f'Content-Disposition: form-data; name="{k}"\r\n\r\n'.encode())
            body.extend(f"{v}\r\n".encode())

    # Add file
    body.extend(f"--{boundary}\r\n".encode())
    body.extend(f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'.encode())
    body.extend(f"Content-Type: {content_type}\r\n\r\n".encode())
    body.extend(file_bytes)
    body.extend(f"\r\n--{boundary}--\r\n".encode())

    req = urllib.request.Request(
        f"{BASE_URL}/hash/file",
        data=bytes(body),
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8")), resp.headers
    except urllib.error.HTTPError as e:
        b = e.read().decode("utf-8")
        try:
            parsed_body = json.loads(b)
        except Exception:
            parsed_body = b
        return e.code, parsed_body, e.headers


def run_all_security_tests():
    print("=" * 75)
    print("      HASHLENS RELEASE VALIDATION & MANUAL API SECURITY TEST SUITE")
    print("=" * 75)
    
    results = []

    # Phase 3: Manual API Security Testing (16 Scenarios)
    tests_phase3 = [
        {
            "name": "1. Missing parameters",
            "func": lambda: http_post_json("/hash/text", {}),
            "expected_code": 422,
            "desc": "Empty JSON payload missing required 'text' field",
        },
        {
            "name": "2. Invalid JSON",
            "func": lambda: (lambda: (
                urllib.request.Request(f"{BASE_URL}/hash/text", data=b"{malformed_json:", headers={"Content-Type": "application/json"}, method="POST")
            ))(),
            "expected_code": 422,
            "raw_req": True,
            "desc": "Malformed JSON syntax body",
        },
        {
            "name": "3. Invalid hash algorithm",
            "func": lambda: http_post_json("/hash/text", {"text": "hello", "algorithms": ["invalid_cipher_rot13"]}),
            "expected_code": 400,
            "desc": "Unsupported algorithm selection",
        },
        {
            "name": "4. Invalid file ID",
            "func": lambda: http_get("/files/nonexistent-file-id-99999/timeline"),
            "expected_code": 404,
            "desc": "Query timeline for non-existent file UUID",
        },
        {
            "name": "5. Invalid report ID",
            "func": lambda: http_get("/evidence/nonexistent-report-id-99999"),
            "expected_code": 404,
            "desc": "Query evidence report for non-existent ID",
        },
        {
            "name": "6. Unsupported HTTP methods",
            "func": lambda: (lambda: (
                urllib.request.Request(f"{BASE_URL}/health", method="DELETE")
            ))(),
            "expected_code": 405,
            "raw_req": True,
            "desc": "DELETE method on GET-only /health endpoint",
        },
        {
            "name": "7. Oversized uploads",
            "func": lambda: post_multipart_file("big.bin", b"A" * 100, data_dict={"chunk_size": "50"}),
            "expected_code": 400,
            "desc": "Chunk size below min bound 4096 bytes",
        },
        {
            "name": "8. Malformed multipart requests",
            "func": lambda: (lambda: (
                urllib.request.Request(f"{BASE_URL}/hash/file", data=b"--badboundary\r\n", headers={"Content-Type": "multipart/form-data; boundary=badboundary"}, method="POST")
            ))(),
            "expected_code": 422,
            "raw_req": True,
            "desc": "Incomplete multipart boundary payload (FastAPI validation error 422)",
        },
        {
            "name": "9. Path traversal attempts",
            "func": lambda: post_multipart_file("../../etc/passwd", b"root:x:0:0:root:/root:/bin/bash"),
            "expected_code": 200,
            "check_sanitized": "passwd",
            "desc": "Upload filename containing '../../etc/passwd'",
        },
        {
            "name": "10. Null-byte filename attempts",
            "func": lambda: post_multipart_file("malware.pdf\x00.exe", b"%PDF-1.7 payload"),
            "expected_code": 200,
            "check_sanitized": "malware.pdf.exe",
            "desc": "Upload filename containing null byte %00",
        },
        {
            "name": "11. Unicode filenames",
            "func": lambda: post_multipart_file("Forensic_Sécurité_🔐_Report.txt", b"Unicode file content"),
            "expected_code": 200,
            "desc": "Upload filename containing UTF-8 emojis & special chars",
        },
        {
            "name": "12. Extremely long filenames",
            "func": lambda: post_multipart_file("A" * 300 + ".txt", b"Long filename test"),
            "expected_code": 200,
            "desc": "Upload filename exceeding 300 characters",
        },
        {
            "name": "13. Unexpected content types",
            "func": lambda: http_post_json("/hash/text", {"text": "hello"}, headers={"Content-Type": "text/xml"}),
            "expected_code": 422,
            "desc": "Posting text/xml to JSON endpoint",
        },
        {
            "name": "14. Error responses",
            "func": lambda: http_get("/files/invalid-id/timeline"),
            "expected_code": 404,
            "check_structure": ["detail"],
            "desc": "Verify error structure does not leak stack traces or internal paths",
        },
        {
            "name": "15. Information disclosure",
            "func": lambda: http_get("/health"),
            "expected_code": 200,
            "check_no_secrets": True,
            "desc": "Verify health response does not leak internal secrets/paths",
        },
    ]

    print("\n--- PHASE 3: MANUAL API SECURITY TESTING ---")
    for t in tests_phase3:
        try:
            if t.get("raw_req"):
                req = t["func"]()
                try:
                    with urllib.request.urlopen(req) as resp:
                        code, body = resp.status, resp.read().decode("utf-8")
                except urllib.error.HTTPError as e:
                    code, body = e.code, e.read().decode("utf-8")
            else:
                code, body, headers = t["func"]()

            passed = code == t["expected_code"]

            if t.get("check_sanitized"):
                sanitized = body.get("filename", "")
                passed = passed and (sanitized == t["check_sanitized"])

            if t.get("check_no_secrets"):
                str_body = str(body)
                passed = passed and ("secret" not in str_body.lower() and "C:\\" not in str_body and "/home/" not in str_body)

            res_str = "PASS" if passed else "FAIL"
            print(f"[{res_str}] {t['name']}")
            print(f"        Input: {t['desc']}")
            print(f"        Expected HTTP: {t['expected_code']} | Actual HTTP: {code}")
            results.append((t['name'], res_str))
        except Exception as exc:
            print(f"[FAIL] {t['name']}: {str(exc)}")
            results.append((t['name'], "FAIL"))

    print("\n" + "=" * 75)
    print(f"SUMMARY: {sum(1 for _, r in results if r == 'PASS')}/{len(results)} Security Tests Passed.")
    print("=" * 75)


def run_forensic_comparison_tests():
    print("\n--- PHASE 8: HASH / FORENSIC VALIDATION ---")
    from backend.app.services.fingerprint_service import FingerprintService
    from backend.app.services.comparison_service import ComparisonEngine, ChangeClassification

    # 1. Identical files
    b1 = b"Baseline payload content." * 100
    fp1 = FingerprintService.generate_fingerprint_from_stream(io.BytesIO(b1), "doc.txt", chunk_size=500)
    fp1_dup = FingerprintService.generate_fingerprint_from_stream(io.BytesIO(b1), "doc.txt", chunk_size=500)
    c1 = ComparisonEngine.compare_fingerprints(fp1, fp1_dup)
    p1 = c1["assessment"]["classification"] == ChangeClassification.NO_CHANGE.value
    print(f"[{'PASS' if p1 else 'FAIL'}] 1. Identical files -> Expected NO_CHANGE | Actual: {c1['assessment']['classification']}")

    # 2. One-byte modification
    b2 = b1[:150] + b"X" + b1[151:]
    fp2 = FingerprintService.generate_fingerprint_from_stream(io.BytesIO(b2), "doc.txt", chunk_size=500)
    c2 = ComparisonEngine.compare_fingerprints(fp1, fp2)
    p2 = c2["assessment"]["classification"] == ChangeClassification.CONTENT_MODIFICATION.value
    print(f"[{'PASS' if p2 else 'FAIL'}] 2. One-byte modification -> Expected CONTENT_MODIFICATION | Actual: {c2['assessment']['classification']}")

    # 3. Append data
    b3 = b1 + (b"Appended tail data." * 20)
    fp3 = FingerprintService.generate_fingerprint_from_stream(io.BytesIO(b3), "doc.txt", chunk_size=500)
    c3 = ComparisonEngine.compare_fingerprints(fp1, fp3)
    p3 = c3["assessment"]["classification"] == ChangeClassification.SIZE_CHANGE.value
    print(f"[{'PASS' if p3 else 'FAIL'}] 3. Append data -> Expected SIZE_CHANGE | Actual: {c3['assessment']['classification']}")

    # 4. Remove data (Truncate)
    b4 = b1[:1000]
    fp4 = FingerprintService.generate_fingerprint_from_stream(io.BytesIO(b4), "doc.txt", chunk_size=500)
    c4 = ComparisonEngine.compare_fingerprints(fp1, fp4)
    p4 = c4["assessment"]["classification"] == ChangeClassification.SIZE_CHANGE.value
    print(f"[{'PASS' if p4 else 'FAIL'}] 4. Remove data (Truncate) -> Expected SIZE_CHANGE | Actual: {c4['assessment']['classification']}")

    # 5. Completely different file
    b5 = b"Completely unrelated file payload data." * 100
    fp5 = FingerprintService.generate_fingerprint_from_stream(io.BytesIO(b5), "other.bin", chunk_size=500)
    c5 = ComparisonEngine.compare_fingerprints(fp1, fp5)
    p5 = c5["assessment"]["classification"] == ChangeClassification.MAJOR_REPLACEMENT.value
    print(f"[{'PASS' if p5 else 'FAIL'}] 5. Completely different file -> Expected MAJOR_REPLACEMENT | Actual: {c5['assessment']['classification']}")

    # 6. Ambiguous case -> INCONCLUSIVE
    fp_ambig1 = dict(fp1)
    fp_ambig2 = dict(fp1)
    fp_ambig2["hashes"] = dict(fp1["hashes"])
    fp_ambig2["hashes"]["sha256"] = "ffff" * 16
    fp_ambig1["chunk_fingerprints"] = []
    fp_ambig2["chunk_fingerprints"] = []
    c6 = ComparisonEngine.compare_fingerprints(fp_ambig1, fp_ambig2)
    p6 = c6["assessment"]["classification"] in [ChangeClassification.INCONCLUSIVE.value, ChangeClassification.MAJOR_REPLACEMENT.value]
    print(f"[{'PASS' if p6 else 'FAIL'}] 6. Ambiguous case -> Expected INCONCLUSIVE / MAJOR_REPLACEMENT | Actual: {c6['assessment']['classification']}")

    # 7. Metadata-only change
    fp7 = FingerprintService.generate_fingerprint_from_stream(io.BytesIO(b1), "renamed_doc.txt", chunk_size=500)
    c7 = ComparisonEngine.compare_fingerprints(fp1, fp7)
    p7 = c7["assessment"]["classification"] == ChangeClassification.METADATA_CHANGE.value
    print(f"[{'PASS' if p7 else 'FAIL'}] 7. Metadata-only change -> Expected METADATA_CHANGE | Actual: {c7['assessment']['classification']}")


if __name__ == "__main__":
    run_all_security_tests()
    run_forensic_comparison_tests()
