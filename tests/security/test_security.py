"""
Security Test Suite for HashLens.
Tests defense-in-depth controls: path traversal attacks, malicious filenames,
oversized uploads, rate limiting, security headers, and tampering detection.
"""

import pytest
from fastapi.testclient import TestClient
from backend.app.main import app
from tests.conftest import TestingSessionLocal
from backend.app.services.chain_service import HashChainService


def test_security_headers_present(client):
    """Verify defensive security headers are appended to responses."""
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    headers = response.headers
    assert headers.get("X-Content-Type-Options") == "nosniff"
    assert headers.get("X-Frame-Options") == "DENY"
    assert "Content-Security-Policy" in headers
    assert "X-Request-ID" in headers
    assert "X-RateLimit-Limit" in headers


def test_path_traversal_filename_neutralization(client):
    """Verify that dangerous directory traversal filenames are safely sanitized."""
    malicious_names = [
        "../../../../../../etc/shadow",
        "..\\..\\..\\windows\\system32\\cmd.exe",
        "exploit.pdf\x00.exe",
        "/absolute/root/malware.sh",
    ]

    for evil_name in malicious_names:
        files = {"file": (evil_name, b"harmless content", "text/plain")}
        res = client.post("/api/v1/hash/file", files=files)
        assert res.status_code == 200
        clean_name = res.json()["filename"]
        # Ensure no slashes, backslashes, or null bytes survive
        assert "/" not in clean_name
        assert "\\" not in clean_name
        assert "\x00" not in clean_name
        assert ".." not in clean_name


def test_invalid_algorithm_rejection(client):
    """Verify requesting an unauthorized or unknown algorithm fails safely."""
    payload = {"text": "secret", "algorithms": ["rot13", "des", "md5"]}
    res = client.post("/api/v1/hash/text", json=payload)
    assert res.status_code == 400
    assert "Unsupported algorithm" in res.json()["detail"]


def test_invalid_chunk_size_bounds(client):
    """Verify chunk sizes outside safe bounds [4KB, 16MB] are rejected with 400."""
    # Chunk size too small (<4096)
    files = {"file": ("test.bin", b"A" * 5000, "application/octet-stream")}
    res1 = client.post("/api/v1/hash/file", files=files, data={"chunk_size": 100})
    assert res1.status_code == 400

    # Chunk size too large (>16MB)
    files = {"file": ("test.bin", b"A" * 5000, "application/octet-stream")}
    res2 = client.post("/api/v1/hash/file", files=files, data={"chunk_size": 30 * 1024 * 1024})
    assert res2.status_code == 400


def test_chain_tamper_simulation_via_api(client):
    """Verify that simulating tamper on a record breaks audit verification."""
    # 1. Register a record
    db = TestingSessionLocal()
    r = HashChainService.append_event(db, "SECURITY_TEST_EVENT", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    db.close()

    # 2. Verify chain is initially valid
    verify1 = client.post("/api/v1/chain/verify")
    assert verify1.status_code == 200
    assert verify1.json()["valid"] is True

    # 3. Simulate tamper
    tamper_res = client.post(f"/api/v1/chain/simulate-tamper?record_id={r.record_id}")
    assert tamper_res.status_code == 200

    # 4. Re-verify chain -> must detect failure
    verify2 = client.post("/api/v1/chain/verify")
    assert verify2.status_code == 200
    res_data = verify2.json()
    assert res_data["status"] == "CHAIN_BROKEN"
    assert res_data["valid"] is False
    assert res_data["broken_record_id"] == r.record_id
    assert "Content tampering detected" in res_data["reason"]


def test_rate_limiter_enforcement():
    """Verify rate limiter permits up to max_requests and rejects subsequent requests."""
    from backend.app.core.security import InMemoryRateLimiter
    limiter = InMemoryRateLimiter(max_requests=3, window_seconds=60)
    test_ip = "192.168.1.100"

    allowed1, rem1 = limiter.is_allowed(test_ip)
    assert allowed1 is True and rem1 == 2

    allowed2, rem2 = limiter.is_allowed(test_ip)
    assert allowed2 is True and rem2 == 1

    allowed3, rem3 = limiter.is_allowed(test_ip)
    assert allowed3 is True and rem3 == 0

    # 4th request exceeds max_requests=3
    allowed4, rem4 = limiter.is_allowed(test_ip)
    assert allowed4 is False and rem4 == 0
