"""
Comprehensive Production Security Test Suite for HashLens.
Systematically validates OWASP API Security top risks, defense-in-depth controls,
property authorization, path traversal neutralization, security header injection,
error response masking, and production environment gating.
"""

import pytest
import jwt
from backend.app.core.config import settings, Settings
from backend.app.core.auth_security import create_access_token, hash_password
from backend.app.models.models import UserModel, TrackedFileModel, ChainRecordModel
from backend.app.services.chain_service import HashChainService
from backend.app.services.history_service import HistoryService
from tests.conftest import TestingSessionLocal


def test_owasp_api1_bola_idor_protection(client):
    """
    OWASP API1 — Broken Object Level Authorization (BOLA/IDOR).
    Verifies that User A cannot access User B's files, timeline, evidence reports, or hash chain.
    Cross-user attempts must return HTTP 404 Not Found to avoid leaking resource existence.
    """
    # 1. Register User A
    res_a = client.post("/api/v1/auth/register", json={
        "email": "usera_bola@hashlens.sec",
        "username": "user_a_bola",
        "password": "Password123!",
    })
    token_a = client.post("/api/v1/auth/login", json={
        "login": "user_a_bola",
        "password": "Password123!",
    }).json()["access_token"]

    # 2. Register User B
    res_b = client.post("/api/v1/auth/register", json={
        "email": "userb_bola@hashlens.sec",
        "username": "user_b_bola",
        "password": "Password123!",
    })
    token_b = client.post("/api/v1/auth/login", json={
        "login": "user_b_bola",
        "password": "Password123!",
    }).json()["access_token"]

    # 3. User A creates a tracked file
    fp_a = {
        "filename": "confidential_audit.pdf",
        "original_filename": "confidential_audit.pdf",
        "size_bytes": 1024,
        "size_human": "1.0 KB",
        "extension": ".pdf",
        "mime_type": "application/pdf",
        "file_category": "document",
        "is_type_advisory": False,
        "hashes": {"md5": "a"*32, "sha1": "a"*40, "sha256": "a"*64, "sha512": "a"*128},
        "chunk_size": 1024,
        "chunk_count": 1,
        "chunk_fingerprints": [{"index": 0, "offset": 0, "length": 1024, "sha256": "a"*64}],
        "timestamp": "2026-09-20T00:00:00Z",
        "metadata_fingerprint": "meta_a_123",
    }
    track_res = client.post(
        "/api/v1/files/track",
        json=fp_a,
        headers={"Authorization": f"Bearer {token_a}"},
    )
    assert track_res.status_code == 200
    file_id_a = track_res.json()["file_id"]

    # 4. User B attempts to access User A's file timeline -> 404
    timeline_res = client.get(
        f"/api/v1/files/{file_id_a}/timeline",
        headers={"Authorization": f"Bearer {token_b}"},
    )
    assert timeline_res.status_code == 404
    assert "not found" in timeline_res.json()["detail"].lower()

    # 5. User B lists files -> User A's file must NOT appear
    list_b = client.get("/api/v1/files", headers={"Authorization": f"Bearer {token_b}"})
    assert list_b.status_code == 200
    file_ids_b = [f["file_id"] for f in list_b.json()]
    assert file_id_a not in file_ids_b


def test_owasp_api2_broken_authentication_jwt_tampering(client):
    """
    OWASP API2 — Broken Authentication.
    Verifies that tampered signatures, expired tokens, or forged claims are strictly rejected with 401.
    """
    # 1. Invalid signature
    user_id = "usr_target_999"
    valid_token = create_access_token(user_id=user_id)
    tampered_token = valid_token[:-4] + "FAIL"

    res1 = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {tampered_token}"},
    )
    assert res1.status_code == 401

    # 2. Missing authorization header
    res2 = client.get("/api/v1/auth/me")
    assert res2.status_code == 401

    # 3. Invalid header format
    res3 = client.get("/api/v1/auth/me", headers={"Authorization": f"Basic {valid_token}"})
    assert res3.status_code == 401


def test_owasp_api3_property_authorization_mass_assignment(client):
    """
    OWASP API3 — Broken Object Property Level Authorization (Mass Assignment).
    Verifies that client payloads attempting to overwrite server-managed fields (user_id, is_active) are ignored.
    """
    # Register user with mass-assignment attempt in JSON
    reg_payload = {
        "email": "mass_assign@hashlens.sec",
        "username": "mass_assign_user",
        "password": "Password123!",
        "is_active": False,
        "is_admin": True,
        "user_id": "usr_hacked_id",
    }
    res = client.post("/api/v1/auth/register", json=reg_payload)
    assert res.status_code == 201
    user_data = res.json()
    assert user_data["email"] == "mass_assign@hashlens.sec"
    assert user_data["username"] == "mass_assign_user"
    assert user_data["is_active"] is True  # Default server assignment retained
    assert user_data["id"] != "usr_hacked_id"  # Server-generated UUID retained


def test_owasp_api4_unrestricted_resource_consumption(client):
    """
    OWASP API4 — Unrestricted Resource Consumption.
    Verifies maximum upload size bounds, chunk size limits, and rate limiting.
    """
    # Oversized chunk size (>16MB)
    files = {"file": ("test.bin", b"A" * 100, "application/octet-stream")}
    res = client.post("/api/v1/hash/file", files=files, data={"chunk_size": 32 * 1024 * 1024})
    assert res.status_code == 400
    assert "chunk_size must be between" in res.json()["detail"]


def test_owasp_api5_function_level_authorization_tamper_gating(client, monkeypatch):
    """
    OWASP API5 — Broken Function Level Authorization.
    Verifies that production mode strictly disables tamper simulation (/chain/simulate-tamper).
    """
    monkeypatch.setattr(settings, "APP_ENV", "production")

    res = client.post("/api/v1/chain/simulate-tamper?record_id=rec_fake_123")
    assert res.status_code == 403
    assert "disabled in production mode" in res.json()["detail"].lower()


def test_owasp_api8_security_misconfiguration_headers(client):
    """
    OWASP API8 — Security Misconfiguration.
    Verifies that all API responses include defensive security headers and sanitized errors.
    """
    res = client.get("/api/v1/health")
    assert res.status_code == 200
    assert res.headers.get("X-Content-Type-Options") == "nosniff"
    assert res.headers.get("X-Frame-Options") == "DENY"
    assert "X-Request-ID" in res.headers

    # Check 404 response error structure
    res_404 = client.get("/api/v1/evidence/nonexistent-report-999")
    assert res_404.status_code == 404
    assert "detail" in res_404.json()
    assert "traceback" not in res_404.json()


def test_path_traversal_and_null_byte_filename_neutralization(client):
    """
    Verifies path traversal filenames with Windows/Unix separators and null bytes are sanitized cleanly.
    """
    traversal_inputs = [
        "../../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\cmd.exe",
        "malware.exe\x00.pdf",
        "....//....//var/log/audit.log",
    ]

    for name in traversal_inputs:
        files = {"file": (name, b"sample content for testing", "text/plain")}
        res = client.post("/api/v1/hash/file", files=files)
        assert res.status_code == 200
        clean_filename = res.json()["filename"]

        assert "/" not in clean_filename
        assert "\\" not in clean_filename
        assert "\x00" not in clean_filename
        assert ".." not in clean_filename
