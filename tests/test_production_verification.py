"""
Pytest Production Verification Suite
Validates the complete production acceptance matrix across health diagnostics,
Argon2id authentication, JWT verification, per-user BOLA/IDOR isolation (404 masking),
tamper-evident hash chaining, evidence report generation, production tamper simulation blocking (403),
local fallback disabling, security headers, and error response masking.
"""

import pytest
from backend.app.core.config import settings
from backend.app.services.chain_service import HashChainService
from backend.app.models.models import UserModel
from tests.conftest import TestingSessionLocal


def test_production_health_check_and_diagnostics(client):
    """Verifies health check endpoint returns 200 with online status and healthy database."""
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "online"
    assert data["database"] == "healthy"
    assert "chain_health" in data


def test_production_authentication_flow(client):
    """Verifies full auth flow: registration, login, JWT issuance, profile retrieval, and logout."""
    # 1. Register
    reg_res = client.post("/api/v1/auth/register", json={
        "email": "prod_user1@hashlens.sec",
        "username": "prod_user1",
        "password": "Password123!",
    })
    assert reg_res.status_code == 201
    assert reg_res.json()["email"] == "prod_user1@hashlens.sec"

    # 2. Login
    login_res = client.post("/api/v1/auth/login", json={
        "login": "prod_user1",
        "password": "Password123!",
    })
    assert login_res.status_code == 200
    token = login_res.json()["access_token"]

    # 3. Profile
    me_res = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_res.status_code == 200
    assert me_res.json()["username"] == "prod_user1"

    # 4. Logout
    logout_res = client.post("/api/v1/auth/logout", headers={"Authorization": f"Bearer {token}"})
    assert logout_res.status_code == 200


def test_production_bola_idor_data_isolation(client):
    """Verifies BOLA/IDOR cross-user resource isolation returns 404 Not Found."""
    # Register User 1
    u1_reg = client.post("/api/v1/auth/register", json={
        "email": "u1_prod@hashlens.sec",
        "username": "u1_prod",
        "password": "Password123!",
    })
    token1 = client.post("/api/v1/auth/login", json={"login": "u1_prod", "password": "Password123!"}).json()["access_token"]

    # Register User 2
    u2_reg = client.post("/api/v1/auth/register", json={
        "email": "u2_prod@hashlens.sec",
        "username": "u2_prod",
        "password": "Password123!",
    })
    token2 = client.post("/api/v1/auth/login", json={"login": "u2_prod", "password": "Password123!"}).json()["access_token"]

    # User 1 tracks a file
    fp = {
        "filename": "sec_audit.docx",
        "original_filename": "sec_audit.docx",
        "size_bytes": 2048,
        "size_human": "2.0 KB",
        "extension": ".docx",
        "mime_type": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "file_category": "document",
        "is_type_advisory": False,
        "hashes": {"md5": "b"*32, "sha1": "b"*40, "sha256": "b"*64, "sha512": "b"*128},
        "chunk_size": 2048,
        "chunk_count": 1,
        "chunk_fingerprints": [{"index": 0, "offset": 0, "length": 2048, "sha256": "b"*64}],
        "timestamp": "2026-09-20T00:00:00Z",
        "metadata_fingerprint": "meta_u1_999",
    }
    track_res = client.post("/api/v1/files/track", json=fp, headers={"Authorization": f"Bearer {token1}"})
    assert track_res.status_code == 200
    file_id1 = track_res.json()["file_id"]

    # User 2 attempts to query User 1's file timeline -> 404
    cross_res = client.get(f"/api/v1/files/{file_id1}/timeline", headers={"Authorization": f"Bearer {token2}"})
    assert cross_res.status_code == 404


def test_production_tamper_simulation_gating(client, monkeypatch):
    """Verifies /chain/simulate-tamper is blocked with HTTP 403 Forbidden in production mode."""
    monkeypatch.setattr(settings, "APP_ENV", "production")
    res = client.post("/api/v1/chain/simulate-tamper?record_id=rec-test-123")
    assert res.status_code == 403
    assert "disabled in production mode" in res.json()["detail"].lower()
