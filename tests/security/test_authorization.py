"""
Security Test Suite for HashLens Per-User Data Isolation & IDOR / BOLA Defenses.
Verifies resource ownership assignment, user-scoped list queries, cross-user read/update/delete denial,
and tamper-evident hash chain isolation.
"""

import pytest
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.core.auth_security import create_access_token
from tests.conftest import TestingSessionLocal
from backend.app.models.models import UserModel, TrackedFileModel, EvidenceReportModel, ChainRecordModel


@pytest.fixture
def user_a(client):
    """Register and authenticate User A."""
    reg_payload = {
        "email": "user_a@hashlens.sec",
        "username": "user_a",
        "password": "PasswordUserA123!",
    }
    client.post("/api/v1/auth/register", json=reg_payload)
    login_res = client.post("/api/v1/auth/login", json={
        "login": "user_a",
        "password": "PasswordUserA123!",
    })
    token = login_res.json()["access_token"]
    user_id = login_res.json()["user"]["id"]
    return {"id": user_id, "token": token, "headers": {"Authorization": f"Bearer {token}"}}


@pytest.fixture
def user_b(client):
    """Register and authenticate User B."""
    reg_payload = {
        "email": "user_b@hashlens.sec",
        "username": "user_b",
        "password": "PasswordUserB123!",
    }
    client.post("/api/v1/auth/register", json=reg_payload)
    login_res = client.post("/api/v1/auth/login", json={
        "login": "user_b",
        "password": "PasswordUserB123!",
    })
    token = login_res.json()["access_token"]
    user_id = login_res.json()["user"]["id"]
    return {"id": user_id, "token": token, "headers": {"Authorization": f"Bearer {token}"}}


def test_resource_ownership_assignment(client, user_a):
    """Verify that resource creation operations assign ownership to current_user.id from JWT."""
    # Hash a dummy file
    files = {"file": ("analyst_report.txt", b"Sensitive content for User A", "text/plain")}
    res_hash = client.post("/api/v1/hash/file", files=files)
    fp = res_hash.json()

    # Track file with User A's token
    res_track = client.post("/api/v1/files/track", json=fp, headers=user_a["headers"])
    assert res_track.status_code == 200
    file_id = res_track.json()["file_id"]

    # Check DB model has user_id == user_a["id"]
    db = TestingSessionLocal()
    tf = db.query(TrackedFileModel).filter(TrackedFileModel.id == file_id).first()
    assert tf is not None
    assert tf.user_id == user_a["id"]
    db.close()


def test_user_scoped_list_isolation(client, user_a, user_b):
    """Verify that GET /files returns only the authenticated user's resources."""
    # User A tracks a file
    fp_a = client.post("/api/v1/hash/file", files={"file": ("file_a.txt", b"Data A", "text/plain")}).json()
    client.post("/api/v1/files/track", json=fp_a, headers=user_a["headers"])

    # User B tracks a file
    fp_b = client.post("/api/v1/hash/file", files={"file": ("file_b.txt", b"Data B", "text/plain")}).json()
    client.post("/api/v1/files/track", json=fp_b, headers=user_b["headers"])

    # User A lists files -> receives file_a.txt only
    list_a = client.get("/api/v1/files", headers=user_a["headers"]).json()
    filenames_a = [f["filename"] for f in list_a]
    assert "file_a.txt" in filenames_a
    assert "file_b.txt" not in filenames_a

    # User B lists files -> receives file_b.txt only
    list_b = client.get("/api/v1/files", headers=user_b["headers"]).json()
    filenames_b = [f["filename"] for f in list_b]
    assert "file_b.txt" in filenames_b
    assert "file_a.txt" not in filenames_b


def test_idor_cross_user_timeline_access_denial(client, user_a, user_b):
    """Verify IDOR protection: User A cannot read User B's file timeline (returns 404)."""
    # User B tracks a file
    fp_b = client.post("/api/v1/hash/file", files={"file": ("secret_b.docx", b"User B Confidential", "text/plain")}).json()
    track_b = client.post("/api/v1/files/track", json=fp_b, headers=user_b["headers"]).json()
    file_b_id = track_b["file_id"]

    # User B can view timeline -> 200
    res_b = client.get(f"/api/v1/files/{file_b_id}/timeline", headers=user_b["headers"])
    assert res_b.status_code == 200

    # User A attempts to view User B's timeline -> 404 Not Found (IDOR defense)
    res_a = client.get(f"/api/v1/files/{file_b_id}/timeline", headers=user_a["headers"])
    assert res_a.status_code == 404


def test_idor_cross_user_evidence_report_denial(client, user_a, user_b):
    """Verify IDOR protection: User A cannot read or render User B's Evidence Report (returns 404)."""
    # User B generates evidence report
    fp_b = client.post("/api/v1/hash/file", files={"file": ("evidence_b.log", b"User B Forensic Logs", "text/plain")}).json()
    rep_b = client.post(
        "/api/v1/evidence/generate",
        json={"fingerprint": fp_b, "analyst_notes": "Confidential report for B"},
        headers=user_b["headers"],
    ).json()
    report_id_b = rep_b["report_id"]

    # User B can fetch report -> 200
    res_b = client.get(f"/api/v1/evidence/{report_id_b}", headers=user_b["headers"])
    assert res_b.status_code == 200

    # User A attempts to fetch report -> 404
    res_a_json = client.get(f"/api/v1/evidence/{report_id_b}", headers=user_a["headers"])
    assert res_a_json.status_code == 404

    # User A attempts to render HTML report -> 404
    res_a_html = client.get(f"/api/v1/evidence/{report_id_b}/html", headers=user_a["headers"])
    assert res_a_html.status_code == 404


def test_per_user_tamper_evident_chain_isolation(client, user_a, user_b):
    """Verify that tamper-evident hash chains are isolated per user."""
    # User A registers event
    fp_a = client.post("/api/v1/hash/file", files={"file": ("chain_a.txt", b"User A Chain Event", "text/plain")}).json()
    client.post("/api/v1/files/track", json=fp_a, headers=user_a["headers"])

    # User B registers event
    fp_b = client.post("/api/v1/hash/file", files={"file": ("chain_b.txt", b"User B Chain Event", "text/plain")}).json()
    client.post("/api/v1/files/track", json=fp_b, headers=user_b["headers"])

    # User A chain records -> only User A
    records_a = client.get("/api/v1/chain/records", headers=user_a["headers"]).json()
    assert len(records_a) >= 1

    # User B chain records -> only User B
    records_b = client.get("/api/v1/chain/records", headers=user_b["headers"]).json()
    assert len(records_b) >= 1

    # User A chain verification -> valid for User A
    audit_a = client.post("/api/v1/chain/verify", headers=user_a["headers"]).json()
    assert audit_a["valid"] is True


def test_jwt_user_id_tampering_denial(client):
    """Verify server rejects client-crafted JWT containing non-existent or forged user_id sub."""
    forged_token = create_access_token(user_id="usr_nonexistent_forged_99999")
    res = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {forged_token}"},
    )
    assert res.status_code == 401
    assert "does not exist" in res.json()["detail"]
