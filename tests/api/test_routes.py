"""
Integration tests for HashLens FastAPI REST endpoints.
Verifies all routes under /api/v1 using FastAPI TestClient.
"""

import io
import pytest
from fastapi.testclient import TestClient

from backend.app.main import app


def test_health_endpoint(client):
    """Verify health check returns online status, version, and database state."""
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] in ["online", "degraded"]
    assert data["app"] == "HashLens"
    assert "uptime_seconds" in data
    assert "database" in data
    assert "chain_health" in data


def test_algorithms_metadata(client):
    """Verify supported algorithms and security education metadata."""
    response = client.get("/api/v1/algorithms")
    assert response.status_code == 200
    data = response.json()
    assert "md5" in data["supported_algorithms"]
    assert "sha256" in data["supported_algorithms"]
    assert "password_security_notice" in data
    assert data["metadata"]["sha256"]["security_status"] == "SECURE_STANDARD"


def test_hash_text_endpoint(client):
    """Verify text hashing via REST API."""
    payload = {"text": "hello", "algorithms": ["md5", "sha256"]}
    response = client.post("/api/v1/hash/text", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["hashes"]["md5"] == "5d41402abc4b2a76b9719d911017c592"
    assert data["hashes"]["sha256"] == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    assert "sha1" not in data["hashes"]


def test_hash_file_endpoint(client):
    """Verify multipart file upload and streaming fingerprint generation."""
    file_bytes = b"Forensic sample content streamed to API." * 200
    files = {"file": ("evidence.txt", file_bytes, "text/plain")}
    response = client.post("/api/v1/hash/file", files=files, data={"chunk_size": "4096"})
    assert response.status_code == 200
    data = response.json()
    assert data["filename"] == "evidence.txt"
    assert data["size_bytes"] == len(file_bytes)
    assert len(data["hashes"]["sha256"]) == 64
    assert data["chunk_count"] > 0
    assert len(data["chunk_fingerprints"]) == data["chunk_count"]


def test_avalanche_endpoint(client):
    """Verify bit-flip avalanche calculation endpoint."""
    payload = {
        "text1": "cybersecurity baseline",
        "text2": "cybersecurity faseline",
        "algorithm": "sha256",
    }
    response = client.post("/api/v1/avalanche", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["total_bits"] == 256
    assert 30.0 <= data["flip_percentage"] <= 70.0


def test_compare_files_endpoint(client):
    """Verify comparing two uploaded files via API."""
    f1 = b"Original baseline data" * 10
    f2 = b"Original baseline data" * 9 + b"Modified trailing data"
    files = {
        "file_a": ("base.txt", f1, "text/plain"),
        "file_b": ("mod.txt", f2, "text/plain"),
    }
    response = client.post("/api/v1/compare/files", files=files)
    assert response.status_code == 200
    data = response.json()
    assert data["overall_status"] == "modified"
    assert data["sha256_changed"] is True
    assert "assessment" in data
    assert "classification" in data["assessment"]


def test_chain_status_and_verify(client):
    """Verify chain audit endpoints."""
    response = client.get("/api/v1/chain/status")
    assert response.status_code == 200
    assert "status" in response.json()

    verify_res = client.post("/api/v1/chain/verify")
    assert verify_res.status_code == 200
    assert verify_res.json()["status"] in ["CHAIN_VALID", "CHAIN_EMPTY"]


def test_evidence_generation_and_html(client):
    """Verify full evidence generation and HTML certificate download."""
    # 1. First hash a file to get fingerprint
    file_bytes = b"Evidence certificate payload."
    files = {"file": ("cert.txt", file_bytes, "text/plain")}
    fp_res = client.post("/api/v1/hash/file", files=files)
    fp = fp_res.json()

    # 2. Generate evidence report
    gen_payload = {
        "fingerprint": fp,
        "analyst_notes": "API Integration Test Case",
    }
    rep_res = client.post("/api/v1/evidence/generate", json=gen_payload)
    assert rep_res.status_code == 200
    report = rep_res.json()
    assert "report_id" in report
    assert "evidence_report_hash" in report

    # 3. Retrieve report JSON
    get_res = client.get(f"/api/v1/evidence/{report['report_id']}")
    assert get_res.status_code == 200
    assert get_res.json()["report_id"] == report["report_id"]

    # 4. Retrieve HTML certificate
    html_res = client.get(f"/api/v1/evidence/{report['report_id']}/html")
    assert html_res.status_code == 200
    assert "text/html" in html_res.headers["content-type"]
    assert report["evidence_report_hash"] in html_res.text
