"""
Unit tests for HashLens Dashboard Architecture & Zero Database Coupling
Ensures that the dashboard operates strictly as an HTTP REST API client.
"""

import pytest
from unittest.mock import patch, MagicMock
from dashboard.utils.api_client import HashLensClient, api_client


def test_dashboard_health_calls_http_backend():
    """Verify that get_health() issues an HTTP GET to /api/v1/health."""
    client = HashLensClient(base_url="http://test-backend:8000/api/v1")
    
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "status": "online",
        "app": "HashLens",
        "version": "1.0.0",
        "environment": "production",
        "uptime_seconds": 120.0,
        "database": "healthy",
        "chain_health": "CHAIN_VALID",
    }

    with patch("requests.get", return_value=mock_resp) as mock_get:
        health = client.get_health()

        mock_get.assert_called_once_with("http://test-backend:8000/api/v1/health", timeout=3)
        assert health["status"] == "online"
        assert health["chain_health"] == "CHAIN_VALID"
        assert health["database"] == "healthy"


def test_dashboard_health_handles_backend_unavailable():
    """Verify get_health() handles HTTP failure safely by returning BACKEND_UNAVAILABLE."""
    client = HashLensClient(base_url="http://non-existent-backend:9999/api/v1")
    
    with patch("requests.get", side_effect=Exception("Connection refused")):
        health = client.get_health()
        assert health["status"] == "BACKEND_UNAVAILABLE"
        assert health["database"] == "UNAVAILABLE"
        assert health["chain_health"] == "CHAIN_UNREACHABLE"
        assert "unreachable" in health.get("error", "").lower()


def test_dashboard_does_not_instantiate_sqlite_or_db_session(monkeypatch):
    """Verify that calling dashboard client methods when API is down never opens or queries SQLite DB."""
    client = HashLensClient(base_url="http://127.0.0.1:9999/api/v1")

    # If SessionLocal were called, monkeypatching it to raise an error would break execution
    def mock_db_error(*args, **kwargs):
        raise RuntimeError("SessionLocal should never be called by dashboard client!")

    monkeypatch.setattr("backend.app.db.database.SessionLocal", mock_db_error, raising=False)

    with patch("requests.get", side_effect=Exception("Connection refused")), \
         patch("requests.post", side_effect=Exception("Connection refused")):
        # All calls should execute safely without calling SessionLocal
        health = client.get_health()
        assert health["status"] == "BACKEND_UNAVAILABLE"

        chain = client.verify_chain()
        assert chain["status"] == "CHAIN_UNREACHABLE"

        records = client.get_chain_records()
        assert records == []

        files = client.get_tracked_files()
        assert files == []

        timeline = client.get_timeline("test-file")
        assert "error" in timeline

        evidence = client.generate_evidence({"filename": "test.txt"})
        assert "error" in evidence


def test_dashboard_obtains_chain_status_from_api_response():
    """Verify chain status comes strictly from API response."""
    client = HashLensClient(base_url="http://test-backend:8000/api/v1")

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "status": "CHAIN_VALID",
        "valid": True,
        "total_records": 10,
        "head_hash": "a" * 64,
    }

    with patch("requests.post", return_value=mock_resp) as mock_post:
        audit = client.verify_chain()

        assert audit["status"] == "CHAIN_VALID"
        assert audit["valid"] is True
        assert audit["head_hash"] == "a" * 64


def test_no_db_or_backend_imports_in_dashboard_modules():
    """Verify no dashboard module imports backend settings, SessionLocal, HashChainService, or DB models."""
    import inspect
    import dashboard.utils.api_client as api_mod

    source = inspect.getsource(api_mod)
    forbidden_terms = [
        "from backend",
        "import backend",
        "backend.app.core.config",
        "settings.",
        "Settings(",
        "JWT_SECRET_KEY",
        "DATABASE_URL",
        "SessionLocal",
        "HashChainService",
        "HistoryService",
        "EvidenceService",
        "ChainRecordModel",
        "sqlite3",
        "create_engine",
    ]

    # Filter out pure comment lines and docstring quotes
    code_lines = [line for line in source.splitlines() if not line.strip().startswith("#")]
    code_text = "\n".join(code_lines)

    for term in forbidden_terms:
        assert term not in code_text, f"Forbidden term '{term}' found in dashboard api_client.py!"


def test_dashboard_imports_cleanly_in_production_without_jwt_secret(monkeypatch):
    """
    Targeted architecture regression test:
    Verifies Streamlit dashboard client initializes under APP_ENV=production
    when JWT_SECRET_KEY and DATABASE_URL are completely absent from environment.
    Must NOT trigger backend Settings validation or raise ValidationError.
    """
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.delenv("JWT_SECRET_KEY", raising=False)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setenv("API_BASE_URL", "https://hashlens-backend.onrender.com")

    client = HashLensClient()
    assert client.base_url == "https://hashlens-backend.onrender.com/api/v1"
    assert client.is_production is True

    health = client.get_health()
    assert health["environment"] == "production"


def test_backend_still_requires_jwt_secret_in_production(monkeypatch):
    """
    Security verification:
    Ensures backend Settings independently enforces JWT_SECRET_KEY validation
    when APP_ENV=production, without weakening security.
    """
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.delenv("JWT_SECRET_KEY", raising=False)

    from pydantic import ValidationError
    from backend.app.core.config import Settings

    with pytest.raises(ValidationError) as exc_info:
        Settings()
    assert "Insecure or missing JWT_SECRET_KEY" in str(exc_info.value)

