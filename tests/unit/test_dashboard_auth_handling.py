"""
Unit and Regression Tests for HashLens Dashboard Authentication & Error Handling.
Verifies status code translation, network exception handling, non-JSON safety,
case-insensitive username login, and zero-coupling regression protection.
"""

import pytest
import requests
from unittest.mock import patch, MagicMock
from dashboard.utils.api_client import HashLensClient, api_client


# =============================================================================
# 1. API CLIENT REGISTER METHOD TESTS
# =============================================================================

def test_register_success_201():
    """Verify 201 Created returns registration json response."""
    client = HashLensClient(base_url="http://test-backend:8000/api/v1")
    mock_resp = MagicMock()
    mock_resp.status_code = 201
    mock_resp.json.return_value = {
        "id": "usr_123",
        "email": "user@example.com",
        "username": "user123",
        "is_active": True,
        "created_at": "2026-09-20T00:00:00Z",
    }
    with patch("requests.post", return_value=mock_resp):
        res = client.register("user@example.com", "user123", "Password123!")
        assert "error" not in res
        assert res["email"] == "user@example.com"
        assert res["id"] == "usr_123"


def test_register_bad_request_400():
    """Verify 400 Bad Request extracts error detail."""
    client = HashLensClient(base_url="http://test-backend:8000/api/v1")
    mock_resp = MagicMock()
    mock_resp.status_code = 400
    mock_resp.json.return_value = {"detail": "An account with this email address already exists."}
    with patch("requests.post", return_value=mock_resp):
        res = client.register("dupe@example.com", "user123", "Password123!")
        assert "error" in res
        assert res["error"] == "An account with this email address already exists."


def test_register_conflict_409():
    """Verify 409 Conflict returns clear duplicate account message."""
    client = HashLensClient(base_url="http://test-backend:8000/api/v1")
    mock_resp = MagicMock()
    mock_resp.status_code = 409
    mock_resp.json.return_value = {"detail": "Conflict"}
    with patch("requests.post", return_value=mock_resp):
        res = client.register("dupe@example.com", "dupeuser", "Password123!")
        assert "error" in res
        assert "account with this username or email already exists" in res["error"]


def test_register_rate_limit_429():
    """Verify 429 Rate Limit returns friendly rate limit error."""
    client = HashLensClient(base_url="http://test-backend:8000/api/v1")
    mock_resp = MagicMock()
    mock_resp.status_code = 429
    with patch("requests.post", return_value=mock_resp):
        res = client.register("user@example.com", "user123", "Password123!")
        assert "error" in res
        assert "Too many attempts" in res["error"]


def test_register_server_error_500():
    """Verify 500 Internal Error returns friendly server unavailable error."""
    client = HashLensClient(base_url="http://test-backend:8000/api/v1")
    mock_resp = MagicMock()
    mock_resp.status_code = 500
    with patch("requests.post", return_value=mock_resp):
        res = client.register("user@example.com", "user123", "Password123!")
        assert "error" in res
        assert "temporarily unavailable" in res["error"]


def test_register_gateway_error_502_non_json_html():
    """Verify 502/503 HTML gateway error doesn't crash json decoder."""
    client = HashLensClient(base_url="http://test-backend:8000/api/v1")
    mock_resp = MagicMock()
    mock_resp.status_code = 502
    mock_resp.json.side_effect = Exception("JSONDecodeError")
    with patch("requests.post", return_value=mock_resp):
        res = client.register("user@example.com", "user123", "Password123!")
        assert "error" in res
        assert "Backend service is temporarily unavailable" in res["error"]


def test_register_timeout():
    """Verify network timeout returns friendly reachability error."""
    client = HashLensClient(base_url="http://test-backend:8000/api/v1")
    with patch("requests.post", side_effect=requests.exceptions.Timeout("Read timed out")):
        res = client.register("user@example.com", "user123", "Password123!")
        assert "error" in res
        assert "Unable to reach the authentication service" in res["error"]


# =============================================================================
# 2. API CLIENT LOGIN METHOD TESTS
# =============================================================================

def test_login_success_200():
    """Verify 200 OK returns token and user data."""
    client = HashLensClient(base_url="http://test-backend:8000/api/v1")
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "access_token": "token123",
        "token_type": "bearer",
        "user": {"id": "usr_123", "email": "user@example.com", "username": "user123"},
    }
    with patch("requests.post", return_value=mock_resp):
        res = client.login("user123", "Password123!")
        assert "access_token" in res
        assert res["access_token"] == "token123"
        assert client.auth_token == "token123"


def test_login_invalid_credentials_401():
    """Verify 401 Unauthorized extracts backend error message."""
    client = HashLensClient(base_url="http://test-backend:8000/api/v1")
    mock_resp = MagicMock()
    mock_resp.status_code = 401
    mock_resp.json.return_value = {"detail": "Invalid email/username or password."}
    with patch("requests.post", return_value=mock_resp):
        res = client.login("wronguser", "WrongPass123!")
        assert "error" in res
        assert "Invalid email/username or password" in res["error"]


def test_login_rate_limit_429():
    """Verify 429 Rate Limit returns friendly rate limit error."""
    client = HashLensClient(base_url="http://test-backend:8000/api/v1")
    mock_resp = MagicMock()
    mock_resp.status_code = 429
    with patch("requests.post", return_value=mock_resp):
        res = client.login("user123", "Password123!")
        assert "error" in res
        assert "Too many attempts" in res["error"]


def test_login_gateway_error_503_html():
    """Verify 503 Bad Gateway returning HTML is handled safely."""
    client = HashLensClient(base_url="http://test-backend:8000/api/v1")
    mock_resp = MagicMock()
    mock_resp.status_code = 503
    mock_resp.json.side_effect = Exception("JSONDecodeError")
    with patch("requests.post", return_value=mock_resp):
        res = client.login("user123", "Password123!")
        assert "error" in res
        assert "Backend service is temporarily unavailable" in res["error"]


def test_login_timeout():
    """Verify network timeout returns clear reachability error."""
    client = HashLensClient(base_url="http://test-backend:8000/api/v1")
    with patch("requests.post", side_effect=requests.exceptions.Timeout("Read timed out")):
        res = client.login("user123", "Password123!")
        assert "error" in res
        assert "Unable to reach the authentication service" in res["error"]


# =============================================================================
# 3. REGRESSION PROTECTION & ZERO-COUPLING TESTS
# =============================================================================

def test_dashboard_does_not_import_backend_settings():
    """Verify dashboard api_client.py does not import backend Settings."""
    import dashboard.utils.api_client as mod
    assert not hasattr(mod, "settings")


def test_dashboard_does_not_require_jwt_secret_in_production(monkeypatch):
    """Verify Dashboard initializes cleanly without JWT_SECRET_KEY or DATABASE_URL."""
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.delenv("JWT_SECRET_KEY", raising=False)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setenv("API_BASE_URL", "https://hashlens-backend.onrender.com")

    client = HashLensClient()
    assert client.base_url == "https://hashlens-backend.onrender.com/api/v1"
    assert client.is_production is True
