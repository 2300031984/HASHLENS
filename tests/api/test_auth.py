"""
API Test Suite for HashLens Authentication.
Verifies user registration, duplicate rejection, login, JWT issuance, profile retrieval, and logout.
"""

import pytest
from fastapi.testclient import TestClient
from backend.app.main import app
from tests.conftest import TestingSessionLocal
from backend.app.models.models import UserModel


def test_user_registration_success(client):
    """Verify new user registration creates account and returns safe profile."""
    payload = {
        "email": "analyst@hashlens.sec",
        "username": "forensic_analyst",
        "password": "SecurePassword123!",
    }
    res = client.post("/api/v1/auth/register", json=payload)
    assert res.status_code == 201
    data = res.json()
    assert data["email"] == "analyst@hashlens.sec"
    assert data["username"] == "forensic_analyst"
    assert data["is_active"] is True
    assert "id" in data
    assert "password" not in data
    assert "password_hash" not in data


def test_user_registration_duplicate_rejection(client):
    """Verify duplicate email or username is rejected with HTTP 400."""
    payload = {
        "email": "dupe@hashlens.sec",
        "username": "dupe_user",
        "password": "Password123!",
    }
    res1 = client.post("/api/v1/auth/register", json=payload)
    assert res1.status_code == 201

    # Same email
    res2 = client.post("/api/v1/auth/register", json={
        "email": "dupe@hashlens.sec",
        "username": "different_user",
        "password": "Password123!",
    })
    assert res2.status_code == 400
    assert "email address already exists" in res2.json()["detail"]

    # Same username
    res3 = client.post("/api/v1/auth/register", json={
        "email": "another@hashlens.sec",
        "username": "dupe_user",
        "password": "Password123!",
    })
    assert res3.status_code == 400
    assert "username already exists" in res3.json()["detail"]


def test_user_login_success(client):
    """Verify login with email or username returns signed JWT access token and user info."""
    reg_payload = {
        "email": "auth_test@hashlens.sec",
        "username": "auth_user",
        "password": "MySecretPassword123",
    }
    client.post("/api/v1/auth/register", json=reg_payload)

    # Login with email
    res_email = client.post("/api/v1/auth/login", json={
        "login": "auth_test@hashlens.sec",
        "password": "MySecretPassword123",
    })
    assert res_email.status_code == 200
    token_data = res_email.json()
    assert "access_token" in token_data
    assert token_data["token_type"] == "bearer"
    assert token_data["user"]["email"] == "auth_test@hashlens.sec"

    # Login with username
    res_user = client.post("/api/v1/auth/login", json={
        "login": "auth_user",
        "password": "MySecretPassword123",
    })
    assert res_user.status_code == 200
    assert "access_token" in res_user.json()


def test_user_login_invalid_credentials(client):
    """Verify login fails safely with HTTP 401 for wrong password or unknown user."""
    res_unknown = client.post("/api/v1/auth/login", json={
        "login": "nonexistent@hashlens.sec",
        "password": "WrongPassword123",
    })
    assert res_unknown.status_code == 401
    assert "Invalid email/username or password" in res_unknown.json()["detail"]


def test_auth_me_endpoint_and_logout(client):
    """Verify GET /auth/me returns current user profile for valid token, rejects missing token."""
    # 1. Register & login
    client.post("/api/v1/auth/register", json={
        "email": "profile_user@hashlens.sec",
        "username": "profile_user",
        "password": "Password123!",
    })
    login_res = client.post("/api/v1/auth/login", json={
        "login": "profile_user",
        "password": "Password123!",
    })
    token = login_res.json()["access_token"]

    # 2. Unauthenticated request -> 401
    res_no_auth = client.get("/api/v1/auth/me")
    assert res_no_auth.status_code == 401

    # 3. Authenticated request -> 200
    res_auth = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res_auth.status_code == 200
    profile = res_auth.json()
    assert profile["email"] == "profile_user@hashlens.sec"
    assert profile["username"] == "profile_user"

    # 4. Logout
    res_logout = client.post("/api/v1/auth/logout")
    assert res_logout.status_code == 200
