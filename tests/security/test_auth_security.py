"""
Security Test Suite for HashLens Authentication & Password Infrastructure.
Verifies Argon2id password hashing, non-exposure of credentials, JWT signature/expiration security,
inactive user protection, and production key enforcement.
"""

from datetime import timedelta
import pytest
import jwt
from backend.app.core.auth_security import create_access_token, decode_access_token, hash_password, verify_password
from backend.app.core.config import Settings
from backend.app.models.models import UserModel
from tests.conftest import TestingSessionLocal


def test_argon2id_password_hashing():
    """Verify password hashing uses Argon2id and produces non-plaintext hashes."""
    pwd = "MySecretForensicPassword2026!"
    hashed = hash_password(pwd)

    # Must be Argon2id format
    assert hashed.startswith("$argon2id$")
    assert pwd not in hashed
    assert verify_password(pwd, hashed) is True
    assert verify_password("WrongPassword!", hashed) is False


def test_jwt_token_claims_and_signature_security():
    """Verify JWT contains only sub, iat, exp and rejects tampered signature."""
    user_id = "usr_test123"
    token = create_access_token(user_id=user_id)

    # Decode without verification to inspect claims
    unverified = jwt.decode(token, options={"verify_signature": False})
    assert unverified["sub"] == user_id
    assert "iat" in unverified
    assert "exp" in unverified
    assert "password" not in unverified
    assert "password_hash" not in unverified

    # Verify signature decoding
    decoded = decode_access_token(token)
    assert decoded["sub"] == user_id

    # Tampered token signature must fail
    tampered_token = token[:-4] + "ABCD"
    with pytest.raises(jwt.PyJWTError):
        decode_access_token(tampered_token)


def test_jwt_expired_token_rejection(client):
    """Verify expired JWT token returns HTTP 401 Unauthorized."""
    user_id = "usr_expired_test"
    expired_token = create_access_token(user_id=user_id, expires_delta=timedelta(seconds=-10))

    res = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {expired_token}"},
    )
    assert res.status_code == 401
    assert "expired" in res.json()["detail"].lower()


def test_inactive_user_authentication_rejection(client):
    """Verify inactive user accounts are denied authentication."""
    # 1. Register user
    reg_res = client.post("/api/v1/auth/register", json={
        "email": "inactive@hashlens.sec",
        "username": "inactive_user",
        "password": "Password123!",
    })
    user_id = reg_res.json()["id"]

    # 2. Set is_active = False in DB
    db = TestingSessionLocal()
    user = db.query(UserModel).filter(UserModel.id == user_id).first()
    user.is_active = False
    db.commit()
    db.close()

    # 3. Attempt login -> 401
    login_res = client.post("/api/v1/auth/login", json={
        "login": "inactive_user",
        "password": "Password123!",
    })
    assert login_res.status_code == 401
    assert "inactive" in login_res.json()["detail"].lower()


def test_production_environment_jwt_secret_validation():
    """Verify production mode fails safely if JWT secret is insecure or missing."""
    with pytest.raises(ValueError, match="Insecure or missing JWT_SECRET_KEY in production mode"):
        Settings(
            APP_ENV="production",
            JWT_SECRET_KEY="dev-secret-key-change-in-production-123456789",
        )

    with pytest.raises(ValueError, match="Insecure or missing JWT_SECRET_KEY in production mode"):
        Settings(
            APP_ENV="production",
            JWT_SECRET_KEY="short",
        )
