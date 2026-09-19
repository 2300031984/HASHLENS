"""
HashLens Authentication Security Helpers
Provides Argon2id password hashing, password verification, and JWT access token creation and decoding.
"""

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional
import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

from backend.app.core.config import settings

# Initialize Argon2id password hasher
ph = PasswordHasher()


def hash_password(password: str) -> str:
    """
    Hashes plaintext password using Argon2id algorithm.
    Never uses MD5/SHA-1/SHA-256 for password security.
    """
    return ph.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """
    Verifies a plaintext password against an Argon2id hash.
    Returns True if valid, False otherwise.
    """
    try:
        return ph.verify(password_hash, password)
    except (VerifyMismatchError, InvalidHashError):
        return False


def create_access_token(user_id: str, expires_delta: Optional[timedelta] = None) -> str:
    """
    Creates a signed JWT access token containing only minimal required claims (sub, iat, exp).
    Never embeds passwords or sensitive data in JWT claims.
    """
    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    payload = {
        "sub": str(user_id),
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
    }

    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def decode_access_token(token: str) -> Dict[str, Any]:
    """
    Decodes and validates JWT token signature and expiration.
    Raises jwt.PyJWTError (e.g. ExpiredSignatureError, InvalidTokenError) if invalid.
    """
    return jwt.decode(
        token,
        settings.JWT_SECRET_KEY,
        algorithms=[settings.JWT_ALGORITHM],
    )
