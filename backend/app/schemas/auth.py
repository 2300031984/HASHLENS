"""
HashLens Authentication Schemas
Pydantic data transfer objects for registration, login, token responses, and user profiles.
"""

from typing import Optional
from pydantic import BaseModel, EmailStr, Field, field_validator


class UserRegisterRequest(BaseModel):
    """Payload for user account registration."""
    email: EmailStr = Field(..., description="User's unique email address")
    username: str = Field(..., min_length=3, max_length=50, description="User's unique username")
    password: str = Field(..., min_length=8, description="User's secure password (min 8 characters)")

    @field_validator("username")
    @classmethod
    def validate_username_chars(cls, v: str) -> str:
        cleaned = v.strip()
        if not cleaned:
            raise ValueError("Username cannot be blank")
        return cleaned


class UserLoginRequest(BaseModel):
    """Payload for user authentication login."""
    login: str = Field(..., description="User's registered email address or username")
    password: str = Field(..., description="User's password")


class UserResponse(BaseModel):
    """Safe user profile response representation (never includes passwords or hashes)."""
    id: str
    email: str
    username: str
    is_active: bool
    created_at: str

    model_config = {"from_attributes": True}


class TokenResponse(BaseModel):
    """JWT Access Token response wrapper."""
    access_token: str
    token_type: str = "bearer"
    user: UserResponse
