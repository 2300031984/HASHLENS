"""
HashLens Authentication Routes
REST API endpoints for user registration, Argon2id login authentication, profile retrieval, and session termination.
"""

import uuid
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from backend.app.api.deps import get_current_user
from backend.app.core.auth_security import create_access_token, hash_password, verify_password
from backend.app.db.database import get_db
from backend.app.models.models import UserModel
from backend.app.schemas.auth import TokenResponse, UserLoginRequest, UserRegisterRequest, UserResponse

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register_user(payload: UserRegisterRequest, db: Session = Depends(get_db)):
    """
    Registers a new user account with unique email and username.
    Hashes password securely using Argon2id.
    """
    email_clean = payload.email.strip().lower()
    username_clean = payload.username.strip()

    # Check duplicate email or username
    existing_user = db.query(UserModel).filter(
        or_(UserModel.email == email_clean, func.lower(UserModel.username) == username_clean.lower())
    ).first()

    if existing_user:
        if existing_user.email == email_clean:
            detail = "An account with this email address already exists."
        else:
            detail = "An account with this username already exists."
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)

    user_id = f"usr_{uuid.uuid4().hex}"
    now_str = datetime.now(timezone.utc).isoformat()
    hashed_pwd = hash_password(payload.password)

    new_user = UserModel(
        id=user_id,
        email=email_clean,
        username=username_clean,
        password_hash=hashed_pwd,
        is_active=True,
        created_at=now_str,
        updated_at=now_str,
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return new_user


@router.post("/login", response_model=TokenResponse)
def login_user(payload: UserLoginRequest, db: Session = Depends(get_db)):
    """
    Authenticates user using email or username + password.
    Issues a signed JWT access token on success.
    """
    login_id = payload.login.strip().lower()
    
    user = db.query(UserModel).filter(
        or_(
            UserModel.email == login_id,
            func.lower(UserModel.username) == login_id,
        )
    ).first()

    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email/username or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is inactive. Authentication denied.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = create_access_token(user_id=user.id)
    return TokenResponse(
        access_token=token,
        token_type="bearer",
        user=UserResponse.model_validate(user),
    )


@router.get("/me", response_model=UserResponse)
def get_current_user_profile(current_user: UserModel = Depends(get_current_user)):
    """
    Returns authenticated user profile information for the valid Bearer token.
    Never exposes passwords or password hashes.
    """
    return current_user


@router.post("/logout")
def logout_user():
    """
    Logs out the current session.
    Client clears stored authentication token.
    """
    return {"message": "Successfully logged out"}
