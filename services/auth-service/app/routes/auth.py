"""
Auth routes — register, login, refresh, logout
"""

import logging
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, HTTPException, status, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import os

from ..models import User, RefreshToken
from ..schemas import (
    UserRegisterRequest, UserResponse, LoginRequest, TokenResponse,
    RefreshTokenRequest, ChangePasswordRequest
)
from ..services.token_service import TokenService
from ..services.password_service import PasswordService
from ..db import get_async_session

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth", tags=["auth"])

REFRESH_TOKEN_EXPIRE_DAYS = int(os.environ.get("REFRESH_TOKEN_EXPIRE_DAYS", "30"))


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(req: UserRegisterRequest, session: AsyncSession = Depends(get_async_session)):
    """
    Register a new user.
    
    **Request**
    ```json
    {
      "email": "user@example.com",
      "password": "StrongP@ss1",
      "name": "John Doe"
    }
    ```
    
    **Response 201**
    ```json
    {
      "id": "uuid",
      "email": "user@example.com",
      "name": "John Doe",
      "role": "viewer",
      "is_active": true,
      "created_at": "2025-01-01T00:00:00Z"
    }
    ```
    """
    # Check if user already exists
    result = await session.execute(select(User).where(User.email == req.email))
    if result.scalar_one_or_none():
        logger.warning("Registration attempt with existing email: %s", req.email)
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered"
        )

    # Hash password
    password_hash = PasswordService.hash_password(req.password)

    # Create user
    new_user = User(
        email=req.email,
        password_hash=password_hash,
        name=req.name,
        role="viewer"  # default role
    )
    session.add(new_user)
    await session.commit()
    await session.refresh(new_user)

    logger.info("New user registered: %s", req.email)
    return UserResponse.from_orm(new_user)


@router.post("/login", response_model=TokenResponse)
async def login(req: LoginRequest, session: AsyncSession = Depends(get_async_session)):
    """
    Login and receive JWT token pair.
    
    **Request**
    ```json
    {
      "email": "user@example.com",
      "password": "StrongP@ss1"
    }
    ```
    
    **Response 200**
    ```json
    {
      "access_token": "<jwt>",
      "token_type": "bearer",
      "expires_in": 900,
      "refresh_token": "<opaque-token>"
    }
    ```
    """
    # Fetch user
    result = await session.execute(select(User).where(User.email == req.email))
    user = result.scalar_one_or_none()

    if not user:
        logger.warning("Login failed: user not found (%s)", req.email)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        )

    # Check if account is locked (brute force protection)
    if user.locked_until and user.locked_until > datetime.now(timezone.utc):
        logger.warning("Login attempt for locked account: %s", req.email)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Account temporarily locked. Try again later."
        )

    # Verify password
    if not PasswordService.verify_password(req.password, user.password_hash):
        # Increment failed login attempts
        user.failed_login_attempts += 1
        if user.failed_login_attempts >= 5:
            user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=15)
            logger.warning("Account locked due to failed login attempts: %s", req.email)
        await session.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        )

    # Reset failed login attempts on successful login
    user.failed_login_attempts = 0
    user.locked_until = None
    await session.commit()

    # Create tokens
    access_token, access_expires = TokenService.create_access_token(user.id)
    refresh_token, refresh_expires = TokenService.create_refresh_token(user.id)

    # Store refresh token hash in database
    token_hash = TokenService.hash_token(refresh_token)
    db_refresh_token = RefreshToken(
        user_id=user.id,
        token_hash=token_hash,
        expires_at=datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    )
    session.add(db_refresh_token)
    await session.commit()

    logger.info("User logged in: %s", req.email)

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=access_expires,
        refresh_token=refresh_token
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh(req: RefreshTokenRequest, session: AsyncSession = Depends(get_async_session)):
    """
    Use a refresh token to obtain a new access token.
    Implements token rotation: old refresh token is revoked, new one issued.
    """
    # Verify refresh token
    try:
        payload = TokenService.verify_token(req.refresh_token)
        if payload.get("token_type") != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type"
            )
        user_id = payload.get("sub")
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )

    # Check that token is in database and not revoked
    token_hash = TokenService.hash_token(req.refresh_token)
    result = await session.execute(
        select(RefreshToken).where(
            RefreshToken.token_hash == token_hash,
            RefreshToken.revoked == False
        )
    )
    db_token = result.scalar_one_or_none()

    if not db_token or db_token.expires_at < datetime.now(timezone.utc):
        logger.warning("Refresh token not found or expired")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token invalid or expired"
        )

    # Revoke old token (token rotation)
    db_token.revoked = True
    await session.commit()

    # Create new tokens
    access_token, access_expires = TokenService.create_access_token(UUID(user_id))
    refresh_token, _ = TokenService.create_refresh_token(UUID(user_id))

    # Store new refresh token
    new_token_hash = TokenService.hash_token(refresh_token)
    new_db_token = RefreshToken(
        user_id=UUID(user_id),
        token_hash=new_token_hash,
        expires_at=datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    )
    session.add(new_db_token)
    await session.commit()

    logger.info("Refresh token used for user %s", user_id)

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=access_expires,
        refresh_token=refresh_token
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(token: str, session: AsyncSession = Depends(get_async_session)):
    """
    Logout by revoking the refresh token.
    Access tokens will continue to work until expiration (short-lived, so acceptable).
    """
    # Note: In a real implementation, you'd extract the token from the request header
    # This is a simplified version for documentation
    token_hash = TokenService.hash_token(token)

    result = await session.execute(
        select(RefreshToken).where(RefreshToken.token_hash == token_hash)
    )
    db_token = result.scalar_one_or_none()

    if db_token:
        db_token.revoked = True
        await session.commit()
        logger.info("User logged out")

    return None


from uuid import UUID
