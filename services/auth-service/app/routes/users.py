"""
User routes — /me, /change-password
"""

import logging
from fastapi import APIRouter, HTTPException, status, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from uuid import UUID

from ..models import User
from ..schemas import MeResponse, ChangePasswordRequest, UserResponse
from ..services.password_service import PasswordService
from ..db import get_async_session

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/users", tags=["users"])


async def get_current_user(token: str, session: AsyncSession = Depends(get_async_session)) -> User:
    """
    Dependency: extract user from JWT token.
    In a real app, this would be in middleware and use FastAPI's Security.
    """
    # This is simplified; in production, use fastapi.security.HTTPBearer
    from ..services.token_service import TokenService
    try:
        payload = TokenService.verify_token(token)
        user_id = UUID(payload.get("sub"))
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials"
        )

    result = await session.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive"
        )

    return user


@router.get("/me", response_model=MeResponse)
async def get_current_user_info(current_user: User = Depends(get_current_user)):
    """
    Get current user's profile.
    """
    return MeResponse.from_orm(current_user)


@router.post("/change-password", status_code=status.HTTP_204_NO_CONTENT)
async def change_password(
    req: ChangePasswordRequest,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_async_session)
):
    """
    Change user password.
    Requires old password for verification.
    """
    # Verify old password
    if not PasswordService.verify_password(req.old_password, current_user.password_hash):
        logger.warning("Password change failed for %s: incorrect old password", current_user.email)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect password"
        )

    # Hash new password
    new_hash = PasswordService.hash_password(req.new_password)

    # Update
    current_user.password_hash = new_hash
    await session.commit()

    logger.info("Password changed for user %s", current_user.email)
    return None
