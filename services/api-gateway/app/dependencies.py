"""
API Gateway dependencies (shared across routers)
"""

from fastapi import Depends, HTTPException, status
from uuid import UUID


async def get_current_user(request) -> UUID:
    """
    Dependency to get the current user from JWT middleware.
    """
    if not hasattr(request.state, "user_id"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated"
        )
    return request.state.user_id
