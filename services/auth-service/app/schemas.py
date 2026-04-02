"""
Pydantic schemas for request/response validation
"""

from pydantic import BaseModel, EmailStr, Field
from datetime import datetime
from typing import Optional
from uuid import UUID


class UserBase(BaseModel):
    email: EmailStr
    name: Optional[str] = None
    role: str = Field(default="viewer", pattern="^(admin|engineer|viewer)$")


class UserRegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=128)
    name: str = Field(..., min_length=2, max_length=255)


class UserResponse(UserBase):
    id: UUID
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds
    refresh_token: str


class RefreshTokenRequest(BaseModel):
    refresh_token: str


class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str = Field(..., min_length=8, max_length=128)


class MeResponse(UserResponse):
    pass


class TokenPayload(BaseModel):
    """JWT claim payload"""
    sub: UUID  # user_id
    exp: int
    iat: int
    token_type: str  # 'access' or 'refresh'
