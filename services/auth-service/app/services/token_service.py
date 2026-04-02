"""
Token Service — JWT creation, verification, and blacklisting
"""

import os
import hashlib
import hmac
from datetime import datetime, timedelta, timezone
from typing import Optional
from jose import JWTError, jwt
from uuid import UUID
import logging

logger = logging.getLogger(__name__)

JWT_SECRET = os.environ.get("JWT_SECRET", "dev-secret-min-32-bytes-long-xxx")
JWT_ALGO = os.environ.get("JWT_ALGO", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.environ.get("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.environ.get("REFRESH_TOKEN_EXPIRE_DAYS", "30"))


class TokenService:
    """
    Manages JWT tokens: creation, verification, and refresh logic.
    In production, use RS256 and rotate secrets regularly.
    """

    @staticmethod
    def create_access_token(user_id: UUID, expires_delta: Optional[timedelta] = None) -> tuple[str, int]:
        """
        Create a short-lived access token.
        Returns: (token, expires_in_seconds)
        """
        if expires_delta is None:
            expires_delta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

        now = datetime.now(timezone.utc)
        expire = now + expires_delta
        expire_ts = int(expire.timestamp())
        issue_ts = int(now.timestamp())

        payload = {
            "sub": str(user_id),
            "exp": expire_ts,
            "iat": issue_ts,
            "token_type": "access",
        }

        token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)
        expires_in = int(expires_delta.total_seconds())

        logger.info("Created access token for user %s, expires in %d seconds", user_id, expires_in)
        return token, expires_in

    @staticmethod
    def create_refresh_token(user_id: UUID, expires_delta: Optional[timedelta] = None) -> tuple[str, int]:
        """
        Create a long-lived refresh token.
        Returns: (token, expires_in_seconds)
        """
        if expires_delta is None:
            expires_delta = timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)

        now = datetime.now(timezone.utc)
        expire = now + expires_delta
        expire_ts = int(expire.timestamp())
        issue_ts = int(now.timestamp())

        payload = {
            "sub": str(user_id),
            "exp": expire_ts,
            "iat": issue_ts,
            "token_type": "refresh",
        }

        token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)
        expires_in = int(expires_delta.total_seconds())

        logger.info("Created refresh token for user %s, expires in %d seconds", user_id, expires_in)
        return token, expires_in

    @staticmethod
    def hash_token(token: str) -> str:
        """
        Hash a token before storage. Use SHA-256 for comparison.
        This protects the token even if the database is compromised.
        """
        return hashlib.sha256(token.encode()).hexdigest()

    @staticmethod
    def verify_token(token: str) -> dict:
        """
        Verify and decode a JWT token.
        Raises JWTError if invalid or expired.
        """
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
            return payload
        except JWTError as exc:
            logger.warning("Token verification failed: %s", exc)
            raise

    @staticmethod
    def verify_token_type(token: str, expected_type: str) -> bool:
        """
        Verify that the token is the expected type (access or refresh).
        """
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
            return payload.get("token_type") == expected_type
        except JWTError:
            return False

    @staticmethod
    def get_user_id_from_token(token: str) -> Optional[UUID]:
        """
        Extract user_id from token without full verification.
        Used for debugging/logging only.
        """
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
            return UUID(payload.get("sub"))
        except (JWTError, ValueError):
            return None
