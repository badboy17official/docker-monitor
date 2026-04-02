"""
Password Service — Bcrypt hashing and verification
"""

from passlib.context import CryptContext
import logging

logger = logging.getLogger(__name__)

# Bcrypt with cost factor 12 (slow enough to resist brute force, fast enough for login)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__rounds=12)


class PasswordService:
    """Secure password hashing and comparison."""

    @staticmethod
    def hash_password(password: str) -> str:
        """
        Hash a plaintext password using bcrypt.
        Never store plaintext passwords.
        """
        return pwd_context.hash(password)

    @staticmethod
    def verify_password(password: str, password_hash: str) -> bool:
        """
        Verify that a plaintext password matches the stored hash.
        Uses constant-time comparison to resist timing attacks.
        """
        try:
            return pwd_context.verify(password, password_hash)
        except Exception as exc:
            logger.warning("Password verification error: %s", exc)
            return False

    @staticmethod
    def get_password_hash(password: str) -> str:
        """
        Alias for hash_password for clarity.
        """
        return PasswordService.hash_password(password)
