"""Authentication service.

Handles password hashing, verification, and JWT token generation.
"""

import os
from datetime import datetime, timezone, timedelta

import bcrypt
import jwt

SECRET_KEY = os.getenv("JWT_SECRET", "change-me-in-production-echobase-threat-intel")
ALGORITHM = "HS256"
TOKEN_EXPIRY_HOURS = int(os.getenv("TOKEN_EXPIRY_HOURS", "72"))


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))


def create_token(user_id: int, email: str) -> str:
    payload = {
        "sub": str(user_id),
        "email": email,
        "exp": datetime.now(timezone.utc) + timedelta(hours=TOKEN_EXPIRY_HOURS),
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> dict:
    """Decode and validate a JWT token. Raises jwt.PyJWTError on failure."""
    return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
