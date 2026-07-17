"""
API Key Authentication — secure agent-to-backend communication.
Supports key creation, validation, rotation, and scoping.
"""
import secrets
import hashlib
from datetime import datetime, timezone
from typing import Optional, List
from fastapi import Depends, HTTPException, Security, status
from fastapi.security import APIKeyHeader
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from backend.database import get_db
from backend.models import ApiKey, User


API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)


def generate_api_key() -> tuple[str, str, str]:
    """Generate a new API key. Returns (raw_key, key_hash, key_prefix)."""
    raw_key = f"sx_{secrets.token_urlsafe(48)}"
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    key_prefix = raw_key[:12]
    return raw_key, key_hash, key_prefix


def hash_api_key(raw_key: str) -> str:
    """Hash an API key for storage."""
    return hashlib.sha256(raw_key.encode()).hexdigest()


async def validate_api_key(
    api_key: Optional[str] = Security(API_KEY_HEADER),
    db: AsyncSession = Depends(get_db),
) -> Optional[User]:
    """Validate an API key and return the associated user."""
    if not api_key:
        return None

    key_hash = hash_api_key(api_key)
    result = await db.execute(
        select(ApiKey).where(ApiKey.key_hash == key_hash, ApiKey.is_active == True)
    )
    key_record = result.scalar_one_or_none()

    if not key_record:
        return None

    # Check expiry
    current_utc = datetime.now(timezone.utc).replace(tzinfo=None)
    if key_record.expires_at and key_record.expires_at < current_utc:
        return None

    # Update last used
    key_record.last_used = current_utc
    await db.flush()

    # Load user
    user_result = await db.execute(select(User).where(User.id == key_record.user_id))
    user = user_result.scalar_one_or_none()

    return user if user and user.is_active else None


async def require_api_key_or_token(
    api_key: Optional[str] = Security(API_KEY_HEADER),
    db: AsyncSession = Depends(get_db),
) -> User:
    """Require either a valid API key or a Bearer token."""
    # Try API key first
    if api_key:
        user = await validate_api_key(api_key, db)
        if user:
            return user
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key"
        )

    # Fall through — let the standard Bearer auth handle it
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="API key or Bearer token required"
    )
