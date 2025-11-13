"""
CRUD operations for VotingToken model
"""

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, delete
from sqlalchemy.orm import selectinload
from app.models.electorates import VotingToken
from app.schemas.electorates import VotingTokenCreate
from typing import List, Optional
import uuid
import hashlib
from datetime import datetime, timezone


async def create_voting_token(
    db: AsyncSession, token_data: VotingTokenCreate, token: str, expires_at: datetime
) -> VotingToken:
    """Create a new voting token record"""

    # Normalize token for consistent hashing (remove hyphens/spaces and uppercase)
    clean_token = token.replace("-", "").replace(" ", "").upper()
    token_hash = hashlib.sha256(clean_token.encode()).hexdigest()

    db_token = VotingToken(
        electorate_id=token_data.electorate_id,
        token_hash=token_hash,
        device_fingerprint=token_data.device_fingerprint,
        device_info=token_data.device_info.model_dump(),
        location_data=(
            token_data.location_data.model_dump() if token_data.location_data else None
        ),
        ip_address="",  # Will be set by the calling function
        user_agent="",  # Will be set by the calling function
        biometric_data_hash=(
            hashlib.sha256(token_data.biometric_data.encode()).hexdigest()
            if token_data.biometric_data
            else None
        ),
        device_password_hash=(
            hashlib.sha256(token_data.device_password.encode()).hexdigest()
            if token_data.device_password
            else None
        ),
        expires_at=expires_at,
    )

    db.add(db_token)
    await db.commit()
    await db.refresh(db_token)
    return db_token


async def get_voting_token_by_hash(
    db: AsyncSession, token_hash: str
) -> Optional[VotingToken]:
    """Get voting token by hash"""
    result = await db.execute(
        select(VotingToken)
        .options(selectinload(VotingToken.electorate))
        .where(VotingToken.token_hash == token_hash)
    )
    return result.scalar_one_or_none()


async def get_voting_token_by_id(
    db: AsyncSession, token_id: uuid.UUID
) -> Optional[VotingToken]:
    """Get voting token by ID"""
    result = await db.execute(
        select(VotingToken)
        .options(selectinload(VotingToken.electorate))
        .where(VotingToken.id == token_id)
    )
    return result.scalar_one_or_none()


async def get_active_voting_tokens_by_electorate(
    db: AsyncSession, electorate_id: uuid.UUID
) -> List[VotingToken]:
    """Get all active voting tokens for an electorate"""
    result = await db.execute(
        select(VotingToken).where(
            VotingToken.electorate_id == electorate_id,
            VotingToken.is_active == True,
            VotingToken.revoked == False,
            VotingToken.expires_at > datetime.now(timezone.utc),
        )
    )
    return result.scalars().all()


async def update_token_usage(
    db: AsyncSession, token_id: uuid.UUID
) -> Optional[VotingToken]:
    """Update token usage count and last used timestamp"""
    result = await db.execute(select(VotingToken).where(VotingToken.id == token_id))
    token = result.scalar_one_or_none()

    if token:
        token.usage_count += 1
        token.last_used_at = datetime.now(timezone.utc)
        await db.commit()
        await db.refresh(token)

    return token


async def revoke_voting_token(
    db: AsyncSession, token_id: uuid.UUID, reason: str = "Manual revocation"
) -> bool:
    """Revoke a voting token"""
    result = await db.execute(select(VotingToken).where(VotingToken.id == token_id))
    token = result.scalar_one_or_none()

    if token:
        token.revoked = True
        token.revoked_at = datetime.now(timezone.utc)
        token.revoked_reason = reason
        token.is_active = False
        await db.commit()
        return True

    return False


async def revoke_all_tokens_for_electorate(
    db: AsyncSession, electorate_id: uuid.UUID, reason: str = "Electorate revocation"
) -> int:
    """Revoke all tokens for an electorate"""
    result = await db.execute(
        update(VotingToken)
        .where(VotingToken.electorate_id == electorate_id, VotingToken.revoked == False)
        .values(
            revoked=True,
            revoked_at=datetime.now(timezone.utc),
            revoked_reason=reason,
            is_active=False,
        )
    )
    await db.commit()
    return result.rowcount


async def cleanup_expired_tokens(db: AsyncSession) -> int:
    """Clean up expired tokens"""
    result = await db.execute(
        delete(VotingToken).where(VotingToken.expires_at < datetime.now(timezone.utc))
    )
    await db.commit()
    return result.rowcount


async def get_token_statistics(db: AsyncSession) -> dict:
    """Get token usage statistics"""
    from sqlalchemy import func

    # Total tokens
    total_result = await db.execute(select(func.count(VotingToken.id)))
    total_tokens = total_result.scalar()

    # Active tokens
    active_result = await db.execute(
        select(func.count(VotingToken.id)).where(
            VotingToken.is_active == True,
            VotingToken.revoked == False,
            VotingToken.expires_at > datetime.now(timezone.utc),
        )
    )
    active_tokens = active_result.scalar()

    # Revoked tokens
    revoked_result = await db.execute(
        select(func.count(VotingToken.id)).where(VotingToken.revoked == True)
    )
    revoked_tokens = revoked_result.scalar()

    # Expired tokens
    expired_result = await db.execute(
        select(func.count(VotingToken.id)).where(
            VotingToken.expires_at < datetime.now(timezone.utc)
        )
    )
    expired_tokens = expired_result.scalar()

    return {
        "total_tokens": total_tokens,
        "active_tokens": active_tokens,
        "revoked_tokens": revoked_tokens,
        "expired_tokens": expired_tokens,
    }
