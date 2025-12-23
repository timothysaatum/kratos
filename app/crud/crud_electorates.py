from datetime import datetime, timezone
from uuid import UUID
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models.electorates import Electorate
from app.schemas.electorates import ElectorateCreate, ElectorateUpdate
from sqlalchemy.orm import selectinload
from typing import List, Optional
import hashlib
import secrets


def hash_voting_pin(voting_pin: str) -> str:
    """Hash a voting pin using SHA-256 with salt"""
    if not voting_pin:
        return ""
    salt = secrets.token_hex(16)
    hashed = hashlib.sha256((voting_pin + salt).encode()).hexdigest()
    return f"{salt}:{hashed}"


async def get_electorate_by_student_id(
    db: AsyncSession, student_id: str
) -> Optional[Electorate]:
    result = await db.execute(
        select(Electorate)
        .options(selectinload(Electorate.voting_tokens))
        .where(Electorate.student_id == student_id)
    )
    return result.scalar_one_or_none()


async def get_electorates(
    db: AsyncSession, skip: int = 0, limit: int = 100
) -> List[Electorate]:
    # result = await db.execute(
    #     select(Electorate)
    #     .options(selectinload(Electorate.voting_tokens))
    #     .where(Electorate.is_deleted == False)
    #     .offset(skip)
    #     .limit(limit)
    # )
    # return result.scalars().all()
    result = await db.execute(
        select(Electorate)
        .options(selectinload(Electorate.voting_tokens))
        .where(Electorate.is_deleted == False)
        .offset(skip)
        .limit(limit)
    )
    electorates = result.scalars().all()
    
    now = datetime.now(timezone.utc)
    
    response = []
    for electorate in electorates:
        has_active_token = False
        if electorate.voting_tokens:
            for token in electorate.voting_tokens:
                if token.revoked or not token.is_active:
                    continue
                
                expires_at = token.expires_at
                if expires_at.tzinfo is None:
                    expires_at = expires_at.replace(tzinfo=timezone.utc)
                
                if expires_at > now:
                    has_active_token = True
                    break
        
        response.append({
            "id": str(electorate.id),
            "student_id": electorate.student_id,
            "program": electorate.program,
            "year_level": electorate.year_level,
            "phone_number": electorate.phone_number,
            "email": electorate.email,
            "has_voted": electorate.has_voted,
            "voted_at": electorate.voted_at.isoformat() if electorate.voted_at else None,
            "created_at": electorate.created_at.isoformat(),
            "updated_at": electorate.updated_at.isoformat(),
            "voting_token": "GENERATED" if has_active_token else None
        })
    
    return response
    

async def get_electorate(
    db: AsyncSession, voter_id: UUID
) -> Optional[Electorate]:
    """Get electorate by UUID"""
    result = await db.execute(
        select(Electorate).options(selectinload(Electorate.voting_tokens)).where(Electorate.id == voter_id)
    )
    return result.scalar_one_or_none()


async def create_electorate(
    db: AsyncSession, electorate: ElectorateCreate
) -> Electorate:
    # Extract voting_pin and hash it, then create the model data
    electorate_data = electorate.model_dump()
    voting_pin = electorate_data.pop('voting_pin', None)
    
    # Hash the voting pin if provided
    voting_pin_hash = hash_voting_pin(voting_pin) if voting_pin else ""
    
    # Create the Electorate object with the correct field name
    db_electorate = Electorate(
        voting_pin_hash=voting_pin_hash,
        **electorate_data
    )
    db.add(db_electorate)
    await db.commit()
    # Refresh then re-query with tokens eagerly loaded to avoid lazy IO during serialization
    await db.refresh(db_electorate)
    result = await db.execute(
        select(Electorate).options(selectinload(Electorate.voting_tokens)).where(Electorate.id == db_electorate.id)
    )
    return result.scalar_one()


async def update_electorate(
    db: AsyncSession, electorate_id: str, updates: ElectorateUpdate
) -> Optional[Electorate]:
    result = await db.execute(
        select(Electorate).where(Electorate.id == electorate_id)
    )
    db_electorate = result.scalar_one_or_none()
    if not db_electorate:
        return None
    
    update_data = updates.model_dump(exclude_unset=True)
    
    # Handle voting_pin field separately
    if 'voting_pin' in update_data:
        voting_pin = update_data.pop('voting_pin')
        voting_pin_hash = hash_voting_pin(voting_pin) if voting_pin else ""
        setattr(db_electorate, 'voting_pin_hash', voting_pin_hash)
    
    # Update other fields
    for field, value in update_data.items():
        setattr(db_electorate, field, value)
    
    await db.commit()
    await db.refresh(db_electorate)
    # Re-query with tokens eagerly loaded to prevent lazy IO during response validation
    result = await db.execute(
        select(Electorate).options(selectinload(Electorate.voting_tokens)).where(Electorate.id == db_electorate.id)
    )
    return result.scalar_one()


async def delete_electorate(db: AsyncSession, electorate_id: str) -> bool:
    result = await db.execute(
        select(Electorate).where(Electorate.id == electorate_id)
    )
    db_electorate = result.scalar_one_or_none()
    if not db_electorate:
        return False
    db_electorate.is_deleted = True
    await db.commit()
    return True


async def bulk_create_electorates(
        db: AsyncSession, electorate_list: List[ElectorateCreate]
    ) -> List[Electorate]:
    objs = []
    for e in electorate_list:
        # Extract voting_pin and hash it
        electorate_data = e.model_dump()
        voting_pin = electorate_data.pop('voting_pin', None)
        
        # Hash the voting pin if provided
        voting_pin_hash = hash_voting_pin(voting_pin) if voting_pin else ""
        
        # Create the Electorate object with the correct field name
        obj = Electorate(
            voting_pin_hash=voting_pin_hash,
            **electorate_data
        )
        objs.append(obj)
    
    db.add_all(objs)
    await db.commit()
    # Refresh each object, then re-query all with tokens eagerly loaded
    for obj in objs:
        await db.refresh(obj)

    ids = [obj.id for obj in objs]
    result = await db.execute(
        select(Electorate).options(selectinload(Electorate.voting_tokens)).where(Electorate.id.in_(ids))
    )
    return result.scalars().all()
