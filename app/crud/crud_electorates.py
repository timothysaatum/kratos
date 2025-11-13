from uuid import UUID
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models.electorates import Electorate
from app.schemas.electorates import ElectorateCreate, ElectorateUpdate
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
        select(Electorate).where(Electorate.student_id == student_id)
    )
    return result.scalar_one_or_none()


async def get_electorates(
    db: AsyncSession, skip: int = 0, limit: int = 100
) -> List[Electorate]:
    result = await db.execute(
        select(Electorate)
        .where(Electorate.is_deleted == False)
        .offset(skip)
        .limit(limit)
    )
    return result.scalars().all()

async def get_electorate(
    db: AsyncSession, voter_id: UUID
) -> Optional[Electorate]:
    """Get electorate by UUID"""
    result = await db.execute(
        select(Electorate).where(Electorate.id == voter_id)
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
    await db.refresh(db_electorate)
    return db_electorate


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
    return db_electorate


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
    for obj in objs:
        await db.refresh(obj)
    return objs
