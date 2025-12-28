"""
CRUD operations for Candidate management
"""

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload
from sqlalchemy import func, and_, or_
from typing import List, Optional
from uuid import UUID
from datetime import datetime, timezone

from app.models.electorates import Candidate, Portfolio, Vote
from app.schemas.electorates import CandidateCreate, CandidateUpdate


async def create_candidate_engine(db: AsyncSession, candidate_data: CandidateCreate) -> Candidate:
    """Create a new candidate"""
    candidate = Candidate(**candidate_data.model_dump())
    db.add(candidate)
    await db.commit()
    await db.refresh(candidate)
    return candidate


async def get_candidate_engine(db: AsyncSession, candidate_id: UUID) -> Optional[Candidate]:
    """Get a candidate by ID"""
    result = await db.execute(
        select(Candidate)
        .options(selectinload(Candidate.portfolio))
        .where(Candidate.id == candidate_id)
    )
    return result.scalar_one_or_none()


async def get_candidates_by_portfolio(
    db: AsyncSession, 
    portfolio_id: UUID, 
    active_only: bool = True
) -> List[Candidate]:
    """Get all candidates for a specific portfolio"""
    query = select(Candidate).options(selectinload(Candidate.portfolio))
    query = query.where(Candidate.portfolio_id == portfolio_id)
    
    if active_only:
        query = query.where(Candidate.is_active == True)
    
    query = query.order_by(Candidate.display_order, Candidate.name)
    
    result = await db.execute(query)
    return result.scalars().all()


async def get_candidates(
    db: AsyncSession, 
    skip: int = 0, 
    limit: int = 100, 
    active_only: bool = True
) -> List[Candidate]:
    """Get all candidates with optional filtering"""
    query = select(Candidate).options(selectinload(Candidate.portfolio))
    
    if active_only:
        query = query.where(Candidate.is_active == True)
    
    query = query.order_by(Candidate.portfolio_id, Candidate.display_order, Candidate.name)
    query = query.offset(skip).limit(limit)
    
    result = await db.execute(query)
    return result.scalars().all()


async def update_candidate_engine(
    db: AsyncSession, 
    candidate_id: UUID, 
    candidate_data: CandidateUpdate
) -> Optional[Candidate]:
    """Update a candidate"""
    result = await db.execute(
        select(Candidate).where(Candidate.id == candidate_id)
    )
    candidate = result.scalar_one_or_none()
    
    if not candidate:
        return None
    
    update_data = candidate_data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(candidate, field, value)
    
    candidate.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(candidate)
    return candidate


async def delete_candidate_engine(db: AsyncSession, candidate_id: UUID) -> bool:
    """Delete a candidate (cascade deletes votes)"""
    result = await db.execute(
        select(Candidate).where(Candidate.id == candidate_id)
    )
    candidate = result.scalar_one_or_none()
    
    if not candidate:
        return False
    
    await db.delete(candidate)
    await db.commit()
    return True


async def get_candidate_with_votes(db: AsyncSession, candidate_id: UUID) -> Optional[dict]:
    """Get candidate with vote statistics"""
    # Get candidate
    candidate_result = await db.execute(
        select(Candidate)
        .options(selectinload(Candidate.portfolio))
        .where(Candidate.id == candidate_id)
    )
    candidate = candidate_result.scalar_one_or_none()
    
    if not candidate:
        return None
    
    # Get vote count
    vote_count_result = await db.execute(
        select(func.count(Vote.id))
        .where(
            and_(
                Vote.candidate_id == candidate_id,
                Vote.is_valid == True
            )
        )
    )
    vote_count = vote_count_result.scalar() or 0
    
    return {
        'candidate': candidate,
        'vote_count': vote_count
    }


async def get_candidates_for_voting(db: AsyncSession, portfolio_id: UUID) -> List[Candidate]:
    """Get active candidates for a portfolio for voting interface"""
    result = await db.execute(
        select(Candidate)
        .options(selectinload(Candidate.portfolio))
        .where(
            and_(
                Candidate.portfolio_id == portfolio_id,
                Candidate.is_active == True
            )
        )
        .order_by(Candidate.display_order, Candidate.name)
    )
    return result.scalars().all()


async def get_candidate_statistics(db: AsyncSession) -> dict:
    """Get overall candidate statistics"""
    # Total candidates
    total_candidates_result = await db.execute(
        select(func.count(Candidate.id))
    )
    total_candidates = total_candidates_result.scalar() or 0
    
    # Active candidates
    active_candidates_result = await db.execute(
        select(func.count(Candidate.id))
        .where(Candidate.is_active == True)
    )
    active_candidates = active_candidates_result.scalar() or 0
    
    # Candidates with pictures
    candidates_with_pictures_result = await db.execute(
        select(func.count(Candidate.id))
        .where(Candidate.picture_url.isnot(None))
    )
    candidates_with_pictures = candidates_with_pictures_result.scalar() or 0
    
    # Candidates by portfolio
    candidates_by_portfolio_result = await db.execute(
        select(
            Portfolio.name,
            func.count(Candidate.id).label('candidate_count')
        )
        .join(Candidate, Portfolio.id == Candidate.portfolio_id)
        .where(Candidate.is_active == True)
        .group_by(Portfolio.id, Portfolio.name)
        .order_by(func.count(Candidate.id).desc())
    )
    candidates_by_portfolio = [
        {'portfolio_name': row.name, 'candidate_count': row.candidate_count}
        for row in candidates_by_portfolio_result
    ]
    
    return {
        'total_candidates': total_candidates,
        'active_candidates': active_candidates,
        'candidates_with_pictures': candidates_with_pictures,
        'candidates_by_portfolio': candidates_by_portfolio
    }


async def search_candidates(
    db: AsyncSession,
    search_term: str,
    portfolio_id: Optional[UUID] = None,
    limit: int = 20
) -> List[Candidate]:
    """Search candidates by name or manifesto"""
    query = select(Candidate).options(selectinload(Candidate.portfolio))
    
    # Search in name and manifesto
    search_filter = or_(
        Candidate.name.ilike(f"%{search_term}%"),
        Candidate.manifesto.ilike(f"%{search_term}%")
    )
    
    query = query.where(search_filter)
    
    if portfolio_id:
        query = query.where(Candidate.portfolio_id == portfolio_id)
    
    query = query.where(Candidate.is_active == True)
    query = query.order_by(Candidate.name).limit(limit)
    
    result = await db.execute(query)
    return result.scalars().all()