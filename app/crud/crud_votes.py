"""
CRUD operations for Vote management
"""

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload
from sqlalchemy import func, and_, desc
from typing import List, Optional, Dict, Any
from uuid import UUID
from datetime import datetime, timezone

from app.models.electorates import Vote, Candidate, Portfolio, Electorate
from app.schemas.electorates import VoteCreate


async def create_vote(
    db: AsyncSession, 
    vote_data: VoteCreate,
    electorate_id: UUID,
    voting_session_id: Optional[UUID],
    ip_address: str,
    device_fingerprint: str,
    user_agent: str
) -> Vote:
    """Create a new vote"""
    vote = Vote(
        electorate_id=electorate_id,
        portfolio_id=vote_data.portfolio_id,
        candidate_id=vote_data.candidate_id,
        voting_session_id=voting_session_id,
        ip_address=ip_address,
        device_fingerprint=device_fingerprint,
        user_agent=user_agent,
        voted_at=datetime.now(timezone.utc)
    )
    db.add(vote)
    await db.commit()
    await db.refresh(vote)
    return vote


async def get_vote(db: AsyncSession, vote_id: UUID) -> Optional[Vote]:
    """Get a vote by ID"""
    result = await db.execute(
        select(Vote)
        .options(
            selectinload(Vote.electorate),
            selectinload(Vote.portfolio),
            selectinload(Vote.candidate),
            selectinload(Vote.voting_session)
        )
        .where(Vote.id == vote_id)
    )
    return result.scalar_one_or_none()


async def get_votes_by_electorate(
    db: AsyncSession, 
    electorate_id: UUID,
    valid_only: bool = True
) -> List[Vote]:
    """Get all votes by an electorate"""
    query = select(Vote).options(
        selectinload(Vote.portfolio),
        selectinload(Vote.candidate)
    ).where(Vote.electorate_id == electorate_id)
    
    if valid_only:
        query = query.where(Vote.is_valid == True)
    
    query = query.order_by(desc(Vote.voted_at))
    
    result = await db.execute(query)
    return result.scalars().all()


async def get_votes_by_portfolio(
    db: AsyncSession, 
    portfolio_id: UUID,
    valid_only: bool = True
) -> List[Vote]:
    """Get all votes for a specific portfolio"""
    query = select(Vote).options(
        selectinload(Vote.electorate),
        selectinload(Vote.candidate)
    ).where(Vote.portfolio_id == portfolio_id)
    
    if valid_only:
        query = query.where(Vote.is_valid == True)
    
    query = query.order_by(desc(Vote.voted_at))
    
    result = await db.execute(query)
    return result.scalars().all()


async def get_votes_by_candidate(
    db: AsyncSession, 
    candidate_id: UUID,
    valid_only: bool = True
) -> List[Vote]:
    """Get all votes for a specific candidate"""
    query = select(Vote).options(
        selectinload(Vote.electorate),
        selectinload(Vote.portfolio)
    ).where(Vote.candidate_id == candidate_id)
    
    if valid_only:
        query = query.where(Vote.is_valid == True)
    
    query = query.order_by(desc(Vote.voted_at))
    
    result = await db.execute(query)
    return result.scalars().all()


async def check_electorate_voted_for_portfolio(
    db: AsyncSession, 
    electorate_id: UUID, 
    portfolio_id: UUID
) -> bool:
    """Check if an electorate has already voted for a specific portfolio"""
    result = await db.execute(
        select(Vote.id)
        .where(
            and_(
                Vote.electorate_id == electorate_id,
                Vote.portfolio_id == portfolio_id,
                Vote.is_valid == True
            )
        )
        .limit(1)
    )
    return result.scalar_one_or_none() is not None


async def get_vote_count_by_candidate(
    db: AsyncSession, 
    candidate_id: UUID,
    valid_only: bool = True
) -> int:
    """Get vote count for a specific candidate"""
    query = select(func.count(Vote.id)).where(Vote.candidate_id == candidate_id)
    
    if valid_only:
        query = query.where(Vote.is_valid == True)
    
    result = await db.execute(query)
    return result.scalar() or 0


async def get_vote_count_by_portfolio(
    db: AsyncSession, 
    portfolio_id: UUID,
    valid_only: bool = True
) -> int:
    """Get total vote count for a specific portfolio"""
    query = select(func.count(Vote.id)).where(Vote.portfolio_id == portfolio_id)
    
    if valid_only:
        query = query.where(Vote.is_valid == True)
    
    result = await db.execute(query)
    return result.scalar() or 0


async def get_election_results(db: AsyncSession, portfolio_id: UUID) -> Dict[str, Any]:
    """Get election results for a specific portfolio"""
    # Get portfolio info
    portfolio_result = await db.execute(
        select(Portfolio).where(Portfolio.id == portfolio_id)
    )
    portfolio = portfolio_result.scalar_one_or_none()
    
    if not portfolio:
        return None
    
    # Get vote counts for each candidate
    vote_counts_result = await db.execute(
        select(
            Candidate.id,
            Candidate.name,
            Candidate.picture_url,
            func.count(Vote.id).label('vote_count')
        )
        .join(Vote, Candidate.id == Vote.candidate_id)
        .where(
            and_(
                Candidate.portfolio_id == portfolio_id,
                Vote.is_valid == True
            )
        )
        .group_by(Candidate.id, Candidate.name, Candidate.picture_url)
        .order_by(desc(func.count(Vote.id)))
    )
    
    candidates = []
    total_votes = 0
    winner = None
    
    for row in vote_counts_result:
        candidate_data = {
            'id': str(row.id),
            'name': row.name,
            'picture_url': row.picture_url,
            'vote_count': row.vote_count
        }
        candidates.append(candidate_data)
        total_votes += row.vote_count
        
        # First candidate (highest votes) is the winner
        if winner is None:
            winner = candidate_data
    
    return {
        'portfolio_id': str(portfolio_id),
        'portfolio_name': portfolio.name,
        'total_votes': total_votes,
        'candidates': candidates,
        'winner': winner
    }


async def get_all_election_results(db: AsyncSession) -> List[Dict[str, Any]]:
    """Get election results for all portfolios"""
    # Get all active portfolios
    portfolios_result = await db.execute(
        select(Portfolio.id, Portfolio.name)
        .where(Portfolio.is_active == True)
        .order_by(Portfolio.voting_order, Portfolio.name)
    )
    portfolios = portfolios_result.all()

    results = []
    for portfolio in portfolios:
        result = await get_election_results(db, portfolio.id)
        if result:
            results.append(result)

    return results


async def get_voting_statistics_engine(db: AsyncSession) -> Dict[str, Any]:
    """Get overall voting statistics"""
    # Total votes
    total_votes_result = await db.execute(
        select(func.count(Vote.id))
    )
    total_votes = total_votes_result.scalar() or 0

    # Valid votes
    valid_votes_result = await db.execute(
        select(func.count(Vote.id))
        .where(Vote.is_valid == True)
    )
    valid_votes = valid_votes_result.scalar() or 0

    # Total electorates
    total_electorates_result = await db.execute(
        select(func.count(Electorate.id)).where(Electorate.is_deleted == False)
    )
    total_electorates = total_electorates_result.scalar() or 0

    # Electorates who have voted
    voted_electorates_result = await db.execute(
        select(func.count(func.distinct(Vote.electorate_id)))
        .where(Vote.is_valid == True)
    )
    voted_electorates = voted_electorates_result.scalar() or 0

    # Votes by hour (for activity analysis)
    votes_by_hour_result = await db.execute(
        select(
            func.extract('hour', Vote.voted_at).label('hour'),
            func.count(Vote.id).label('vote_count')
        )
        .where(Vote.is_valid == True)
        .group_by(func.extract('hour', Vote.voted_at))
        .order_by('hour')
    )
    votes_by_hour = [
        {'hour': int(row.hour), 'vote_count': row.vote_count}
        for row in votes_by_hour_result
    ]

    return {
        'total_votes': total_votes,
        'valid_votes': valid_votes,
        'invalid_votes': total_votes - valid_votes,
        'total_electorates': total_electorates,
        'voted_electorates': voted_electorates,
        'voting_percentage': (voted_electorates / total_electorates * 100) if total_electorates > 0 else 0,
        'votes_by_hour': votes_by_hour
    }


async def invalidate_vote(db: AsyncSession, vote_id: UUID, reason: str = "Invalidated") -> bool:
    """Invalidate a vote"""
    result = await db.execute(
        select(Vote).where(Vote.id == vote_id)
    )
    vote = result.scalar_one_or_none()

    if not vote:
        return False

    vote.is_valid = False
    await db.commit()
    return True


async def get_recent_votes_engine(
    db: AsyncSession, limit: int = 50, valid_only: bool = True
) -> List[Vote]:
    """Get recent votes for monitoring"""
    query = select(Vote).options(
        selectinload(Vote.electorate),
        selectinload(Vote.portfolio),
        selectinload(Vote.candidate)
    )

    if valid_only:
        query = query.where(Vote.is_valid == True)

    query = query.order_by(desc(Vote.voted_at)).limit(limit)

    result = await db.execute(query)
    return result.scalars().all()
