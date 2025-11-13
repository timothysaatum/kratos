"""
CRUD operations for Portfolio management
"""
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload
from sqlalchemy import func, and_
from typing import List, Optional
from uuid import UUID
from datetime import datetime, timezone

from app.models.electorates import Portfolio, Candidate, Vote
from app.schemas.electorates import PortfolioCreate, PortfolioUpdate


async def create_portfolio_engine(db: AsyncSession, portfolio_data: PortfolioCreate) -> Portfolio:
    """Create a new portfolio"""
    portfolio = Portfolio(**portfolio_data.model_dump())
    db.add(portfolio)
    await db.commit()
    await db.refresh(portfolio)
    return portfolio


async def get_portfolio_engine(
    db: AsyncSession, portfolio_id: UUID
) -> Optional[Portfolio]:
    """Get a portfolio by ID"""
    result = await db.execute(
        select(Portfolio)
        .options(selectinload(Portfolio.candidates))
        .where(Portfolio.id == portfolio_id)
    )
    return result.scalar_one_or_none()


async def get_portfolio_by_name(db: AsyncSession, name: str) -> Optional[Portfolio]:
    """Get a portfolio by name"""
    result = await db.execute(
        select(Portfolio).where(Portfolio.name == name)
    )
    return result.scalar_one_or_none()


async def get_portfolios(
    db: AsyncSession, 
    skip: int = 0, 
    limit: int = 100, 
    active_only: bool = True
) -> List[Portfolio]:
    """Get all portfolios with optional filtering"""
    query = select(Portfolio).options(selectinload(Portfolio.candidates))

    if active_only:
        query = query.where(Portfolio.is_active == True)

    query = query.order_by(Portfolio.voting_order, Portfolio.name).offset(skip).limit(limit)

    result = await db.execute(query)
    return result.scalars().all()


async def update_portfolio_engine(
    db: AsyncSession, portfolio_id: UUID, portfolio_data: PortfolioUpdate
) -> Optional[Portfolio]:
    """Update a portfolio"""
    result = await db.execute(
        select(Portfolio).where(Portfolio.id == portfolio_id)
    )
    portfolio = result.scalar_one_or_none()

    if not portfolio:
        return None

    update_data = portfolio_data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(portfolio, field, value)

    portfolio.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(portfolio)
    return portfolio


async def delete_portfolio_engine(db: AsyncSession, portfolio_id: UUID) -> bool:
    """Delete a portfolio (cascade deletes candidates and votes)"""
    result = await db.execute(
        select(Portfolio).where(Portfolio.id == portfolio_id)
    )
    portfolio = result.scalar_one_or_none()
    
    if not portfolio:
        return False
    
    await db.delete(portfolio)
    await db.commit()
    return True


async def get_portfolio_with_stats(db: AsyncSession, portfolio_id: UUID) -> Optional[dict]:
    """Get portfolio with vote statistics"""
    # Get portfolio
    portfolio_result = await db.execute(
        select(Portfolio)
        .options(selectinload(Portfolio.candidates))
        .where(Portfolio.id == portfolio_id)
    )
    portfolio = portfolio_result.scalar_one_or_none()
    
    if not portfolio:
        return None
    
    # Get vote counts for each candidate
    vote_counts_result = await db.execute(
        select(
            Candidate.id,
            Candidate.name,
            func.count(Vote.id).label('vote_count')
        )
        .join(Vote, Candidate.id == Vote.candidate_id)
        .where(
            and_(
                Candidate.portfolio_id == portfolio_id,
                Vote.is_valid == True
            )
        )
        .group_by(Candidate.id, Candidate.name)
    )
    
    candidate_votes = {row.id: {'name': row.name, 'vote_count': row.vote_count} for row in vote_counts_result}
    
    # Get total votes for portfolio
    total_votes_result = await db.execute(
        select(func.count(Vote.id))
        .join(Candidate, Vote.candidate_id == Candidate.id)
        .where(
            and_(
                Candidate.portfolio_id == portfolio_id,
                Vote.is_valid == True
            )
        )
    )
    total_votes = total_votes_result.scalar() or 0
    
    # Add vote counts to candidates
    for candidate in portfolio.candidates:
        candidate.vote_count = candidate_votes.get(candidate.id, {}).get('vote_count', 0)
    
    return {
        'portfolio': portfolio,
        'total_votes': total_votes,
        'candidate_count': len(portfolio.candidates)
    }


async def get_active_portfolios_for_voting(db: AsyncSession) -> List[Portfolio]:
    """Get active portfolios ordered by voting order for voting interface"""
    result = await db.execute(
        select(Portfolio)
        .options(selectinload(Portfolio.candidates))
        .where(
            and_(
                Portfolio.is_active == True,
                Portfolio.candidates.any(Candidate.is_active == True)
            )
        )
        .order_by(Portfolio.voting_order, Portfolio.name)
    )
    return result.scalars().all()


async def get_portfolio_statistics(db: AsyncSession) -> dict:
    """Get overall portfolio statistics"""
    # Total portfolios
    total_portfolios_result = await db.execute(
        select(func.count(Portfolio.id))
    )
    total_portfolios = total_portfolios_result.scalar() or 0
    
    # Active portfolios
    active_portfolios_result = await db.execute(
        select(func.count(Portfolio.id))
        .where(Portfolio.is_active == True)
    )
    active_portfolios = active_portfolios_result.scalar() or 0
    
    # Portfolios with candidates
    portfolios_with_candidates_result = await db.execute(
        select(func.count(func.distinct(Portfolio.id)))
        .join(Candidate, Portfolio.id == Candidate.portfolio_id)
        .where(Candidate.is_active == True)
    )
    portfolios_with_candidates = portfolios_with_candidates_result.scalar() or 0
    
    return {
        'total_portfolios': total_portfolios,
        'active_portfolios': active_portfolios,
        'portfolios_with_candidates': portfolios_with_candidates,
        'inactive_portfolios': total_portfolios - active_portfolios
    }
