"""
Voting System Router

This router handles all voting-related operations including:
- Portfolio management
- Candidate management
- Vote casting
- Election results
"""

from uuid import UUID
from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Request,
    status,
)
from jose import JWTError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List
from datetime import datetime, timezone
from app.core.database import get_db
from app.middleware.auth_middleware import rate_limit_voting, get_current_voter
from app.models.electorates import Electorate, VotingSession
from app.schemas.electorates import (
    PortfolioOut,
    VoteOut,
    VotingCreation,
    VotingSessionResponse,
)
from app.crud.crud_portfolios import (
    get_active_portfolios_for_voting,
)
from app.crud.crud_candidates import get_candidate_engine
from app.crud.crud_votes import (
    create_vote,
    get_votes_by_electorate,
    check_electorate_voted_for_portfolio,
)
from app.utils.device_fingerprinting import DeviceFingerprinter
from app.utils.security import TokenManager

router = APIRouter(prefix="/voting", tags=["Voting System"])


# Voting Endpoints
@router.get("/ballot", response_model=List[PortfolioOut])
async def get_voting_ballot(
    db: AsyncSession = Depends(get_db),
    electorate: Electorate = Depends(get_current_voter),
):
    """Get the voting ballot for the current electorate"""
    try:
        portfolios = await get_active_portfolios_for_voting(db)
        return portfolios
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve voting ballot: {str(e)}",
        )


@router.post("/vote", response_model=VotingSessionResponse)
@rate_limit_voting
async def cast_vote(
        vote_data: VotingCreation,
        request: Request,
        db: AsyncSession = Depends(get_db),
        electorate: Electorate = Depends(get_current_voter),
    ):
    """Cast multiple votes at once"""
    try:
        device_info = DeviceFingerprinter.extract_device_info(request)
        session_token = request.cookies.get("voting_session")
        voting_session_id = None

        if session_token:
            try:
                payload = TokenManager.decode_token(session_token)
                session_id_str = payload.get("session_id")
                if session_id_str:
                    voting_session_id = UUID(session_id_str)
            except (ValueError, JWTError):
                pass

        created_votes = []

        # Loop through all votes in the request
        for vote in vote_data.votes:
            # Check if electorate already voted for this portfolio
            has_voted = await check_electorate_voted_for_portfolio(
                db, electorate.id, vote.portfolio_id
            )
            if has_voted:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"You have already voted for portfolio {vote.portfolio_id}",
                )

            # Verify candidate validity
            candidate = await get_candidate_engine(db, vote.candidate_id)
            if not candidate or candidate.portfolio_id != vote.portfolio_id:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid candidate for portfolio {vote.portfolio_id}",
                )

            # Create the vote
            created_vote = await create_vote(
                db=db,
                vote_data=vote,
                electorate_id=electorate.id,
                voting_session_id=voting_session_id,
                ip_address=device_info.get("client_ip"),
                device_fingerprint=device_info.get("fingerprint"),
                user_agent=device_info.get("user_agent"),
            )

            created_votes.append(created_vote)

        # Compute remaining session time (optional)
        session_remaining_time = None
        if voting_session_id:
            session_result = await db.execute(
                select(VotingSession).where(VotingSession.id == voting_session_id)
            )
            session = session_result.scalar_one_or_none()
            if session:
                time_remaining = (
                    session.expires_at - datetime.now(timezone.utc)
                ).total_seconds()
                session_remaining_time = max(0, int(time_remaining))
        
        # Mark electorate as having voted
        electorate.has_voted = True
        await db.commit()


        return VotingSessionResponse(
            success=True,
            message=f"{len(created_votes)} vote(s) cast successfully",
            votes_cast=len(created_votes),
            failed_votes=[],
            session_remaining_time=session_remaining_time,
        )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to cast vote: {str(e)}",
        )


@router.get("/my-votes", response_model=List[VoteOut])
async def get_my_votes(
    db: AsyncSession = Depends(get_db),
    electorate: Electorate = Depends(get_current_voter),
):
    """Get all votes cast by the current electorate"""
    try:
        votes = await get_votes_by_electorate(db, electorate.id)
        return votes
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve votes: {str(e)}",
        )
