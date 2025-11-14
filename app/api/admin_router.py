"""
Admin Router for Election Management

This router handles administrative operations including:
- Bulk token generation
- Voter management
- Election monitoring
- Voting station management
"""
import uuid
from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Optional
from uuid import UUID
from datetime import datetime, timezone
from app.core.database import get_db
from app.schemas.electorates import (
    BulkTokenGenerationRequest, 
    ElectorateOut, ElectionResults, 
    SingleTokenRegenerationRequest, 
    SingleTokenRegenerationResponse, 
    TokenGenerationRequest, 
    TokenGenerationResponse
)
from app.services.token_generation_service import BulkTokenGenerator
from app.services.notification_service import NotificationService
from app.crud.crud_electorates import get_electorates, get_electorate
from app.crud.crud_portfolios import get_portfolio_statistics
from app.crud.crud_candidates import get_candidate_statistics
from app.crud.crud_votes import (
    get_voting_statistics_engine,
    get_all_election_results,
    get_recent_votes_engine,
)
from app.middleware.auth_middleware import get_current_admin
router = APIRouter(prefix="/admin", tags=["Admin"])

# Initialize services
token_generator = BulkTokenGenerator()
notification_service = NotificationService()


@router.post("/generate-tokens/all", response_model=TokenGenerationResponse)
async def generate_tokens_for_all(
    request: TokenGenerationRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_admin=Depends(get_current_admin),
):
    """Generate voting tokens for all electorates"""
    try:
        result = await token_generator.generate_tokens_for_all_electorates(
            db=db,
            election_name=request.election_name,
            voting_url=request.voting_url,
            send_notifications=request.send_notifications,
            notification_methods=request.notification_methods,
            exclude_voted=request.exclude_voted,
            background_tasks=background_tasks,
        )
        return result
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Token generation failed: {str(e)}",
        )


@router.post("/generate-tokens/bulk", response_model=TokenGenerationResponse)
async def generate_tokens_for_selected(
    request: BulkTokenGenerationRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_admin=Depends(get_current_admin),
):
    """Generate voting tokens for selected electorates"""
    try:
        result = await token_generator.generate_tokens_for_electorates(
            db=db,
            electorate_ids=request.electorate_ids,
            election_name=request.election_name,
            voting_url=request.voting_url,
            send_notifications=request.send_notifications,
            notification_methods=request.notification_methods,
            background_tasks=background_tasks,
        )
        return result
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Token generation failed: {str(e)}",
        )


@router.post(
    "/regenerate-token/{electorate_id}", response_model=SingleTokenRegenerationResponse
)
async def regenerate_token(
    electorate_id: uuid.UUID,
    request: SingleTokenRegenerationRequest,
    db: AsyncSession = Depends(get_db),
    current_admin=Depends(get_current_admin),
):
    """Regenerate voting token for a specific electorate"""
    try:
        result = await token_generator.regenerate_token_for_electorate(
            db=db,
            electorate_id=electorate_id,
            election_name=request.election_name,
            voting_url=request.voting_url,
            send_notification=request.send_notification,
            notification_methods=request.notification_methods,
        )
        return result
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Token regeneration failed: {str(e)}",
        )


@router.post("/generate-tokens/portfolio/{portfolio_id}")
async def generate_tokens_for_portfolio(
    portfolio_id: UUID,
    election_name: str = "Election",
    voting_url: str = "http://localhost:8000",
    send_notifications: bool = True,
    notification_methods: List[str] = ["email", "sms"],
    background_tasks: BackgroundTasks = None,
    db: AsyncSession = Depends(get_db),
    current_admin=Depends(get_current_admin),
):
    """Generate voting tokens for electorates who haven't voted for a specific portfolio"""
    try:
        result = await token_generator.generate_tokens_for_portfolio(
            db=db,
            portfolio_id=portfolio_id,
            election_name=election_name,
            voting_url=voting_url,
            send_notifications=send_notifications,
            notification_methods=notification_methods,
            background_tasks=background_tasks,
        )

        return result

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Token generation failed: {str(e)}",
        )

# Voter Management Endpoints
@router.get("/voters", response_model=List[ElectorateOut])
async def list_voters(
    skip: int = 0,
    limit: int = 100,
    has_voted: Optional[bool] = None,
    has_token: Optional[bool] = None,
    db: AsyncSession = Depends(get_db),
    current_admin=Depends(get_current_admin),
):
    """List voters with optional filtering"""
    try:
        voters = await get_electorates(db, skip=skip, limit=limit)

        # Apply additional filtering if needed
        if has_voted is not None:
            voters = [v for v in voters if v.has_voted == has_voted]

        return voters

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve voters: {str(e)}",
        )


@router.get("/voters/{voter_id}", response_model=ElectorateOut)
async def get_voter(
    voter_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_admin=Depends(get_current_admin),
):
    """Get specific voter details"""
    try:
        voter = await get_electorate(db, voter_id)
        if not voter:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Voter not found"
            )
        return voter

    except HTTPException:
        raise

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve voter: {str(e)}",
        )


# Election Monitoring Endpoints
@router.get("/statistics")
async def get_election_statistics(
    db: AsyncSession = Depends(get_db),
    current_admin=Depends(get_current_admin),
):
    """Get comprehensive election statistics"""
    try:
        # Get voting statistics
        voting_stats = await get_voting_statistics_engine(db)

        # Get token statistics
        token_stats = await token_generator.get_token_statistics(db)

        # Get portfolio statistics
        portfolio_stats = await get_portfolio_statistics(db)

        # Get candidate statistics
        candidate_stats = await get_candidate_statistics(db)

        return {
            "voting": voting_stats,
            "tokens": token_stats,
            "portfolios": portfolio_stats,
            "candidates": candidate_stats,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve statistics: {str(e)}",
        )


@router.get("/results", response_model=List[ElectionResults])
async def get_election_results(
    db: AsyncSession = Depends(get_db),
    current_admin=Depends(get_current_admin),
):
    """Get election results for all portfolios"""
    try:
        results = await get_all_election_results(db)
        return results

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve results: {str(e)}",
        )


@router.get("/recent-activity")
async def get_recent_activity(
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
    current_admin=Depends(get_current_admin),
):
    """Get recent voting activity for monitoring"""
    try:
        recent_votes = await get_recent_votes_engine(db, limit=limit)

        return {
            "recent_votes": recent_votes,
            "total_recent_votes": len(recent_votes),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve recent activity: {str(e)}",
        )
