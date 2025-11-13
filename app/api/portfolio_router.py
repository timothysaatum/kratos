from typing import List
from uuid import UUID
from fastapi import (
    APIRouter, 
    Depends, 
    HTTPException, 
    status
)
from sqlalchemy.ext.asyncio import AsyncSession
from app.middleware.auth_middleware import get_current_admin
from app.core.database import get_db
from app.crud.crud_portfolios import (
    create_portfolio_engine,
    delete_portfolio_engine,
    get_portfolio_by_name,
    get_portfolio_engine, 
    get_portfolios,
    update_portfolio_engine
)
from app.schemas.electorates import (
    PortfolioCreate, 
    PortfolioOut, 
    PortfolioUpdate
)

router = APIRouter(prefix="/portfolios", tags=["Portfolio Management"])

# Portfolio Management Endpoints
@router.post(
    "", response_model=PortfolioOut, status_code=status.HTTP_201_CREATED
)
async def create_portfolio(
    portfolio_data: PortfolioCreate, 
    db: AsyncSession = Depends(get_db),
    current_admin = Depends(get_current_admin),
):
    """Create a new portfolio"""
    try:
        # Check if portfolio name already exists
        existing = await get_portfolio_by_name(db, portfolio_data.name)
        if existing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Portfolio with this name already exists",
            )

        portfolio = await create_portfolio_engine(db, portfolio_data)
        return portfolio
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create portfolio: {str(e)}",
        )


@router.get("", response_model=List[PortfolioOut])
async def list_portfolios(
    skip: int = 0,
    limit: int = 100,
    active_only: bool = True,
    db: AsyncSession = Depends(get_db),
    current_admin = Depends(get_current_admin),
):
    """List all portfolios"""
    try:
        portfolios = await get_portfolios(
            db, skip=skip, limit=limit, active_only=active_only
        )
        return portfolios
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve portfolios: {str(e)}",
        )


@router.get("/{portfolio_id}", response_model=PortfolioOut)
async def get_portfolio(
    portfolio_id: UUID, 
    db: AsyncSession = Depends(get_db),
    current_admin = Depends(get_current_admin),
):
    """Get a specific portfolio"""
    try:
        portfolio = await get_portfolio_engine(db, portfolio_id)
        if not portfolio:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Portfolio not found"
            )
            
        return portfolio
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve portfolio: {str(e)}",
        )


@router.patch("/{portfolio_id}", response_model=PortfolioOut)
async def update_portfolio(
    portfolio_id: UUID,
    portfolio_data: PortfolioUpdate,
    db: AsyncSession = Depends(get_db),
    current_admin=Depends(get_current_admin),
):
    """Update a portfolio"""
    try:
        portfolio = await update_portfolio_engine(db, portfolio_id, portfolio_data)
        if not portfolio:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Portfolio not found"
            )
        return portfolio
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update portfolio: {str(e)}",
        )


@router.delete(
        "/{portfolio_id}", 
        status_code=status.HTTP_204_NO_CONTENT
    )
async def delete_portfolio(
    portfolio_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_admin=Depends(get_current_admin),
):
    """Delete a portfolio"""
    try:
        success = await delete_portfolio_engine(db, portfolio_id)
        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Portfolio not found"
            )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete portfolio: {str(e)}",
        )
