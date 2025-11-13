from typing import List
from fastapi import (
    APIRouter, 
    Depends, 
    HTTPException,
    status
)
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.database import get_db
from app.crud.crud_votes import (
    get_all_election_results,
)
from app.schemas.electorates import ElectionResults


router = APIRouter(prefix="/results", tags=["Results"])


# Results and Statistics Endpoints
@router.get("/results", response_model=List[ElectionResults])
async def get_election_results(db: AsyncSession = Depends(get_db)):
    """Get election results for all portfolios"""
    try:
        results = await get_all_election_results(db)
        return results
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve election results: {str(e)}",
        )