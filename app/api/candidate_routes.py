import os
from typing import List, Optional
from uuid import UUID
import uuid
from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from sqlalchemy.ext.asyncio import AsyncSession
from app.middleware.auth_middleware import get_current_admin
from app.core.database import get_db
from app.crud.crud_candidates import (
    create_candidate_engine,
    delete_candidate_engine,
    get_candidate_engine,
    get_candidates,
    get_candidates_by_portfolio,
    search_candidates,
    update_candidate_engine,
)
from app.crud.crud_portfolios import (
    get_portfolio_engine,
)
from app.schemas.electorates import (
    CandidateCreate,
    CandidateOut,
    CandidateUpdate,
)

# File upload configuration
UPLOAD_DIR = "uploads/candidates"
ALLOWED_IMAGE_TYPES = {"image/jpeg", "image/png", "image/gif", "image/webp"}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB


router = APIRouter(prefix="/candidates", tags=["Candidate Management"])


# Candidate Management Endpoints
@router.post(
    "", response_model=CandidateOut, status_code=status.HTTP_201_CREATED
)
async def create_candidate(
    candidate_data: CandidateCreate,
    db: AsyncSession = Depends(get_db),
    current_admin = Depends(get_current_admin)
):
    """Create a new candidate"""
    try:
        # Verify portfolio exists
        portfolio = await get_portfolio_engine(db, candidate_data.portfolio_id)
        if not portfolio:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Portfolio not found"
            )

        candidate = await create_candidate_engine(db, candidate_data)
        return candidate
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create candidate: {str(e)}",
        )


@router.post("/upload-image")
async def upload_candidate_image(
    file: UploadFile = File(...), current_admin=Depends(get_current_admin)
):
    """Upload candidate image independently (before or during candidate creation)"""
    try:
        # Validate file type
        if file.content_type not in ALLOWED_IMAGE_TYPES:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid file type. Only JPEG, PNG, GIF, and WebP are allowed",
            )

        # Check file size
        content = await file.read()
        if len(content) > MAX_FILE_SIZE:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="File too large. Maximum size is 5MB",
            )

        # Create upload directory if it doesn't exist
        os.makedirs(UPLOAD_DIR, exist_ok=True)

        # Generate unique filename
        file_extension = file.filename.split(".")[-1] if "." in file.filename else "jpg"
        unique_filename = f"{uuid.uuid4().hex}.{file_extension}"
        file_path = os.path.join(UPLOAD_DIR, unique_filename)

        # Save file
        with open(file_path, "wb") as buffer:
            buffer.write(content)

        # Return the file URL that can be used when creating/updating candidate
        file_url = f"/uploads/candidates/{unique_filename}"

        return {
            "success": True,
            "message": "Image uploaded successfully",
            "filename": unique_filename,
            "file_url": file_url,
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to upload image: {str(e)}",
        )


@router.delete("/delete-image/{filename}")
async def delete_candidate_image(
    filename: str, current_admin=Depends(get_current_admin)
):
    """Delete a candidate image file"""
    try:
        file_path = os.path.join(UPLOAD_DIR, filename)

        if not os.path.exists(file_path):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Image file not found"
            )

        os.remove(file_path)

        return {"success": True, "message": "Image deleted successfully"}

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete image: {str(e)}",
        )


@router.post("/{candidate_id}/upload-picture")
async def upload_candidate_picture(
    candidate_id: UUID, file: UploadFile = File(...), 
    db: AsyncSession = Depends(get_db),
    current_admin = Depends(get_current_admin)
):
    """Upload candidate picture"""
    try:
        # Verify candidate exists
        candidate = await get_candidate(db, candidate_id)
        if not candidate:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Candidate not found"
            )

        # Validate file type
        if file.content_type not in ALLOWED_IMAGE_TYPES:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid file type. Only JPEG, PNG, GIF, and WebP are allowed",
            )

        # Check file size
        content = await file.read()
        if len(content) > MAX_FILE_SIZE:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="File too large. Maximum size is 5MB",
            )

        # Create upload directory if it doesn't exist
        os.makedirs(UPLOAD_DIR, exist_ok=True)

        # Generate unique filename
        file_extension = file.filename.split(".")[-1] if "." in file.filename else "jpg"
        unique_filename = f"{candidate_id}_{uuid.uuid4().hex}.{file_extension}"
        file_path = os.path.join(UPLOAD_DIR, unique_filename)

        # Save file
        with open(file_path, "wb") as buffer:
            buffer.write(content)

        # Update candidate record
        candidate.picture_filename = unique_filename
        candidate.picture_url = f"/uploads/candidates/{unique_filename}"
        await db.commit()

        return {
            "message": "Picture uploaded successfully",
            "filename": unique_filename,
            "url": candidate.picture_url,
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to upload picture: {str(e)}",
        )


# @router.get("", response_model=List[CandidateOut])
# async def list_candidates(
#     current_admin = Depends(get_current_admin),
#     skip: int = 0,
#     limit: int = 100,
#     portfolio_id: Optional[UUID] = None,
#     active_only: bool = True,
#     search: Optional[str] = None,
#     db: AsyncSession = Depends(get_db),
# ):
#     """List candidates with optional filtering"""
#     try:
#         if search:
#             candidates = await search_candidates(
#                 db, search_term=search, portfolio_id=portfolio_id, limit=limit
#             )
#         elif portfolio_id:
#             candidates = await get_candidates_by_portfolio(
#                 db, portfolio_id=portfolio_id, active_only=active_only
#             )
#         else:
#             candidates = await get_candidates(
#                 db, skip=skip, limit=limit, active_only=active_only
#             )
#         return candidates
#     except Exception as e:
#         raise HTTPException(
#             status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
#             detail=f"Failed to retrieve candidates: {str(e)}",
#         )


# @router.get("/{candidate_id}", response_model=CandidateOut)
# async def get_candidate(
#     candidate_id: UUID,
#     db: AsyncSession = Depends(get_db),
#     current_admin = Depends(get_current_admin)
#     ):
#     """Get a specific candidate"""
#     try:
#         candidate = await get_candidate_engine(db, candidate_id)
#         if not candidate:
#             raise HTTPException(
#                 status_code=status.HTTP_404_NOT_FOUND, detail="Candidate not found"
#             )
#         return candidate
#     except HTTPException:
#         raise
#     except Exception as e:
#         raise HTTPException(
#             status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
#             detail=f"Failed to retrieve candidate: {str(e)}",
#         )
@router.get("", response_model=List[CandidateOut])
async def list_candidates(
    skip: int = 0,
    limit: int = 100,
    portfolio_id: Optional[UUID] = None,
    active_only: bool = False,
    search: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_admin=Depends(get_current_admin),
):
    """List candidates with optional filtering"""
    try:
        if search:
            candidates = await search_candidates(
                db, search_term=search, portfolio_id=portfolio_id, limit=limit
            )
        elif portfolio_id:
            candidates = await get_candidates_by_portfolio(
                db, portfolio_id=portfolio_id, active_only=active_only
            )
        else:
            candidates = await get_candidates(
                db, skip=skip, limit=limit, active_only=active_only
            )

        # Ensure picture URLs are properly formatted for frontend
        for candidate in candidates:
            if candidate.picture_url and not candidate.picture_url.startswith("http"):
                # Make sure the URL is accessible from frontend
                if not candidate.picture_url.startswith("/"):
                    candidate.picture_url = f"/{candidate.picture_url}"

        return candidates
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve candidates: {str(e)}",
        )


@router.get("/{candidate_id}", response_model=CandidateOut)
async def get_candidate(
    candidate_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_admin=Depends(get_current_admin),
):
    """Get a specific candidate"""
    try:
        candidate = await get_candidate_engine(db, candidate_id)
        if not candidate:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Candidate not found"
            )
        return candidate
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve candidate: {str(e)}",
        )


@router.patch("/{candidate_id}", response_model=CandidateOut)
async def update_candidate(
    candidate_id: UUID,
    candidate_data: CandidateUpdate,
    db: AsyncSession = Depends(get_db),
    current_admin = Depends(get_current_admin)
):
    """Update a candidate"""
    try:
        candidate = await update_candidate_engine(db, candidate_id, candidate_data)
        if not candidate:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Candidate not found"
            )
        return candidate
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update candidate: {str(e)}",
        )


@router.delete("/{candidate_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_candidate(
    candidate_id: UUID, 
    db: AsyncSession = Depends(get_db), 
    current_admin = Depends(get_current_admin)
):
    """Delete a candidate"""
    try:
        success = await delete_candidate_engine(db, candidate_id)
        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Candidate not found"
            )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete candidate: {str(e)}",
        )
