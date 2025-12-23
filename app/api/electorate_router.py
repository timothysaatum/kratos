from uuid import UUID
from fastapi import (
    APIRouter, 
    Depends, 
    HTTPException, 
    status, 
    UploadFile, 
    File
    )
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List
from app.crud.crud_electorates import (
    get_electorates,
    create_electorate,
    update_electorate,
    delete_electorate,
    bulk_create_electorates,
)
from app.schemas.electorates import (
    ElectorateOut, 
    ElectorateCreate, 
    ElectorateUpdate
    )
from app.core.database import get_db
import pandas as pd
from io import BytesIO
from app.middleware.auth_middleware import get_current_admin
router = APIRouter(prefix="/electorates", tags=["Electorates"])


@router.get("/", response_model=List[ElectorateOut])
async def list_electorates(
    skip: int = 0, 
    limit: int = 100, 
    db: AsyncSession = Depends(get_db),
    current_admin = Depends(get_current_admin)
):
    return await get_electorates(db, skip=skip, limit=limit)


@router.patch("/{electorate_id}", response_model=ElectorateOut)
async def update_electorate_route(
    electorate_id: UUID, 
    updates: ElectorateUpdate, 
    db: AsyncSession = Depends(get_db),
    current_admin = Depends(get_current_admin)
):
    updated = await update_electorate(db, electorate_id, updates)
    if not updated:
        raise HTTPException(status_code=404, detail="Electorate not found")
    return updated


@router.post("/", response_model=ElectorateOut, status_code=status.HTTP_201_CREATED)
async def create_electorate_route(
    electorate: ElectorateCreate, 
    db: AsyncSession = Depends(get_db),
    current_admin = Depends(get_current_admin)
):
    print(electorate)
    return await create_electorate(db, electorate)


@router.delete("/{electorate_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_electorate_route(
    electorate_id: UUID, 
    db: AsyncSession = Depends(get_db),
    current_admin = Depends(get_current_admin)
):
    deleted = await delete_electorate(db, electorate_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Electorate not found")
    return None


@router.post(
    "/bulk", response_model=List[ElectorateOut], status_code=status.HTTP_201_CREATED
)
async def bulk_create_electorates_route(
    electorates: List[ElectorateCreate], 
    db: AsyncSession = Depends(get_db),
    current_admin = Depends(get_current_admin)
):
    return await bulk_create_electorates(db, electorates)


@router.post(
    "/bulk-upload",
    response_model=List[ElectorateOut],
    status_code=status.HTTP_201_CREATED,
)
async def bulk_upload_electorates(
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    current_admin=Depends(get_current_admin),
):
    # Get file extension
    file_extension = file.filename.lower().split(".")[-1]

    if file_extension not in ["xlsx", "xls", "csv"]:
        raise HTTPException(
            status_code=400, detail="Only Excel and CSV files are supported."
        )

    contents = await file.read()

    # Read based on file type
    if file_extension == "csv":
        df = pd.read_csv(BytesIO(contents))
    elif file_extension == "xlsx":
        df = pd.read_excel(BytesIO(contents), engine="openpyxl")
    else:  # xls
        df = pd.read_excel(BytesIO(contents), engine="xlrd")

    # Expecting a column named 'student_id' and optionally others
    if "student_id" not in df.columns:
        raise HTTPException(
            status_code=400, detail="Excel must have a 'student_id' column."
        )

    electorate_list = []
    for row in df.to_dict(orient="records"):
        student_id = str(row.get("student_id", "")).strip()
        if not student_id or student_id == "nan":
            continue

        electorate = ElectorateCreate(
            student_id=student_id,
            program=str(row.get("program")) if pd.notna(row.get("program")) else None,
            year_level=(
                int(row.get("year_level")) if pd.notna(row.get("year_level")) else None
            ),
            phone_number=(
                str(row.get("phone_number"))
                if pd.notna(row.get("phone_number"))
                else None
            ),
            email=str(row.get("email")) if pd.notna(row.get("email")) else None,
        )
        electorate_list.append(electorate)

    return await bulk_create_electorates(db, electorate_list)
