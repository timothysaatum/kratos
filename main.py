"""
Main entry point for the Election System API
Initializes FastAPI app, config, and database integration
"""

import os
import uvicorn
from fastapi import FastAPI, Depends
from app.core.config import Settings
from app.core.database import get_db
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from app.api.electorate_router import router as electorate_router
from app.api.auth_router import router as auth_router
from app.api.voting_router import router as voting_router
from app.api.portfolio_router import router as portfolio_router
from app.api.admin_router import router as admin_router
from app.api.results_router import router as results_router
from app.api.candidate_routes import router as candidate_router


settings = Settings()


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.VERSION,
    description=settings.DESCRIPTION,
    debug=settings.DEBUG,
    openapi_url="/openapi.json",
    docs_url="/docs",
    redoc_url="/redoc",
)

# Register routers
app.include_router(admin_router, prefix=settings.API_PREFIX)
app.include_router(candidate_router, prefix=settings.API_PREFIX)
app.include_router(portfolio_router, prefix=settings.API_PREFIX)
app.include_router(electorate_router, prefix=settings.API_PREFIX)
app.include_router(auth_router, prefix=settings.API_PREFIX)
app.include_router(voting_router, prefix=settings.API_PREFIX)
app.include_router(results_router, prefix=settings.API_PREFIX)

origins = [
    "http://localhost:3000",
    "https://kratos-ui.vercel.app/"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

UPLOAD_DIR = "uploads"
CANDIDATE_UPLOAD_DIR = os.path.join(UPLOAD_DIR, "candidates")
os.makedirs(CANDIDATE_UPLOAD_DIR, exist_ok=True)

# Mount static files for serving uploaded images
app.mount("/uploads", StaticFiles(directory=UPLOAD_DIR), name="uploads")

# Example root endpoint
@app.get("/")
async def root():
    return {"message": f"Welcome to {settings.APP_NAME}"}


# Example endpoint using async DB session
@app.get("/healthcheck")
async def healthcheck(db=Depends(get_db)):
    return {"status": "ok"}


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.RELOAD,
        workers=settings.WORKERS,
    )
