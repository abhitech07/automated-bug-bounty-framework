from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
from src.api import recon
from sqlalchemy.orm import Session

from src.core.config import settings
from src.core.database import get_db, create_tables
from src.core import models

# Initialize FastAPI app
app = FastAPI(
    title=settings.APP_NAME,
    description="API for the AI-assisted bug bounty pentesting framework",
    version=settings.APP_VERSION
)
app.include_router(recon.router)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, replace with specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Create tables on startup (for development)
@app.on_event("startup")
def on_startup():
    if settings.DEBUG:
        create_tables()
        print("Development mode: Database tables verified/created.")

# Health check endpoint
@app.get("/")
async def root():
    return {
        "message": settings.APP_NAME,
        "status": "operational",
        "version": settings.APP_VERSION
    }

@app.get("/health")
async def health_check():
    return {"status": "healthy", "database": "connected"}

# Test database endpoint
@app.get("/api/test-db")
async def test_db(db: Session = Depends(get_db)):
    try:
        # Try a simple query
        result = db.execute("SELECT version()").fetchone()
        return {"database": "connected", "version": result[0]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database connection failed: {str(e)}")

from src import schemas

@app.post("/api/targets/", response_model=schemas.TargetResponse)
def create_target(target: schemas.TargetCreate, db: Session = Depends(get_db)):
    db_target = models.Target(**target.dict())
    db.add(db_target)
    db.commit()
    db.refresh(db_target)
    return db_target

# This allows running with: python src/main.py
if __name__ == "__main__":
    uvicorn.run(
        "src.main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.DEBUG
    )