from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from src.core.config import settings

# Create the SQLAlchemy engine
engine = create_engine(
    settings.DATABASE_URL,
    pool_pre_ping=True,  # Checks connection is alive before using it
    echo=settings.DEBUG   # Logs SQL queries in debug mode
)

# Create a configured "Session" class
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Dependency to get DB session for FastAPI
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Function to create all tables (run this once)
def create_tables():
    from src.core.models import Base
    Base.metadata.create_all(bind=engine)
    print("✅ Database tables created successfully.")