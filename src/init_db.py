#!/usr/bin/env python3
"""
Database initialization script.
Run this once to create all tables.
"""
import sys
sys.path.insert(0, '.')

from src.core.database import create_tables, engine
from src.core.config import settings

if __name__ == "__main__":
    print(f"Initializing database: {settings.POSTGRES_DB} on {settings.POSTGRES_HOST}:{settings.POSTGRES_PORT}")
    create_tables()
    print("Database initialization complete.")