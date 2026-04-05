"""
Database Configuration

SQLAlchemy database setup for user authentication and session management.
Supports SQLite (development) and PostgreSQL (production).
"""

from sqlalchemy import create_engine, event
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import NullPool
from typing import Generator
import os
from pathlib import Path

from config.config import get_config

# Create database directory for SQLite
DB_DIR = Path(__file__).parent.parent.parent / "data"
DB_DIR.mkdir(exist_ok=True)

# Get configuration
config = get_config()
DATABASE_URL = config.get("database_url") or f"sqlite:///{DB_DIR / 'decepticon.db'}"

# Determine database type
is_sqlite = DATABASE_URL.startswith("sqlite")
is_postgresql = DATABASE_URL.startswith("postgresql")

# Engine configuration based on database type
engine_kwargs = {
    "echo": not config.is_production,  # Log SQL queries in development
}

if is_sqlite:
    # SQLite specific configuration
    engine_kwargs["connect_args"] = {"check_same_thread": False}
elif is_postgresql:
    # PostgreSQL specific configuration
    pool_size = int(config.get("db_pool_size", 10))
    max_overflow = int(config.get("db_max_overflow", 20))
    pool_timeout = int(config.get("db_pool_timeout", 30))
    pool_recycle = int(config.get("db_pool_recycle", 3600))
    
    engine_kwargs["pool_size"] = pool_size
    engine_kwargs["max_overflow"] = max_overflow
    engine_kwargs["pool_timeout"] = pool_timeout
    engine_kwargs["pool_recycle"] = pool_recycle
    engine_kwargs["pool_pre_ping"] = True  # Verify connections before using

# Create engine
engine = create_engine(DATABASE_URL, **engine_kwargs)

# Enable foreign key constraints for SQLite
if is_sqlite:
    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_conn, connection_record):
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

# Session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base class for models
Base = declarative_base()


def get_db() -> Generator[Session, None, None]:
    """
    Get database session
    
    Yields:
        Database session
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """Initialize database tables"""
    # Import models to register them with Base
    from src.auth import db_models  # noqa: F401
    
    Base.metadata.create_all(bind=engine)
    
    db_type = "PostgreSQL" if is_postgresql else "SQLite"
    print(f"✅ Database initialized ({db_type}): {DATABASE_URL}")


def reset_db():
    """Reset database (drop all tables and recreate)"""
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    print("[OK] Database reset complete")


def get_db_info() -> dict:
    """Get database information"""
    return {
        "type": "postgresql" if is_postgresql else "sqlite",
        "url": DATABASE_URL.split("@")[-1] if "@" in DATABASE_URL else DATABASE_URL,
        "is_production": config.is_production,
        "pool_size": engine.pool.size() if is_postgresql else None,
    }


def health_check() -> bool:
    """Check database health"""
    try:
        from sqlalchemy import text
        db = next(get_db())
        db.execute(text("SELECT 1"))
        db.close()
        return True
    except Exception as e:
        print(f"[WARN] Database health check failed: {e}")
        return False
