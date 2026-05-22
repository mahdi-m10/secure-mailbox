"""
database.py — SQLite connection and SQLAlchemy session factory.

SQLAlchemy 2.0 style:
  • Engine created with create_engine()
  • Sessions managed via SessionLocal / get_db() dependency
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase

# ---------------------------------------------------------------------------
# Database URL
# The .db file will be created in the project root when the app starts.
# Change this to a PostgreSQL / MySQL URL when moving to production.
# ---------------------------------------------------------------------------
DATABASE_URL = "sqlite:///./secure_messenger.db"

# ---------------------------------------------------------------------------
# Engine
# connect_args={"check_same_thread": False} is required for SQLite because
# FastAPI runs requests on multiple threads.
# ---------------------------------------------------------------------------
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
    echo=False,          # set True to log every SQL statement (useful during dev)
)

# ---------------------------------------------------------------------------
# Session factory
# ---------------------------------------------------------------------------
SessionLocal = sessionmaker(
    bind=engine,
    autocommit=False,
    autoflush=False,
)

# ---------------------------------------------------------------------------
# Declarative base — all ORM models inherit from this
# ---------------------------------------------------------------------------
class Base(DeclarativeBase):
    """Shared declarative base for all SQLAlchemy models."""
    pass


# ---------------------------------------------------------------------------
# FastAPI dependency — yields a database session per request
# ---------------------------------------------------------------------------
def get_db():
    """
    Yield a database session for the duration of a request, then close it.

    Usage in a route:
        from backend.database import get_db
        from sqlalchemy.orm import Session
        from fastapi import Depends

        @app.get("/example")
        def example(db: Session = Depends(get_db)):
            ...
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
