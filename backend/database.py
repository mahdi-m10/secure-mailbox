"""
database.py — SQLite connection and SQLAlchemy session factory.

SQLAlchemy 2.0 style:
  • Engine created with create_engine()
  • Sessions managed via SessionLocal / get_db() dependency
"""

import os

from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase

load_dotenv()

# ---------------------------------------------------------------------------
# Database URL
# Read from the DATABASE_URL environment variable (see .env.example); the
# default below is used only when it is unset. The .db file is created in the
# process's working directory on first start.
# Set DATABASE_URL to a PostgreSQL / MySQL URL when moving to production.
# ---------------------------------------------------------------------------
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./secure_mailbox.db")

# SQLite needs check_same_thread=False (FastAPI serves requests on multiple
# threads); other backends reject that argument, so only pass it for SQLite.
_connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------
engine = create_engine(
    DATABASE_URL,
    connect_args=_connect_args,
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
