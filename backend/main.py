"""
main.py — FastAPI application entry point.

Start the server with:
    uvicorn backend.main:app --reload
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.database import engine
from backend import models

# ---------------------------------------------------------------------------
# Create all tables on startup (safe to call repeatedly – only creates new
# tables, does not drop existing ones).
# ---------------------------------------------------------------------------
models.Base.metadata.create_all(bind=engine)

# ---------------------------------------------------------------------------
# App instance
# ---------------------------------------------------------------------------
app = FastAPI(
    title="Secure Messenger API",
    description="End-to-end encrypted messaging backend (university project).",
    version="0.1.0",
)

# ---------------------------------------------------------------------------
# CORS – tighten origins for production
# ---------------------------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # TODO: restrict to frontend origin in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/health", tags=["meta"])
def health_check():
    """Liveness probe — returns 200 when the server is running."""
    return {"status": "ok", "version": app.version}
