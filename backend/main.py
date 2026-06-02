"""
main.py — FastAPI application entry point.

Start the server with:
    uvicorn backend.main:app --reload
"""

from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from backend.database import engine
from backend import models
from backend.routers import auth as auth_router
from backend.routers import messages as messages_router
from backend.routers import users as users_router

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
# Routers
# ---------------------------------------------------------------------------

app.include_router(auth_router.router)
app.include_router(messages_router.router)
app.include_router(users_router.router)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/health", tags=["meta"])
def health_check():
    """Liveness probe — returns 200 when the server is running."""
    return {"status": "ok", "version": app.version}


# ---------------------------------------------------------------------------
# Static files — web client
# Must be mounted AFTER all API routes so the API routes take precedence.
# Accessible at /app/index.html, /app/chat.html, etc.
# ---------------------------------------------------------------------------
_web_client = Path(__file__).parent.parent / "web-client"
app.mount("/app", StaticFiles(directory=_web_client, html=True), name="web-client")
