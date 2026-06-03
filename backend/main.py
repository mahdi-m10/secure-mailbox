"""
main.py — FastAPI application entry point.

Start the server with:
    uvicorn backend.main:app --reload
"""

from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from backend.database import engine
from backend import models
from backend.limiter import limiter
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

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ---------------------------------------------------------------------------
# CORS
# ---------------------------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://team10.theburkenator.com"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)

# ---------------------------------------------------------------------------
# Security headers
# ---------------------------------------------------------------------------
@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline' https://unpkg.com; style-src 'self' 'unsafe-inline'; connect-src 'self' https://team10.theburkenator.com"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response

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
