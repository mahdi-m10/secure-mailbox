"""
main.py — FastAPI application entry point.

Start the server with:
    uvicorn backend.main:app --reload
"""

from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from backend.database import engine
from backend import models
from backend.limiter import limiter
from backend.routers import auth as auth_router
from backend.routers import files as files_router
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
    title="Secure Mailbox API",
    description="End-to-end encrypted asynchronous file mailbox backend (university project).",
    version="0.2.0",
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
# Request body size limit
#
# FastAPI/Starlette impose NO default body size limit — without this an
# attacker (or a buggy client) could POST an arbitrarily large JSON body and
# exhaust memory.  16 MiB comfortably fits the ~8 MiB-plaintext upload cap
# (see schemas.MAX_CIPHERTEXT_B64_LEN) plus JSON overhead.
#
# Limitation: this checks the Content-Length header, so a chunked request
# without one bypasses it — the schema-level ciphertext cap still applies
# after parsing.  Noted for the pentest report.
# ---------------------------------------------------------------------------
MAX_REQUEST_BODY_BYTES: int = 16 * 1024 * 1024


@app.middleware("http")
async def limit_body_size(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if content_length and content_length.isdigit() and int(content_length) > MAX_REQUEST_BODY_BYTES:
        return JSONResponse(
            status_code=413,
            content={"detail": "Request body too large."},
        )
    return await call_next(request)


# ---------------------------------------------------------------------------
# Security headers
# ---------------------------------------------------------------------------
@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    # connect-src includes the public Sepolia RPC endpoint: the web client
    # reads the KeyRegistry contract DIRECTLY (docs/crypto-design.md
    # §8.11(f)) — proxying that check through this server would let a
    # compromised server answer its own integrity check.
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline' https://unpkg.com; style-src 'self' 'unsafe-inline'; connect-src 'self' https://team10.theburkenator.com https://ethereum-sepolia-rpc.publicnode.com"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response

# ---------------------------------------------------------------------------
# Routers
# ---------------------------------------------------------------------------

app.include_router(auth_router.router)
app.include_router(files_router.router)
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
# Accessible at /app/index.html, /app/files.html, etc.
# ---------------------------------------------------------------------------
_web_client = Path(__file__).parent.parent / "web-client"
app.mount("/app", StaticFiles(directory=_web_client, html=True), name="web-client")
