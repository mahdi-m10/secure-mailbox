"""
dependencies.py — Reusable FastAPI dependency functions.

Currently contains:
  • get_current_user() — JWT auth dependency (placeholder ready to wire up)
  • get_db re-exported for convenience

Environment variables (loaded from .env via python-dotenv):
  SECRET_KEY                  — HS256 signing key (required)
  ALGORITHM                   — JWT algorithm, default HS256
  ACCESS_TOKEN_EXPIRE_MINUTES — token lifetime in minutes, default 30
"""

import os
from pathlib import Path

from dotenv import load_dotenv
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from sqlalchemy.orm import Session

from backend.database import get_db
from backend import models
from backend.schemas import TokenData

# ---------------------------------------------------------------------------
# Load .env — walk up from this file's directory to find the project root.
# override=False means real environment variables always win over .env values,
# which is the correct behaviour for containerised / CI deployments.
# ---------------------------------------------------------------------------
_env_path = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(dotenv_path=_env_path, override=False)

# ---------------------------------------------------------------------------
# Configuration — read from environment (populated by .env during development,
# injected directly as env-vars in production/CI).
# ---------------------------------------------------------------------------
SECRET_KEY: str = os.environ.get(
    "SECRET_KEY",
    # Hard fallback raises loudly so a misconfigured deploy is obvious.
    "",
)
if not SECRET_KEY:
    raise RuntimeError(
        "SECRET_KEY environment variable is not set. "
        "Add it to your .env file or export it before starting the server."
    )

ALGORITHM: str = os.environ.get("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES: int = int(
    os.environ.get("ACCESS_TOKEN_EXPIRE_MINUTES", "30")
)

# OAuth2 scheme — points to the login endpoint that issues tokens
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


# ---------------------------------------------------------------------------
# JWT helper — decode and validate an access token
# ---------------------------------------------------------------------------
def _decode_access_token(token: str) -> TokenData:
    """
    Decode a JWT access token and return its claims as TokenData.

    Raises HTTP 401 if the token is invalid or expired.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: int | None = payload.get("sub")
        username: str | None = payload.get("username")
        if user_id is None:
            raise credentials_exception
        return TokenData(user_id=int(user_id), username=username)
    except JWTError:
        raise credentials_exception


# ---------------------------------------------------------------------------
# FastAPI dependency — resolve the current authenticated user
# ---------------------------------------------------------------------------
def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> models.User:
    """
    Dependency that extracts and validates the Bearer token from the
    Authorization header, then loads the corresponding user from the DB.

    Usage in a route:
        from backend.dependencies import get_current_user

        @app.get("/me")
        def read_me(current_user: models.User = Depends(get_current_user)):
            return current_user
    """
    token_data = _decode_access_token(token)

    user = db.get(models.User, token_data.user_id)
    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


# ---------------------------------------------------------------------------
# Optional auth — returns None instead of raising when no token is provided
# (useful for endpoints that serve both public and authenticated responses)
# ---------------------------------------------------------------------------
def get_optional_user(
    token: str | None = Depends(oauth2_scheme),   # OAuth2 scheme won't raise here
    db: Session = Depends(get_db),
) -> models.User | None:
    """
    Like get_current_user but returns None instead of 401 when unauthenticated.
    """
    if token is None:
        return None
    try:
        return get_current_user(token=token, db=db)
    except HTTPException:
        return None
