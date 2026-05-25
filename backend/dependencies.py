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
from datetime import datetime, timedelta, timezone
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
        token_type: str | None = payload.get("type")

        # Reject missing subject OR wrong token type.
        # The type guard prevents a refresh token (type="refresh") from being
        # accepted as an access token — a "confused deputy" / token-confusion
        # attack that would let an attacker with only a refresh token call
        # protected endpoints.
        if user_id is None or token_type != "access":
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


# ---------------------------------------------------------------------------
# Token factory — used by the login endpoint to issue access tokens
# ---------------------------------------------------------------------------

def create_access_token(
    user_id: int,
    username: str,
    expires_delta: timedelta | None = None,
) -> str:
    """
    Build and sign a JWT access token for the given user.

    Payload claims
    --------------
    sub      — user ID as a string (RFC 7519 §4.1.2: "sub" SHOULD be a string)
    username — convenience claim; avoids an extra DB round-trip in simple reads
    iat      — issued-at timestamp (UTC)
    exp      — expiry timestamp (UTC); defaults to ACCESS_TOKEN_EXPIRE_MINUTES
    type     — literal "access"; guards against refresh tokens being used here
               (checked in _decode_access_token)

    Parameters
    ----------
    user_id:
        Primary key of the authenticated user.
    username:
        Username string embedded as a convenience claim.
    expires_delta:
        Custom lifetime.  Defaults to ACCESS_TOKEN_EXPIRE_MINUTES from .env.

    Returns
    -------
    str
        A signed, compact JWT string ready to return in the Token response.
    """
    now = datetime.now(timezone.utc)
    expire = now + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))

    payload: dict = {
        "sub": str(user_id),   # string per RFC 7519
        "username": username,
        "iat": now,
        "exp": expire,
        # Explicit type discriminator — _decode_access_token rejects anything
        # other than "access" so a refresh token cannot be used as an access
        # token even if it were somehow a valid JWT.
        "type": "access",
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
