"""
backend/routers/auth.py — Authentication endpoints.

Routes
------
  POST /auth/register  — create a new account
  POST /auth/login     — authenticate and receive JWT + refresh token
  POST /auth/logout    — invalidate the caller's current session
  PUT  /auth/password  — change the authenticated user's password

Security properties enforced here
----------------------------------
  • Broken Authentication (OWASP A07)
      - Passwords hashed with Argon2id (memory_cost=64 MB, time_cost=3, p=4)
      - verify_password always runs even when the username does not exist,
        keeping both failure modes at the same ~300 ms (no timing oracle)
      - Generic "Invalid credentials" message for both wrong-user and wrong-
        password to prevent username enumeration
      - Refresh tokens are opaque random strings; only their SHA-256 hash is
        persisted — a DB leak cannot be replayed directly
      - Access tokens carry a "type": "access" claim; _decode_access_token
        rejects refresh tokens used as access tokens (token-confusion guard)
      - Password change invalidates all active sessions (force re-login on
        every device after a credential update)

  • Broken Access Control (OWASP A01)
      - Every protected endpoint depends on get_current_user which verifies
        the JWT signature, checks expiry, checks type claim, and reloads the
        user from the DB (catches deactivated accounts mid-session)
      - Logout verifies session ownership (session.user_id == current_user.id)
        before deactivating — prevents one user deactivating another's session
"""

import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend import models
from backend.crypto import DUMMY_HASH, hash_password, needs_rehash, verify_password
from backend.database import get_db
from backend.dependencies import create_access_token, get_current_user
from backend.limiter import limiter
from backend.schemas import (
    DetailResponse,
    LogoutRequest,
    PasswordChange,
    Token,
    UserCreate,
    UserLogin,
    UserResponse,
)

router = APIRouter(prefix="/auth", tags=["auth"])


# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

# Refresh tokens are 32 random bytes encoded as URL-safe base64 (~43 chars).
# They are opaque to the client — not a JWT, not parseable.
_REFRESH_TOKEN_BYTES: int = 32

# Refresh token lifetime.  Access tokens expire in ACCESS_TOKEN_EXPIRE_MINUTES;
# the refresh token is what survives a browser restart or app reopen.
_REFRESH_LIFETIME_DAYS: int = 30


# ---------------------------------------------------------------------------
# Internal helpers (not exported)
# ---------------------------------------------------------------------------

def _sha256_hex(value: str) -> str:
    """Return the lowercase hex SHA-256 digest of *value* encoded as UTF-8.

    Used to hash refresh tokens before persisting them.  The raw token is
    never stored — if the sessions table is compromised the attacker gets only
    hashes, not replayable tokens.
    """
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _get_active_session(refresh_token: str, db: Session) -> models.Session | None:
    """Look up a Session row by raw refresh token (hashes it internally).

    Returns the Session if it is active and not expired, or None.
    """
    token_hash = _sha256_hex(refresh_token)
    now = datetime.now(timezone.utc)

    stmt = (
        select(models.Session)
        .where(
            models.Session.token_hash == token_hash,
            models.Session.is_active.is_(True),
            # Treat NULL expires_at as "never expires" (future-proof).
            (models.Session.expires_at.is_(None)) | (models.Session.expires_at > now),
        )
    )
    return db.scalars(stmt).first()


# ---------------------------------------------------------------------------
# POST /auth/register
# ---------------------------------------------------------------------------

@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user account",
    responses={
        409: {"description": "Username or email already taken"},
        422: {"description": "Request body failed schema validation"},
    },
)
def register(
    payload: UserCreate,
    db: Session = Depends(get_db),
) -> models.User:
    """Create a new account.

    **Input validation (Pydantic)**
    - `username` — 3–64 characters
    - `email`    — valid RFC 5322 format (via `email-validator`)
    - `password` — 8–128 characters

    **Business logic checks**
    1. Username uniqueness — 409 if already taken
    2. Email uniqueness   — 409 if already registered
    3. Password hashed with Argon2id before any DB write

    Returns the created user object (password hash is **never** included).
    """
    # ------------------------------------------------------------------
    # 1. Username uniqueness
    #    Two separate queries (rather than one OR query) so we can report
    #    which field conflicts.  In a high-security context you'd return a
    #    single generic error; here explicit messages improve developer UX.
    # ------------------------------------------------------------------
    existing_username = db.scalars(
        select(models.User).where(models.User.username == payload.username)
    ).first()
    if existing_username:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username is already taken.",
        )

    # ------------------------------------------------------------------
    # 2. Email uniqueness
    # ------------------------------------------------------------------
    existing_email = db.scalars(
        select(models.User).where(models.User.email == payload.email)
    ).first()
    if existing_email:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email address is already registered.",
        )

    # ------------------------------------------------------------------
    # 3. Hash the password with Argon2id
    #    This is the expensive step (~300 ms, 64 MB RAM).  It runs AFTER
    #    the uniqueness checks so we don't burn CPU on a doomed request.
    # ------------------------------------------------------------------
    hashed_pw = hash_password(payload.password)

    # ------------------------------------------------------------------
    # 4. Persist the new user
    # ------------------------------------------------------------------
    user = models.User(
        username=payload.username,
        email=payload.email,
        hashed_password=hashed_pw,
        public_key=payload.public_key,
    )
    db.add(user)
    db.commit()
    db.refresh(user)   # populate server-generated fields (id, created_at, …)

    # If a public key was supplied at registration (the web client's current
    # flow), register it on-chain in the background — same helper used by
    # POST /users/keys, so a key uploaded either way ends up in KeyRegistry.
    if user.public_key:
        import threading

        from backend.blockchain.registry import submit_key_registration_background

        threading.Thread(
            target=submit_key_registration_background,
            args=(user.id, user.username, user.public_key),
            daemon=True,
        ).start()

    return user


# ---------------------------------------------------------------------------
# POST /auth/login
# ---------------------------------------------------------------------------

@router.post(
    "/login",
    response_model=Token,
    status_code=status.HTTP_200_OK,
    summary="Authenticate and receive tokens",
    responses={
        401: {"description": "Invalid credentials or account disabled"},
        422: {"description": "Request body failed schema validation"},
        429: {"description": "Too many requests"},
    },
)
@limiter.limit("5/minute")
def login(
    payload: UserLogin,
    request: Request,
    db: Session = Depends(get_db),
) -> Token:
    """Authenticate with username + password.

    On success returns:
    - **access_token** — short-lived JWT (default 30 min).  Send as
      `Authorization: Bearer <token>` on every authenticated request.
    - **refresh_token** — long-lived opaque token (30 days).  Send to
      `POST /auth/logout` to invalidate this session.

    **Timing-safe design**\n
    The password hash always runs, even when the username does not exist
    (using an internally stored dummy hash).  Both failure modes — wrong
    username and wrong password — take the same ~300 ms and return the
    same generic 401, preventing username enumeration via response timing.
    """
    # ------------------------------------------------------------------
    # 1. Look up the user — do NOT return early on missing user.
    # ------------------------------------------------------------------
    user = db.scalars(
        select(models.User).where(models.User.username == payload.username)
    ).first()

    # ------------------------------------------------------------------
    # 2. Always run verify_password.
    #    When the user does not exist we verify against DUMMY_HASH so the
    #    function takes the same ~300 ms as a real verify.  The result is
    #    discarded — we still reject below — but the time cost is paid.
    # ------------------------------------------------------------------
    stored_hash = user.hashed_password if user else DUMMY_HASH
    password_ok = verify_password(payload.password, stored_hash)

    # ------------------------------------------------------------------
    # 3. Reject invalid credentials with a generic message.
    #    Same message, same timing for "no such user" and "wrong password".
    # ------------------------------------------------------------------
    if not user or not password_ok:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # ------------------------------------------------------------------
    # 4. Account must be active.
    #    Separate check — a banned user who knows their password must not
    #    receive tokens.
    # ------------------------------------------------------------------
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="This account has been disabled. Please contact support.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # ------------------------------------------------------------------
    # 5. Transparent rehash.
    #    If the stored hash was computed with older/weaker parameters
    #    (e.g. we bumped memory_cost since this user last logged in),
    #    silently upgrade it now while we still have the plaintext.
    # ------------------------------------------------------------------
    if needs_rehash(stored_hash):
        user.hashed_password = hash_password(payload.password)
        db.add(user)
        db.commit()

    # ------------------------------------------------------------------
    # 6. Issue the JWT access token.
    # ------------------------------------------------------------------
    access_token = create_access_token(
        user_id=user.id,
        username=user.username,
    )

    # ------------------------------------------------------------------
    # 7. Generate an opaque refresh token (NOT a JWT — fully revocable).
    #    secrets.token_urlsafe() uses os.urandom(), which is
    #    cryptographically secure on all supported platforms.
    # ------------------------------------------------------------------
    refresh_token = secrets.token_urlsafe(_REFRESH_TOKEN_BYTES)
    refresh_expires = datetime.now(timezone.utc) + timedelta(days=_REFRESH_LIFETIME_DAYS)

    # ------------------------------------------------------------------
    # 8. Persist the session — store only the SHA-256 hash of the token.
    #    If the sessions table leaks, attackers get hashes, not tokens.
    # ------------------------------------------------------------------
    session = models.Session(
        user_id=user.id,
        token_hash=_sha256_hex(refresh_token),
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        expires_at=refresh_expires,
    )
    db.add(session)
    db.commit()

    return Token(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
    )


# ---------------------------------------------------------------------------
# POST /auth/logout
# ---------------------------------------------------------------------------

@router.post(
    "/logout",
    response_model=DetailResponse,
    status_code=status.HTTP_200_OK,
    summary="Invalidate the current session",
    responses={
        401: {"description": "Missing or invalid access token"},
        404: {"description": "Session not found or already invalidated"},
    },
)
def logout(
    body: LogoutRequest,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> DetailResponse:
    """Invalidate the session tied to the provided refresh token.

    Requires **both**:
    - A valid `Authorization: Bearer <access_token>` header (identifies the caller).
    - The `refresh_token` in the request body (identifies which session to kill).

    The two-token requirement means an attacker who steals only the access
    token cannot logout the victim (DoS), and one who steals only the refresh
    token cannot prove identity to call this endpoint.

    The session row's `is_active` flag is set to `False`.  The access token
    remains cryptographically valid until it expires (JWT is stateless), but
    at most 30 minutes of residual validity remain.
    """
    session = _get_active_session(body.refresh_token, db)

    # Verify the session exists AND belongs to the currently authenticated user.
    # Without the ownership check, an attacker who somehow obtains another
    # user's refresh token string could force-logout that user.
    if session is None or session.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found or already invalidated.",
        )

    session.is_active = False
    db.add(session)
    db.commit()

    return DetailResponse(detail="Logged out successfully.")


# ---------------------------------------------------------------------------
# PUT /auth/password
# ---------------------------------------------------------------------------

@router.put(
    "/password",
    response_model=DetailResponse,
    status_code=status.HTTP_200_OK,
    summary="Change the authenticated user's password",
    responses={
        400: {"description": "Old password incorrect, or new password unchanged"},
        401: {"description": "Missing or invalid access token"},
        422: {"description": "Request body failed schema validation"},
    },
)
def change_password(
    body: PasswordChange,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> DetailResponse:
    """Change the current user's password.

    **Requires (in addition to `Authorization: Bearer`):**
    - `old_password` — the current password; prevents account takeover on an
      unattended session (someone who found the access token cannot silently
      change the password without knowing the current one).
    - `new_password` — 8–128 characters; must differ from the current password.

    **After a successful change:**
    - All active sessions (refresh tokens on every device) are invalidated.
    - The caller must log in again with the new password to obtain fresh tokens.
    - This is the correct security posture: a password change is a signal that
      the credential has changed; all prior sessions are potentially compromised.
    """
    # ------------------------------------------------------------------
    # 1. Verify the current password.
    #    Returns 400, not 401, because the user IS authenticated via the
    #    access token — this is a bad request (wrong confirmation password),
    #    not an authentication failure.
    # ------------------------------------------------------------------
    if not verify_password(body.old_password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect.",
        )

    # ------------------------------------------------------------------
    # 2. Reject no-op: new password must differ from old.
    #    We re-use verify_password here rather than a plain equality check
    #    because two different strings can hash to the same Argon2id output
    #    only with a collision (impossible in practice), so this is correct.
    # ------------------------------------------------------------------
    if verify_password(body.new_password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password must be different from the current password.",
        )

    # ------------------------------------------------------------------
    # 3. Hash and persist the new password.
    # ------------------------------------------------------------------
    current_user.hashed_password = hash_password(body.new_password)
    db.add(current_user)

    # ------------------------------------------------------------------
    # 4. Invalidate ALL active sessions for this user.
    #    After a password change every existing refresh token is stale.
    #    We bulk-update rather than load each row to minimise round-trips.
    # ------------------------------------------------------------------
    db.execute(
        models.Session.__table__.update()
        .where(models.Session.user_id == current_user.id)
        .where(models.Session.is_active.is_(True))
        .values(is_active=False)
    )

    db.commit()

    return DetailResponse(
        detail="Password updated successfully. Please log in again on all devices."
    )
