"""
schemas.py — Pydantic v2 request / response models.

Keeps API contracts separate from database models.
"""

from datetime import datetime
from pydantic import BaseModel, EmailStr, Field, ConfigDict


# ===========================================================================
# User schemas
# ===========================================================================

class UserCreate(BaseModel):
    """Payload for POST /users — registering a new account."""

    username: str = Field(..., min_length=3, max_length=64, examples=["alice"])
    email: EmailStr = Field(..., examples=["alice@example.com"])
    password: str = Field(..., min_length=8, max_length=128, examples=["s3cur3P@ss"])
    public_key: str | None = Field(
        default=None,
        description="PEM/base64-encoded public key for end-to-end encryption.",
    )


class UserLogin(BaseModel):
    """Payload for POST /auth/login."""

    # max_length caps are purely a DoS guard: an attacker sending a 10 MB
    # password string would force the server to run Argon2id over it (64 MB RAM
    # per attempt × unbounded string length). We do NOT add min_length here —
    # short/wrong credentials should fail with "Invalid credentials", not a
    # Pydantic 422, so we don't leak which field is wrong via the error path.
    username: str = Field(..., max_length=64)
    password: str = Field(..., max_length=128)


class UserResponse(BaseModel):
    """Safe user representation returned by the API (no password hash)."""

    model_config = ConfigDict(from_attributes=True)   # replaces orm_mode in Pydantic v2

    id: int
    username: str
    email: EmailStr
    public_key: str | None
    is_active: bool
    created_at: datetime


# ===========================================================================
# Message schemas
# ===========================================================================

class MessageCreate(BaseModel):
    """Payload for POST /messages — sending an encrypted message."""

    recipient_ids: list[int] = Field(
        ...,
        min_length=1,
        description="One or more user IDs that should receive this message.",
    )
    ciphertext: str = Field(
        ...,
        description="Base64-encoded encrypted message payload.",
    )
    subject: str | None = Field(
        default=None,
        max_length=512,
        description="Optional (possibly encrypted) subject line.",
    )
    encrypted_keys: dict[int, str] = Field(
        default_factory=dict,
        description=(
            "Mapping of recipient_id → wrapped symmetric key "
            "(encrypted with that recipient's public key)."
        ),
    )
    integrity_hash: str | None = Field(
        default=None,
        description="HMAC / SHA-256 integrity tag for tamper detection.",
    )


class MessageResponse(BaseModel):
    """Message representation returned by the API."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    sender_id: int | None
    ciphertext: str
    subject: str | None
    integrity_hash: str | None
    is_deleted: bool
    created_at: datetime


# ===========================================================================
# Auth / token schemas
# ===========================================================================

class Token(BaseModel):
    """JWT token pair returned after successful login."""

    access_token: str
    refresh_token: str | None = None
    token_type: str = "bearer"


class TokenData(BaseModel):
    """Claims extracted from a decoded JWT access token."""

    user_id: int | None = None
    username: str | None = None


# ===========================================================================
# Generic response wrappers
# ===========================================================================

class MessageOut(BaseModel):
    """Generic success message envelope."""

    detail: str


# ===========================================================================
# Auth operation schemas
# ===========================================================================

class LogoutRequest(BaseModel):
    """Body for POST /auth/logout — identifies which session to invalidate."""

    # The raw opaque refresh token returned at login.  The server hashes it
    # (SHA-256) and looks up the matching row in the sessions table.
    # Requiring it here ensures logout is tied to a specific device/session
    # rather than blindly wiping all sessions.
    refresh_token: str = Field(
        ...,
        min_length=1,
        description="The opaque refresh token issued at login.",
    )


class PasswordChange(BaseModel):
    """Body for PUT /auth/password — change the authenticated user's password."""

    # We verify old_password before accepting the change to prevent account
    # takeover on an unattended screen.  max_length prevents DoS via the
    # Argon2id verify call; we deliberately skip min_length so the error is
    # "Current password is incorrect" rather than a Pydantic 422.
    old_password: str = Field(
        ...,
        max_length=128,
        description="The user's current password (required for verification).",
    )

    # New password enforces the same policy as registration: 8–128 chars.
    new_password: str = Field(
        ...,
        min_length=8,
        max_length=128,
        description="The desired new password (min 8, max 128 characters).",
    )
