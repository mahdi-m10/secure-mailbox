"""
backend/routers/users.py — User and public-key discovery endpoints.

Routes
------
  GET  /users              — list all active users with their public keys
  GET  /users/{username}   — retrieve one user's public key by username
  POST /users/keys         — upload or replace the authenticated user's
                             HPKE public key (requires JWT)

Design rationale
----------------
These endpoints exist to support HPKE key exchange.  Before Alice can send
Bob an encrypted message she must fetch his X25519 public key.  The two
GET endpoints are intentionally unauthenticated — requiring a login to
look up a public key would prevent a user from composing a message before
they have a valid access token, and public keys are, by definition, public.

Privacy: the GET endpoints return only (id, username, public_key).  They
deliberately omit email and all other PII.  An unauthenticated endpoint
that returned email addresses would let any anonymous caller harvest the
entire user list with contact details.

Key validation: POST /users/keys accepts only base64-encoded values that
decode to exactly 32 bytes — the X25519 key size enforced by generate_keypair()
in backend/crypto/hpke.py.  Uploading a key of the wrong size would silently
break HPKE for all future senders, so we reject it at the schema layer.

TOFU (Trust On First Use): the server stores whatever public key the user
uploads and returns it to senders without verification.  Senders trust the
first key they see for a given username and warn on any subsequent change.
This is the same trust model used by Signal (safety numbers) and WhatsApp.
See backend/crypto/hpke.py for the full TOFU explanation.
"""

import threading

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend import models
from backend.database import get_db
from backend.dependencies import get_current_user
from backend.schemas import OnChainKeyInfo, PublicKeyUpload, UserPublicKeyResponse

router = APIRouter(prefix="/users", tags=["users"])


# ---------------------------------------------------------------------------
# GET /users
# ---------------------------------------------------------------------------

@router.get(
    "",
    response_model=list[UserPublicKeyResponse],
    summary="List all users and their public keys",
)
def list_users(
    db: Session = Depends(get_db),
    skip:  int = Query(default=0,   ge=0,          description="Pagination offset."),
    limit: int = Query(default=100, ge=1, le=500,  description="Max users to return."),
) -> list[models.User]:
    """Return a paginated list of all active users with their HPKE public keys.

    No authentication required — public keys are, by definition, public.

    Only active users are included.  Users without a public key are still
    listed (``public_key`` is ``null``) so senders can see who exists even
    if they have not yet uploaded a key.

    Response fields: ``id``, ``username``, ``public_key`` only.
    Email and other PII are intentionally excluded.
    """
    return db.scalars(
        select(models.User)
        .where(models.User.is_active.is_(True))
        .order_by(models.User.username.asc())
        .offset(skip)
        .limit(limit)
    ).all()


# ---------------------------------------------------------------------------
# GET /users/{username}
# ---------------------------------------------------------------------------

@router.get(
    "/{username}",
    response_model=UserPublicKeyResponse,
    summary="Get a specific user's public key",
    responses={
        404: {"description": "User not found or inactive"},
    },
)
def get_user(
    username: str,
    db: Session = Depends(get_db),
    onchain: bool = Query(
        default=False,
        description=(
            "If true, also perform a LIVE KeyRegistry read for this user and "
            "return it under `onchain`. Adds an RPC round trip — off by "
            "default. Not offered on the bulk /users listing (would mean "
            "one RPC call per user returned)."
        ),
    ),
) -> UserPublicKeyResponse:
    """Return a single active user's HPKE public key by username.

    No authentication required.

    This is the primary key-discovery endpoint used before composing a
    message: Alice calls ``GET /users/bob`` to retrieve Bob's X25519 public
    key, which she passes to ``encapsulate()`` as ``recipient_public_key``.

    Returns 404 for both non-existent and inactive users — distinguishing
    between the two would let an attacker determine which usernames once
    existed (account enumeration).

    ``?onchain=1`` additionally performs a live KeyRegistry.getKey() call
    and returns it under ``onchain``. This is informational only — it is
    NOT the security gate (that lives client-side, per
    docs/crypto-design.md §3(d)1/§8.1) — so an RPC failure here never fails
    the request; ``onchain`` is null and ``onchain_error`` explains why.
    """
    user = db.scalars(
        select(models.User).where(
            models.User.username == username,
            models.User.is_active.is_(True),
        )
    ).first()

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )

    result = UserPublicKeyResponse.model_validate(user)

    if onchain:
        try:
            from backend.blockchain.registry import get_onchain_key

            info = get_onchain_key(username)
            result.onchain = OnChainKeyInfo(**info, tx_hash=user.eth_key_tx)
        except Exception as exc:
            result.onchain_error = str(exc)

    return result


# ---------------------------------------------------------------------------
# POST /users/keys
# ---------------------------------------------------------------------------

@router.post(
    "/keys",
    response_model=UserPublicKeyResponse,
    summary="Upload or replace the authenticated user's HPKE public key",
    responses={
        401: {"description": "Missing or invalid access token"},
        422: {"description": "public_key is not valid base64 or not 32 bytes"},
    },
)
def upload_public_key(
    body: PublicKeyUpload,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> models.User:
    """Upload or replace the current user's X25519 HPKE public key.

    Requires a valid ``Authorization: Bearer`` access token.

    The ``public_key`` field must be:
    - Valid standard base64
    - Decode to exactly **32 bytes** (the X25519 / HPKE key size)

    Typical client flow:
    ```python
    priv, pub = generate_keypair()          # from backend/crypto/hpke.py
    # store priv securely on device, never transmit it
    encoded = base64.b64encode(pub).decode()
    POST /users/keys  { "public_key": encoded }
    ```

    After upload, other users can fetch this key via ``GET /users/{username}``
    and use it as ``recipient_public_key`` in ``encapsulate()``.

    **Key rotation warning:** replacing a public key invalidates all
    in-flight messages that were encrypted to the old key — senders who
    fetched the old key before the rotation cannot reach the user until
    they re-fetch.  Clients implementing TOFU will show a "key changed"
    warning to senders who stored the previous fingerprint.
    """
    # Pydantic has already validated that body.public_key is valid base64
    # and decodes to exactly 32 bytes before this function is called.
    current_user.public_key = body.public_key
    db.add(current_user)
    db.commit()
    db.refresh(current_user)

    # Register (first time) or rotate (subsequent uploads) the key on-chain
    # in the background — never delays this response on an RPC round trip.
    from backend.blockchain.registry import submit_key_registration_background

    threading.Thread(
        target=submit_key_registration_background,
        args=(current_user.id, current_user.username, body.public_key),
        daemon=True,
    ).start()

    return current_user
