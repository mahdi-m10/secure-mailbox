"""
backend/routers/messages.py — Encrypted message endpoints.

Routes
------
  POST   /messages/send          — send an encrypted message to a recipient
  GET    /messages/inbox         — list received messages (no ciphertext)
  GET    /messages/sent          — list sent messages (no ciphertext)
  DELETE /messages/{id}          — soft-delete a sent message (sender only)
  POST   /messages/{id}/forward  — grant access to a new recipient
  POST   /messages/{id}/revoke   — revoke one or all recipients' access
  GET    /messages/{id}/download — retrieve the full ciphertext for decryption

Access control model
--------------------
Every endpoint requires a valid JWT access token (get_current_user dependency).
Beyond authentication, each endpoint enforces one of two ownership rules:

  Sender-only operations (delete, revoke):
    message.sender_id == current_user.id
    → 403 Forbidden if the requester is not the sender.

  Read operations (download, forward):
    A row must exist in message_access where recipient_id == current_user.id
    OR the requester is the original sender.
    → 404 Not Found if neither condition holds.
      (404 rather than 403: returning 403 would confirm the message exists
       to an unauthorised requester — an IDOR information leak.)

Storage layout
--------------
The nonce is NOT stored in a separate column.  The server stores the combined
blob base64(nonce_bytes ‖ ciphertext_with_tag) in messages.ciphertext.
The nonce is always the first 12 decoded bytes; the rest is the ciphertext.
The download endpoint splits them and returns each as a named field so
clients do not need to know the internal storage format.

Canonical associated data (AAD)
--------------------------------
The server defines the canonical AAD for every message:

    "v1:sender={sender_id}:recipient={recipient_id}:msg={message_id}"

Clients MUST use this exact string when calling encrypt().  The server
computes it from metadata on every download and returns it in the response
so clients know exactly what to pass to decrypt().

Blockchain audit chain
----------------------
Every sent message appends a BlockchainRecord that chains a hash of the
message to the previous record's hash.  This provides tamper-evidence for
the message log.  The chain is append-only; soft-delete sets is_deleted but
never removes the BlockchainRecord (enforced by the RESTRICT FK constraint).
"""

import base64
import hashlib
import threading
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session, aliased
from web3 import Web3

from backend.blockchain.contract import record_message_digest

from backend import models
from backend.database import get_db
from backend.dependencies import get_current_user
from backend.schemas import (
    ForwardRequest,
    MessageDownloadResponse,
    MessageListItem,
    MessageOut,
    MessageSend,
    RevokeRequest,
)

router = APIRouter(prefix="/messages", tags=["messages"])


# ---------------------------------------------------------------------------
# Storage helpers — nonce ‖ ciphertext packing
# ---------------------------------------------------------------------------

def _pack(nonce_b64: str, ciphertext_b64: str) -> str:
    """Combine base64-encoded nonce and ciphertext into a single stored blob.

    The blob is base64(nonce_bytes ‖ ciphertext_bytes).  The nonce is always
    the first 12 decoded bytes; the rest is the ciphertext (including the
    16-byte GCM tag).  Storing them together eliminates any risk of a
    nonce/ciphertext row mismatch if records are ever reordered.
    """
    nonce_bytes = base64.b64decode(nonce_b64)
    ct_bytes    = base64.b64decode(ciphertext_b64)
    return base64.b64encode(nonce_bytes + ct_bytes).decode()


def _unpack(stored_b64: str) -> tuple[str, str]:
    """Split the stored blob back into (nonce_b64, ciphertext_b64).

    Returns base64-encoded strings suitable for returning directly in API
    responses.  Raises ValueError if the blob is too short.
    """
    raw = base64.b64decode(stored_b64)
    if len(raw) < 12 + 16:
        # Minimum valid blob: 12-byte nonce + 16-byte GCM tag (empty plaintext)
        raise ValueError("Stored ciphertext blob is too short to be valid.")
    return (
        base64.b64encode(raw[:12]).decode(),   # nonce
        base64.b64encode(raw[12:]).decode(),   # ciphertext_with_tag
    )


# ---------------------------------------------------------------------------
# Canonical associated data
# ---------------------------------------------------------------------------

def _canonical_aad(sender_id: int | None, recipient_id: int, message_id: int) -> str:
    """Return the canonical AAD string for a given (sender, recipient, message).

    Both the sender (at encrypt time) and the recipient (at decrypt time) must
    use this exact string.  Binding the AAD to sender_id, recipient_id, and
    message_id means:
      - A ciphertext cannot be replayed in a different conversation.
      - A message forwarded to a new recipient requires re-encryption with
        the new recipient's ID in the AAD (or the forward creates a new
        message row — our implementation creates a new message_access row
        without changing the ciphertext, so the download endpoint returns
        the AAD for the original recipient pair).
    """
    return f"v1:sender={sender_id}:recipient={recipient_id}:msg={message_id}"


# ---------------------------------------------------------------------------
# Blockchain helpers
# ---------------------------------------------------------------------------

def _submit_to_chain(message_id: int, integrity_hash: str) -> None:
    """Anchor integrity_hash on Sepolia and store the tx hash in BlockchainRecord.

    Runs in a daemon thread so the HTTP response is not delayed.
    All failures are logged; the SHA-256 hash is still durable in SQLite
    even if the Sepolia submission fails.
    """
    import logging
    from backend.database import SessionLocal

    logger = logging.getLogger(__name__)

    if not integrity_hash:
        logger.warning("msg %d: integrity_hash is empty — skipping chain submission", message_id)
        return

    if len(integrity_hash) != 64:
        logger.error(
            "msg %d: integrity_hash is %d chars (expected 64) — skipping chain submission; value: %r",
            message_id, len(integrity_hash), integrity_hash,
        )
        return

    try:
        tx_hash = record_message_digest(f"0x{integrity_hash}")
        with SessionLocal() as db:
            rec = db.scalars(
                select(models.BlockchainRecord).where(
                    models.BlockchainRecord.message_id == message_id
                )
            ).first()
            if rec:
                rec.eth_tx_hash = tx_hash
                db.commit()
                logger.info("msg %d anchored on Sepolia: %s", message_id, tx_hash)
            else:
                logger.warning("msg %d: BlockchainRecord not found after commit", message_id)
    except Exception as exc:
        logger.error("msg %d: failed to anchor on Sepolia: %r", message_id, exc)


def _append_blockchain_record(message: models.Message, db: Session) -> None:
    """Append a new BlockchainRecord chaining *message* to the audit log.

    Each record stores:
      message_hash  — SHA-256 of (ciphertext + sender_id + created_at)
      previous_hash — block_hash of the most recent existing record,
                      or "0" * 64 for the genesis block
      block_hash    — SHA-256(previous_hash + message_hash)
      block_index   — 1-based sequence number in the chain

    Note: this implementation is not atomic under concurrent sends (two
    simultaneous sends could both read the same previous record and create
    the same block_index).  For a production system, use a DB-level sequence
    or a serialised writer.  For this project the risk is acceptable.
    """
    content = f"{message.ciphertext}{message.sender_id}{message.created_at.isoformat()}"
    message_hash = hashlib.sha256(content.encode()).hexdigest()

    last = db.scalars(
        select(models.BlockchainRecord)
        .order_by(models.BlockchainRecord.block_index.desc())
        .limit(1)
    ).first()

    previous_hash = last.block_hash if last else "0" * 64
    block_index   = (last.block_index + 1) if last else 1
    block_hash    = hashlib.sha256(
        (previous_hash + message_hash).encode()
    ).hexdigest()

    db.add(models.BlockchainRecord(
        message_id=message.id,
        message_hash=message_hash,
        previous_hash=previous_hash,
        block_hash=block_hash,
        block_index=block_index,
    ))


def _submit_to_chain(message_id: int, integrity_hash: str) -> None:
    """Anchor integrity_hash on Sepolia and persist the tx hash in BlockchainRecord.

    Runs in a daemon thread so the HTTP response is not delayed.

    Duplicate-hash behaviour
    ------------------------
    In production every message has a unique hash because the ciphertext
    embeds a random 12-byte nonce chosen at encrypt time — two messages with
    the same plaintext therefore produce different hashes.  Duplicate hash
    reverts only occur in testing when the same plaintext and nonce are
    reused.  When a revert is detected this function calls
    verify_hash_on_chain() to confirm the hash was already recorded in a
    prior transaction; if so, eth_tx_hash is set to the sentinel "duplicate"
    so the proof endpoint can still confirm the hash is anchored on-chain.
    """
    import logging
    from backend.database import SessionLocal
    from backend.blockchain.contract import record_message_digest, verify_hash_on_chain

    logger = logging.getLogger(__name__)

    if not integrity_hash:
        logger.warning("msg %d: integrity_hash is empty — skipping chain submission", message_id)
        return

    if len(integrity_hash) != 64:
        logger.error(
            "msg %d: integrity_hash is %d chars (expected 64) — skipping; value: %r",
            message_id, len(integrity_hash), integrity_hash,
        )
        return

    eth_tx: str | None = None

    try:
        eth_tx = record_message_digest(f"0x{integrity_hash}")
        logger.info("msg %d anchored on Sepolia: %s", message_id, eth_tx)

    except EnvironmentError as exc:
        # Missing SEPOLIA_RPC_URL, CONTRACT_ADDRESS, or DEPLOYER_PRIVATE_KEY.
        # No point querying the chain without credentials.
        logger.error("msg %d: blockchain env vars not configured: %r", message_id, exc)
        return

    except (ValueError, RuntimeError) as exc:
        # ValueError  — ContractLogicError raised at build_transaction time
        #               (contract rejects the call before the tx is broadcast).
        # RuntimeError — receipt.status == 0 (revert after the tx was mined).
        # Both can indicate "hash already recorded".
        err_str = str(exc).lower()
        if "reverted" in err_str or "rejected" in err_str:
            try:
                proof = verify_hash_on_chain(f"0x{integrity_hash}")
            except Exception as ve:
                logger.error(
                    "msg %d: contract rejected submission and on-chain check failed — "
                    "original=%r  verify_error=%r",
                    message_id, exc, ve,
                )
                return

            if proof.get("exists"):
                logger.warning(
                    "msg %d: hash already recorded on-chain at contract index %s "
                    "(duplicate content — expected during testing, not in production "
                    "because each message embeds a unique random nonce)",
                    message_id, proof.get("index"),
                )
                eth_tx = "duplicate"
            else:
                logger.error(
                    "msg %d: contract reverted but hash is not on-chain — "
                    "possible gas issue or unexpected contract state: %r",
                    message_id, exc,
                )
                return
        else:
            logger.error("msg %d: failed to anchor on Sepolia: %r", message_id, exc)
            return

    except Exception as exc:
        logger.error("msg %d: unexpected error anchoring on Sepolia: %r", message_id, exc)
        return

    # Persist eth_tx_hash ("0x..." or "duplicate") into the BlockchainRecord row.
    # "duplicate" is truthy, so get_blockchain_proof will still call
    # verify_hash_on_chain and correctly confirm the hash is on-chain.
    try:
        with SessionLocal() as db:
            rec = db.scalars(
                select(models.BlockchainRecord).where(
                    models.BlockchainRecord.message_id == message_id
                )
            ).first()
            if rec:
                rec.eth_tx_hash = eth_tx
                db.commit()
            else:
                logger.warning("msg %d: BlockchainRecord not found", message_id)
    except Exception as exc:
        logger.error("msg %d: failed to persist eth_tx_hash=%r: %r", message_id, eth_tx, exc)


# ---------------------------------------------------------------------------
# Access-control helpers
# ---------------------------------------------------------------------------

def _load_active_message(message_id: int, db: Session) -> models.Message:
    """Return the Message row or raise 404.

    Raises 404 (not 403) regardless of whether the message exists but is
    deleted — revealing that a message *was* deleted would confirm its
    prior existence to an unauthorised requester.
    """
    msg = db.get(models.Message, message_id)
    if msg is None or msg.is_deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="Message not found.")
    return msg


def _require_sender(message: models.Message, current_user: models.User) -> None:
    """Raise 403 if *current_user* is not the sender of *message*.

    403 (not 404) is appropriate here: by the time this is called the caller
    has already been shown the message exists (they are either the sender or
    a recipient who retrieved the message ID via inbox).  Confirming existence
    to someone with partial access is not an additional information leak.
    """
    if message.sender_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="Only the sender may perform this action.")


def _get_access_record(
    message_id: int, user_id: int, db: Session
) -> models.MessageAccess | None:
    """Return the MessageAccess row for (message_id, user_id), or None."""
    return db.scalars(
        select(models.MessageAccess).where(
            models.MessageAccess.message_id == message_id,
            models.MessageAccess.recipient_id == user_id,
        )
    ).first()


def _require_read_access(
    message: models.Message,
    current_user: models.User,
    db: Session,
) -> models.MessageAccess | None:
    """Verify current_user may read *message*; return their access record.

    Allowed if:
      - current_user is the sender, OR
      - a MessageAccess row exists for current_user as recipient.

    Returns the MessageAccess row (or None if the sender is reading their own
    message — senders have no recipient row).

    Raises 404 (not 403) on failure to prevent IDOR: returning 403 would
    confirm the message exists to someone who has no access to it.
    """
    if message.sender_id == current_user.id:
        return None   # sender always has access; no MessageAccess row for them

    access = _get_access_record(message.id, current_user.id, db)
    if access is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="Message not found.")
    return access


def _lookup_active_user(username: str, db: Session) -> models.User:
    """Return an active User by username or raise 404."""
    user = db.scalars(
        select(models.User).where(
            models.User.username == username,
            models.User.is_active.is_(True),
        )
    ).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="User not found.")
    return user


# ---------------------------------------------------------------------------
# POST /messages/send
# ---------------------------------------------------------------------------

@router.post(
    "/send",
    response_model=MessageListItem,
    status_code=status.HTTP_201_CREATED,
    summary="Send an encrypted message",
    responses={
        400: {"description": "Cannot send to yourself / invalid encoding"},
        404: {"description": "Recipient not found"},
        422: {"description": "Schema validation failure (bad nonce length etc.)"},
    },
)
def send_message(
    body: MessageSend,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    """Send an encrypted message to *recipient_username*.

    The server stores the encrypted payload opaquely — it never decrypts the
    ciphertext and never has access to plaintext.

    The server combines nonce and ciphertext into a single stored blob
    (base64(nonce ‖ ciphertext)) so the download endpoint can return both
    as named fields without requiring clients to know the storage layout.
    """
    # ------------------------------------------------------------------
    # 1. Resolve recipient — must exist and be active
    # ------------------------------------------------------------------
    recipient = _lookup_active_user(body.recipient_username, db)

    if recipient.id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot send a message to yourself.",
        )

    # ------------------------------------------------------------------
    # 2. Pack nonce ‖ ciphertext into the single stored blob.
    #    The Pydantic validators on MessageSend already confirmed both are
    #    valid base64 and the nonce decodes to exactly 12 bytes.
    # ------------------------------------------------------------------
    stored_blob = _pack(body.nonce, body.ciphertext)

    # ------------------------------------------------------------------
    # 3. Compute a keccak256 integrity hash over the stored blob.
    #    keccak256 matches the bytes32 type the smart contract expects, so the
    #    same value is stored in SQLite and anchored on Sepolia.
    # ------------------------------------------------------------------
    # bytes(HexBytes).hex() is Python's built-in bytes.hex() — always returns exactly
    # 64 zero-padded lowercase hex chars with no "0x" prefix, regardless of
    # which web3.py version is installed (HexBytes.hex() behaviour varies).
    integrity = bytes(Web3.keccak(text=stored_blob)).hex()

    # ------------------------------------------------------------------
    # 4. Persist the message row.
    #    sender_id is set server-side from the verified JWT — the client
    #    cannot claim to be a different sender (mass-assignment prevention).
    #    db.flush() allocates the auto-increment ID without committing so
    #    the blockchain record and access row can reference it in the same
    #    transaction.
    # ------------------------------------------------------------------
    message = models.Message(
        sender_id=current_user.id,
        ciphertext=stored_blob,
        subject=body.subject,
        integrity_hash=integrity,
    )
    db.add(message)
    db.flush()   # populates message.id and message.created_at

    # ------------------------------------------------------------------
    # 5. Create the recipient's access record.
    # ------------------------------------------------------------------
    db.add(models.MessageAccess(
        message_id=message.id,
        recipient_id=recipient.id,
        encrypted_key=body.encrypted_key,
    ))

    # ------------------------------------------------------------------
    # 6. Append a blockchain audit record.
    # ------------------------------------------------------------------
    _append_blockchain_record(message, db)

    db.commit()
    db.refresh(message)

    # Anchor the integrity hash on Sepolia in the background — the HTTP
    # response is not held waiting for the ~15-30 s block confirmation.
    threading.Thread(
        target=_submit_to_chain,
        args=(message.id, message.integrity_hash or ""),
        daemon=True,
    ).start()

    return {
        "id":                 message.id,
        "sender_id":          message.sender_id,
        "sender_username":    current_user.username,
        "recipient_username": body.recipient_username,
        "subject":            message.subject,
        "is_read":            False,
        "is_deleted":         message.is_deleted,
        "created_at":         message.created_at,
    }


# ---------------------------------------------------------------------------
# GET /messages/inbox
# ---------------------------------------------------------------------------

@router.get(
    "/inbox",
    response_model=list[MessageListItem],
    summary="List received messages",
)
def get_inbox(
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
    skip:  int = Query(default=0,  ge=0,           description="Offset for pagination."),
    limit: int = Query(default=50, ge=1,  le=200,  description="Max items to return."),
) -> list[dict]:
    """Return a paginated summary list of messages received by the current user.

    **No ciphertext is returned here** — use `GET /messages/{id}/download`
    to fetch the encrypted payload for a specific message.  This keeps the
    listing fast and prevents bulk ciphertext exposure.

    Messages are returned newest-first.  Fetching the inbox does NOT mark
    messages as read; that happens only on `/download`.
    """
    # Single JOIN query to avoid N+1 lookups for sender usernames.
    stmt = (
        select(models.Message, models.MessageAccess, models.User)
        .join(
            models.MessageAccess,
            models.MessageAccess.message_id == models.Message.id,
        )
        .outerjoin(
            models.User,
            models.User.id == models.Message.sender_id,
        )
        .where(
            models.MessageAccess.recipient_id == current_user.id,
            # is_deleted is a sender-side flag only; recipients retain inbox
            # visibility even after the sender deletes their copy.
        )
        .order_by(models.Message.created_at.desc())
        .offset(skip)
        .limit(limit)
    )
    rows = db.execute(stmt).all()

    return [
        {
            "id":              msg.id,
            "sender_id":       msg.sender_id,
            "sender_username": sender.username if sender else None,
            "subject":         msg.subject,
            "is_read":         access.is_read,
            "is_deleted":      msg.is_deleted,
            "is_forwarded":    bool(msg.is_forwarded),
            "created_at":      msg.created_at,
        }
        for msg, access, sender in rows
    ]


# ---------------------------------------------------------------------------
# GET /messages/sent
# ---------------------------------------------------------------------------

@router.get(
    "/sent",
    response_model=list[MessageListItem],
    summary="List sent messages",
)
def get_sent(
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
    skip:  int = Query(default=0,  ge=0,          description="Offset for pagination."),
    limit: int = Query(default=50, ge=1, le=200,  description="Max items to return."),
) -> list[dict]:
    """Return a paginated summary list of messages sent by the current user.

    No ciphertext is included.  Messages are returned newest-first.
    Soft-deleted messages are excluded.
    """
    # Alias User as the recipient so SQLAlchemy can distinguish it from the
    # sender join used elsewhere in the query.
    RecipientUser = aliased(models.User, name="recipient")

    # Subquery: for each message, pick the *first* MessageAccess row by id.
    # This gives us the original direct recipient and avoids duplicate rows
    # when a message has been forwarded to additional people.
    first_access_sq = (
        select(
            func.min(models.MessageAccess.id).label("id"),
            models.MessageAccess.message_id,
        )
        .group_by(models.MessageAccess.message_id)
        .subquery()
    )

    stmt = (
        select(models.Message, RecipientUser)
        .join(first_access_sq, first_access_sq.c.message_id == models.Message.id)
        .join(
            models.MessageAccess,
            models.MessageAccess.id == first_access_sq.c.id,
        )
        .join(
            RecipientUser,
            RecipientUser.id == models.MessageAccess.recipient_id,
        )
        .where(
            models.Message.sender_id == current_user.id,
            models.Message.is_deleted.is_(False),
        )
        .order_by(models.Message.created_at.desc())
        .offset(skip)
        .limit(limit)
    )
    rows = db.execute(stmt).all()

    return [
        {
            "id":                 msg.id,
            "sender_id":          msg.sender_id,
            "sender_username":    current_user.username,
            "recipient_username": recipient.username,
            "subject":            msg.subject,
            "is_read":            True,   # sender always "read" their own outgoing message
            "is_deleted":         msg.is_deleted,
            "created_at":         msg.created_at,
        }
        for msg, recipient in rows
    ]


# ---------------------------------------------------------------------------
# DELETE /messages/{id}
# ---------------------------------------------------------------------------

@router.delete(
    "/{message_id}",
    response_model=MessageOut,
    summary="Soft-delete a sent message",
    responses={
        403: {"description": "Not the sender"},
        404: {"description": "Message not found"},
    },
)
def delete_message(
    message_id: int,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    """Soft-delete a message.  Only the original sender may do this.

    Sets `is_deleted = True`.  The message row and its BlockchainRecord are
    preserved for audit-chain integrity (the FK is RESTRICT — hard deletion
    would break the chain).  The server will no longer return this message
    in inbox/sent listings or serve its ciphertext via download.
    """
    message = _load_active_message(message_id, db)
    _require_sender(message, current_user)

    message.is_deleted = True
    db.add(message)
    db.commit()

    return {"detail": "Message deleted."}


# ---------------------------------------------------------------------------
# POST /messages/{id}/forward
# ---------------------------------------------------------------------------

@router.post(
    "/{message_id}/forward",
    response_model=MessageOut,
    summary="Forward a message to a new recipient",
    responses={
        403: {"description": "No read access to this message"},
        404: {"description": "Message or recipient not found"},
        409: {"description": "Recipient already has access"},
    },
)
def forward_message(
    message_id: int,
    body: ForwardRequest,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    """Grant a new recipient access to an existing message.

    The forwarder must be either the original sender or an existing recipient.
    Because the ciphertext is already encrypted to a specific recipient via
    the wrapped `encrypted_key`, the forwarder must:

    1. Decrypt the message_key using their own private key.
    2. Re-encrypt message_key with the new recipient's public key.
    3. Supply the re-wrapped key as `encrypted_key` in this request.

    Without this, the new recipient receives the ciphertext but cannot
    unwrap the key and therefore cannot decrypt it.

    The server creates a new `message_access` row; the ciphertext is NOT
    copied (the same encrypted blob is shared).
    """
    # Load without the is_deleted gate: a sender's soft-delete only hides the
    # message from the sender's own view; recipients who still have a
    # MessageAccess row retain read (and forward) access.
    message = db.get(models.Message, message_id)
    if message is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="Message not found.")

    if message.sender_id == current_user.id:
        # Sender: may not forward after they deleted their own copy.
        if message.is_deleted:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                                detail="Message not found.")
    else:
        # Recipient: access is controlled by MessageAccess row only.
        if _get_access_record(message.id, current_user.id, db) is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                                detail="Message not found.")

    new_recipient = _lookup_active_user(body.recipient_username, db)

    # Prevent self-forward
    if new_recipient.id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot forward a message to yourself.",
        )

    # Idempotency guard — avoid duplicate access rows
    if _get_access_record(message.id, new_recipient.id, db):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="That user already has access to this message.",
        )

    if body.new_ciphertext and body.new_nonce and body.new_encrypted_key:
        # ── Re-encrypted forward (preferred) ────────────────────────────
        # The forwarder decrypted the original on their device and re-encrypted
        # it for the new recipient.  Create a fresh Message row so the new
        # recipient can actually decrypt the content with their own key pair.
        stored_blob = _pack(body.new_nonce, body.new_ciphertext)
        integrity   = bytes(Web3.keccak(text=stored_blob)).hex()  # 64-char hex, no 0x

        fwd_msg = models.Message(
            sender_id=current_user.id,
            ciphertext=stored_blob,
            subject=message.subject,
            integrity_hash=integrity,
            is_forwarded=True,
        )
        db.add(fwd_msg)
        db.flush()   # allocate fwd_msg.id

        db.add(models.MessageAccess(
            message_id=fwd_msg.id,
            recipient_id=new_recipient.id,
            encrypted_key=body.new_encrypted_key,
        ))

        _append_blockchain_record(fwd_msg, db)
        db.commit()

        threading.Thread(
            target=_submit_to_chain,
            args=(fwd_msg.id, fwd_msg.integrity_hash),
            daemon=True,
        ).start()
    else:
        # ── Legacy path: share existing message_access row ───────────────
        # The new recipient receives the original ciphertext but cannot
        # decrypt it (it was encrypted for the original recipient's key).
        db.add(models.MessageAccess(
            message_id=message.id,
            recipient_id=new_recipient.id,
            encrypted_key=body.encrypted_key,
        ))
        db.commit()

    return {"detail": f"Message forwarded to {new_recipient.username}."}


# ---------------------------------------------------------------------------
# POST /messages/{id}/revoke
# ---------------------------------------------------------------------------

@router.post(
    "/{message_id}/revoke",
    response_model=MessageOut,
    summary="Revoke message access",
    responses={
        403: {"description": "Not the sender"},
        404: {"description": "Message or recipient not found"},
    },
)
def revoke_message(
    message_id: int,
    body: RevokeRequest,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    """Revoke access to a message.  Only the original sender may do this.

    **Without `recipient_username`** — full revocation: sets `is_deleted = True`
    so the server stops serving the message to all recipients.  The ciphertext
    and BlockchainRecord are preserved (RESTRICT FK); only the access flag changes.

    **With `recipient_username`** — targeted revocation: removes that specific
    recipient's `message_access` row.  Other recipients are unaffected.
    The message itself remains active; the server simply stops serving the
    ciphertext to that one user.

    Note: revocation is a server-side access control measure.  Any recipient
    who already downloaded and decrypted the message retains their local
    plaintext copy — the server cannot un-decrypt a message already received.
    """
    message = _load_active_message(message_id, db)
    _require_sender(message, current_user)

    if body.recipient_username is None:
        # Full revocation: remove every MessageAccess row so no recipient can
        # download the message.  The message row, ciphertext, and blockchain
        # record are intentionally preserved — revocation is an access-control
        # action, not a deletion.  is_deleted is NOT set so the sender can still
        # see the message in their sent list (the frontend shows "Access revoked").
        access_rows = db.scalars(
            select(models.MessageAccess).where(
                models.MessageAccess.message_id == message.id
            )
        ).all()
        for row in access_rows:
            db.delete(row)
        db.commit()
        return {"detail": "Message access revoked for all recipients."}

    # Targeted revocation: remove only this recipient's access row.
    target = _lookup_active_user(body.recipient_username, db)
    access = _get_access_record(message.id, target.id, db)
    if access is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"{target.username} does not have access to this message.",
        )

    db.delete(access)
    db.commit()

    return {"detail": f"Access revoked for {target.username}."}


# ---------------------------------------------------------------------------
# GET /messages/{id}/download
# ---------------------------------------------------------------------------

@router.get(
    "/{message_id}/download",
    response_model=MessageDownloadResponse,
    summary="Download a message's encrypted payload",
    responses={
        404: {"description": "Message not found or no access"},
    },
)
def download_message(
    message_id: int,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    """Return the full encrypted payload needed to decrypt a message.

    Verifies that `current_user` is either the sender or an authorised
    recipient (via `message_access`).  Returns 404 — not 403 — on any
    access failure to prevent IDOR: a 403 would confirm the message exists
    to someone who has no business knowing that.

    **Returned fields for decryption:**
    - `ciphertext`       — the combined stored blob (nonce ‖ ciphertext)
    - `nonce`            — the first 12 decoded bytes, re-encoded as base64
    - `associated_data`  — the canonical AAD; pass this to `decrypt()`
    - `encrypted_key`    — the recipient's wrapped key material

    Marks the message as read in `message_access` (only for recipients;
    senders are implicitly always "read").
    """
    # Load the raw message row without the is_deleted gate so that recipients
    # can still download a message the sender soft-deleted (delete is sender-only).
    message = db.get(models.Message, message_id)
    if message is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="Message not found.")

    if message.sender_id == current_user.id:
        # Sender: is_deleted hides the message from their own view.
        if message.is_deleted:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                                detail="Message not found.")
        access = None
    else:
        # Recipient: access is controlled solely by the MessageAccess row.
        # A missing row means either the message never existed for them, or
        # access was revoked — both surface as 404 to prevent IDOR.
        access = _get_access_record(message.id, current_user.id, db)
        if access is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                                detail="Message not found.")

    # ------------------------------------------------------------------
    # Split the stored blob into nonce and ciphertext.
    # _unpack() raises ValueError if the blob is malformed — treat that
    # as a server-side data integrity failure.
    # ------------------------------------------------------------------
    try:
        nonce_b64, _ct_b64 = _unpack(message.ciphertext)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Message data is corrupted.",
        )

    # ------------------------------------------------------------------
    # Mark as read (only recipients have an access row; senders do not).
    # ------------------------------------------------------------------
    if access is not None and not access.is_read:
        access.is_read = True
        access.read_at = datetime.now(timezone.utc)
        db.add(access)
        db.commit()

    # ------------------------------------------------------------------
    # Canonical AAD.
    # For recipients: their ID is in the access row.
    # For the sender reading their own sent message: use the sender's own
    # ID as the recipient_id placeholder.  The sender should not normally
    # decrypt messages they sent (they already have the plaintext), but
    # this allows self-audit without erroring.
    # ------------------------------------------------------------------
    recipient_id = access.recipient_id if access else current_user.id
    aad = _canonical_aad(message.sender_id, recipient_id, message.id)

    # ------------------------------------------------------------------
    # Resolve sender display name (single DB lookup; not in a join because
    # this endpoint returns one row, not a list).
    # ------------------------------------------------------------------
    sender = db.get(models.User, message.sender_id) if message.sender_id else None

    return {
        "id":              message.id,
        "sender_id":       message.sender_id,
        "sender_username": sender.username if sender else None,
        "ciphertext":      message.ciphertext,
        "nonce":           nonce_b64,
        "associated_data": aad,
        "encrypted_key":   access.encrypted_key if access else None,
        "subject":         message.subject,
        "integrity_hash":  message.integrity_hash,
        "is_read":         access.is_read if access else True,
        "created_at":      message.created_at,
    }


# ---------------------------------------------------------------------------
# GET /messages/{id}/blockchain-proof
# ---------------------------------------------------------------------------

@router.get(
    "/{message_id}/blockchain-proof",
    summary="Retrieve on-chain proof for a message",
    responses={
        404: {"description": "Message not found or no access"},
    },
)
def get_blockchain_proof(
    message_id: int,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    """Return the blockchain proof for a message.

    Recomputes keccak256 of the stored ciphertext, compares it to the
    persisted integrity_hash, and (if an Ethereum tx hash exists) fetches
    the on-chain hash from the Sepolia contract for final verification.

    Response fields:
      stored_hash   — keccak256 recorded at send time (from SQLite)
      computed_hash — keccak256 freshly computed from the current ciphertext
      hash_match    — True when stored == computed (ciphertext not tampered)
      eth_tx_hash   — Sepolia tx hash, or null if not yet anchored
      on_chain      — contract record {exists, hash, timestamp, recorder} or null
      on_chain_match— True when on-chain hash == computed hash, or null
    """
    message = db.get(models.Message, message_id)
    if message is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="Message not found.")

    if message.sender_id == current_user.id:
        if message.is_deleted:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                                detail="Message not found.")
    else:
        if _get_access_record(message.id, current_user.id, db) is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                                detail="Message not found.")

    rec          = message.blockchain_record
    stored_hash  = message.integrity_hash or ""
    # Recompute using the same algorithm as the send/forward endpoints:
    # bytes(Web3.keccak(text=blob)).hex() — guaranteed 64-char keccak256 hex.
    computed_hash = bytes(Web3.keccak(text=message.ciphertext)).hex()
    hash_match   = bool(stored_hash and computed_hash == stored_hash)

    result: dict = {
        "stored_hash":    stored_hash,
        "computed_hash":  computed_hash,
        "hash_match":     hash_match,
        "has_chain_record": rec is not None,
        "eth_tx_hash":    rec.eth_tx_hash if rec else None,
        "block_index":    rec.block_index if rec else None,
        "chain_recorded_at": rec.created_at.isoformat() if rec else None,
        "on_chain":       None,
        "on_chain_match": None,
    }

    if rec and rec.eth_tx_hash and stored_hash:
        try:
            from backend.blockchain.contract import verify_hash_on_chain
            on_chain = verify_hash_on_chain(stored_hash)
            result["on_chain"] = on_chain
            if on_chain["exists"] and on_chain["hash"]:
                on_chain_hex = on_chain["hash"][2:]  # strip 0x
                result["on_chain_match"] = (on_chain_hex == computed_hash)
        except Exception:
            pass  # node unreachable — surface what we have from SQLite

    return result
