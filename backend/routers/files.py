"""
backend/routers/files.py — Encrypted file (mailbox) endpoints.

Routes
------
  POST   /files/upload           — encrypt-and-upload a file for a recipient
  GET    /files/shared           — list files shared with me (no ciphertext)
  GET    /files/owned            — list files I uploaded (no ciphertext)
  DELETE /files/{id}             — soft-delete an uploaded file (owner only)
  POST   /files/{id}/share       — share a file with a new recipient
  POST   /files/{id}/revoke      — revoke one or all recipients' access
  GET    /files/{id}/download    — retrieve the full ciphertext for decryption
  GET    /files/{id}/blockchain-proof — on-chain integrity proof

Access control model
--------------------
Every endpoint requires a valid JWT access token (get_current_user dependency).
Beyond authentication, each endpoint enforces one of two ownership rules:

  Owner-only operations (delete, revoke):
    file.owner_id == current_user.id
    → 403 Forbidden if the requester is not the owner.

  Read operations (download, share):
    A row must exist in file_access where recipient_id == current_user.id
    OR the requester is the owner.
    → 404 Not Found if neither condition holds.
      (404 rather than 403: returning 403 would confirm the file exists
       to an unauthorised requester — an IDOR information leak.)

Storage layout
--------------
The nonce is NOT stored in a separate column.  The server stores the combined
blob base64(nonce_bytes ‖ ciphertext_with_tag) in files.ciphertext.
The nonce is always the first 12 decoded bytes; the rest is the ciphertext.
The download endpoint splits them and returns each as a named field so
clients do not need to know the internal storage format.

Canonical associated data (AAD)
--------------------------------
The canonical AAD for every file (see backend.crypto.build_file_aad):

    "smx:v1:sender={owner_username}:recipient={recipient_username}:filename={filename}"

The sender builds it at encrypt time and binds it into the AEAD; the
recipient rebuilds it from the download response and their own username.
Binding the filename means a malicious server cannot relabel a stored
ciphertext without the recipient's tag check failing.  The file ID is
deliberately NOT included — it does not exist at encrypt time.

The upload endpoint validates a client-supplied associated_data against the
canonical value (400 on mismatch) to catch client-side construction bugs
early; the security check is always the recipient's local one.

Client status: the crypto layers in all three implementations accept AAD;
the web and C++ clients start binding it when they are reworked for the
/files API (tracked in docs/crypto-design.md §9).

Upload size limits
------------------
Uploads are JSON with base64 payloads (a deliberate simplicity trade-off —
see docs/crypto-design.md §8.6).  Two layers of enforcement:
  - schemas.FileUpload caps the base64 ciphertext at ~8 MiB of plaintext
  - main.py rejects any request body over MAX_REQUEST_BODY_BYTES with 413

Blockchain audit chain
----------------------
Every upload appends a BlockchainRecord that chains a hash of the file to
the previous record's hash.  This provides tamper-evidence for the mailbox
log.  The chain is append-only; soft-delete sets is_deleted but never
removes the BlockchainRecord (enforced by the RESTRICT FK constraint).
"""

import base64
import hashlib
import threading
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session, aliased
from web3 import Web3

from backend import models
from backend.crypto import build_file_aad
from backend.database import get_db
from backend.dependencies import get_current_user
from backend.schemas import (
    DetailResponse,
    FileDownloadResponse,
    FileListItem,
    FileUpload,
    RevokeRequest,
    ShareRequest,
)

router = APIRouter(prefix="/files", tags=["files"])


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

def _canonical_aad(
    owner_username: str | None,
    recipient_username: str,
    filename: str | None,
) -> str:
    """Return the canonical AAD string for a (owner, recipient, filename) triple.

    Delegates to backend.crypto.build_file_aad — the single definition of the
    format — and decodes to str for JSON transport.  "sender"/"recipient" in
    the string name the cryptographic roles: the owner encrypted the file
    (HPKE sender), the recipient decrypts it.
    """
    return build_file_aad(owner_username or "", recipient_username, filename).decode("utf-8")


# ---------------------------------------------------------------------------
# Blockchain helpers
# ---------------------------------------------------------------------------

def _append_blockchain_record(file_obj: models.FileObject, db: Session) -> None:
    """Append a new BlockchainRecord chaining *file_obj* to the audit log.

    Each record stores:
      message_hash  — SHA-256 of (ciphertext + owner_id + created_at)
      previous_hash — block_hash of the most recent existing record,
                      or "0" * 64 for the genesis block
      block_hash    — SHA-256(previous_hash + message_hash)
      block_index   — 1-based sequence number in the chain

    Note: this implementation is not atomic under concurrent uploads (two
    simultaneous uploads could both read the same previous record and create
    the same block_index).  For a production system, use a DB-level sequence
    or a serialised writer.  For this project the risk is acceptable.
    """
    content = f"{file_obj.ciphertext}{file_obj.owner_id}{file_obj.created_at.isoformat()}"
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
        file_id=file_obj.id,
        message_hash=message_hash,
        previous_hash=previous_hash,
        block_hash=block_hash,
        block_index=block_index,
    ))


def _submit_to_chain(file_id: int, integrity_hash: str) -> None:
    """Anchor integrity_hash on Sepolia and persist the tx hash in BlockchainRecord.

    Runs in a daemon thread so the HTTP response is not delayed.

    Duplicate-hash behaviour
    ------------------------
    In production every file has a unique hash because the ciphertext
    embeds a random 12-byte nonce chosen at encrypt time — two files with
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
        logger.warning("file %d: integrity_hash is empty — skipping chain submission", file_id)
        return

    if len(integrity_hash) != 64:
        logger.error(
            "file %d: integrity_hash is %d chars (expected 64) — skipping; value: %r",
            file_id, len(integrity_hash), integrity_hash,
        )
        return

    eth_tx: str | None = None

    try:
        eth_tx = record_message_digest(f"0x{integrity_hash}")
        logger.info("file %d anchored on Sepolia: %s", file_id, eth_tx)

    except EnvironmentError as exc:
        # Missing SEPOLIA_RPC_URL, CONTRACT_ADDRESS, or DEPLOYER_PRIVATE_KEY.
        # No point querying the chain without credentials.
        logger.error("file %d: blockchain env vars not configured: %r", file_id, exc)
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
                    "file %d: contract rejected submission and on-chain check failed — "
                    "original=%r  verify_error=%r",
                    file_id, exc, ve,
                )
                return

            if proof.get("exists"):
                logger.warning(
                    "file %d: hash already recorded on-chain at contract index %s "
                    "(duplicate content — expected during testing, not in production "
                    "because each file embeds a unique random nonce)",
                    file_id, proof.get("index"),
                )
                eth_tx = "duplicate"
            else:
                logger.error(
                    "file %d: contract reverted but hash is not on-chain — "
                    "possible gas issue or unexpected contract state: %r",
                    file_id, exc,
                )
                return
        else:
            logger.error("file %d: failed to anchor on Sepolia: %r", file_id, exc)
            return

    except Exception as exc:
        logger.error("file %d: unexpected error anchoring on Sepolia: %r", file_id, exc)
        return

    # Persist eth_tx_hash ("0x..." or "duplicate") into the BlockchainRecord row.
    # "duplicate" is truthy, so get_blockchain_proof will still call
    # verify_hash_on_chain and correctly confirm the hash is on-chain.
    try:
        with SessionLocal() as db:
            rec = db.scalars(
                select(models.BlockchainRecord).where(
                    models.BlockchainRecord.file_id == file_id
                )
            ).first()
            if rec:
                rec.eth_tx_hash = eth_tx
                db.commit()
            else:
                logger.warning("file %d: BlockchainRecord not found", file_id)
    except Exception as exc:
        logger.error("file %d: failed to persist eth_tx_hash=%r: %r", file_id, eth_tx, exc)


# ---------------------------------------------------------------------------
# Access-control helpers
# ---------------------------------------------------------------------------

def _load_active_file(file_id: int, db: Session) -> models.FileObject:
    """Return the FileObject row or raise 404.

    Raises 404 (not 403) regardless of whether the file exists but is
    deleted — revealing that a file *was* deleted would confirm its
    prior existence to an unauthorised requester.
    """
    file_obj = db.get(models.FileObject, file_id)
    if file_obj is None or file_obj.is_deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="File not found.")
    return file_obj


def _require_owner(file_obj: models.FileObject, current_user: models.User) -> None:
    """Raise 403 if *current_user* is not the owner of *file_obj*.

    403 (not 404) is appropriate here: by the time this is called the caller
    has already been shown the file exists (they are either the owner or
    a recipient who retrieved the file ID via a listing).  Confirming
    existence to someone with partial access is not an additional
    information leak.
    """
    if file_obj.owner_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="Only the owner may perform this action.")


def _get_access_record(
    file_id: int, user_id: int, db: Session
) -> models.FileAccess | None:
    """Return the FileAccess row for (file_id, user_id), or None."""
    return db.scalars(
        select(models.FileAccess).where(
            models.FileAccess.file_id == file_id,
            models.FileAccess.recipient_id == user_id,
        )
    ).first()


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
# POST /files/upload
# ---------------------------------------------------------------------------

@router.post(
    "/upload",
    response_model=FileListItem,
    status_code=status.HTTP_201_CREATED,
    summary="Upload an encrypted file for a recipient",
    responses={
        400: {"description": "Cannot upload to yourself / invalid encoding"},
        404: {"description": "Recipient not found"},
        413: {"description": "Request body exceeds the upload size limit"},
        422: {"description": "Schema validation failure (bad nonce length, oversize ciphertext, etc.)"},
    },
)
def upload_file(
    body: FileUpload,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    """Upload an encrypted file addressed to *recipient_username*.

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
            detail="You cannot upload a file to yourself.",
        )

    # ------------------------------------------------------------------
    # 1b. Cross-check client-supplied associated_data (when present).
    #     The client binds this string into the AEAD; the server cannot
    #     verify the binding (it has no key), but it CAN verify the client
    #     built the canonical string correctly — catching construction bugs
    #     at upload time instead of as a confusing decrypt failure at the
    #     recipient.  The authoritative check remains the recipient's local
    #     GCM tag verification.
    # ------------------------------------------------------------------
    canonical = _canonical_aad(
        current_user.username, body.recipient_username, body.filename
    )
    if body.associated_data is not None and body.associated_data != canonical:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "associated_data does not match the canonical form "
                f"'{canonical}'. Rebuild it with the documented format."
            ),
        )

    # ------------------------------------------------------------------
    # 2. Pack nonce ‖ ciphertext into the single stored blob.
    #    The Pydantic validators on FileUpload already confirmed both are
    #    valid base64, the nonce decodes to exactly 12 bytes, and the
    #    ciphertext is within the upload size cap.
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
    # 4. Persist the file row.
    #    owner_id is set server-side from the verified JWT — the client
    #    cannot claim to be a different owner (mass-assignment prevention).
    #    db.flush() allocates the auto-increment ID without committing so
    #    the blockchain record and access row can reference it in the same
    #    transaction.
    # ------------------------------------------------------------------
    file_obj = models.FileObject(
        owner_id=current_user.id,
        ciphertext=stored_blob,
        subject=body.subject,
        filename=body.filename,
        content_type=body.content_type,
        size_bytes=body.size_bytes,
        integrity_hash=integrity,
    )
    db.add(file_obj)
    db.flush()   # populates file_obj.id and file_obj.created_at

    # ------------------------------------------------------------------
    # 5. Create the recipient's access record.
    # ------------------------------------------------------------------
    db.add(models.FileAccess(
        file_id=file_obj.id,
        recipient_id=recipient.id,
        encrypted_key=body.encrypted_key,
    ))

    # ------------------------------------------------------------------
    # 6. Append a blockchain audit record.
    # ------------------------------------------------------------------
    _append_blockchain_record(file_obj, db)

    db.commit()
    db.refresh(file_obj)

    # Anchor the integrity hash on Sepolia in the background — the HTTP
    # response is not held waiting for the ~15-30 s block confirmation.
    threading.Thread(
        target=_submit_to_chain,
        args=(file_obj.id, file_obj.integrity_hash or ""),
        daemon=True,
    ).start()

    return {
        "id":                 file_obj.id,
        "owner_id":           file_obj.owner_id,
        "owner_username":     current_user.username,
        "recipient_username": body.recipient_username,
        "subject":            file_obj.subject,
        "filename":           file_obj.filename,
        "content_type":       file_obj.content_type,
        "size_bytes":         file_obj.size_bytes,
        "is_read":            False,
        "is_deleted":         file_obj.is_deleted,
        "created_at":         file_obj.created_at,
    }


# ---------------------------------------------------------------------------
# GET /files/shared
# ---------------------------------------------------------------------------

@router.get(
    "/shared",
    response_model=list[FileListItem],
    summary="List files shared with me",
)
def list_shared_files(
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
    skip:  int = Query(default=0,  ge=0,           description="Offset for pagination."),
    limit: int = Query(default=50, ge=1,  le=200,  description="Max items to return."),
) -> list[dict]:
    """Return a paginated summary list of files shared with the current user.

    **No ciphertext is returned here** — use `GET /files/{id}/download`
    to fetch the encrypted payload for a specific file.  This keeps the
    listing fast and prevents bulk ciphertext exposure.

    Files are returned newest-first.  Fetching the listing does NOT mark
    files as read; that happens only on `/download`.
    """
    # Single JOIN query to avoid N+1 lookups for owner usernames.
    stmt = (
        select(models.FileObject, models.FileAccess, models.User)
        .join(
            models.FileAccess,
            models.FileAccess.file_id == models.FileObject.id,
        )
        .outerjoin(
            models.User,
            models.User.id == models.FileObject.owner_id,
        )
        .where(
            models.FileAccess.recipient_id == current_user.id,
            # is_deleted is an owner-side flag only; recipients retain
            # visibility even after the owner deletes their copy.
        )
        .order_by(models.FileObject.created_at.desc())
        .offset(skip)
        .limit(limit)
    )
    rows = db.execute(stmt).all()

    return [
        {
            "id":              file_obj.id,
            "owner_id":        file_obj.owner_id,
            "owner_username":  owner.username if owner else None,
            "subject":         file_obj.subject,
            "filename":        file_obj.filename,
            "content_type":    file_obj.content_type,
            "size_bytes":      file_obj.size_bytes,
            "is_read":         access.is_read,
            "is_deleted":      file_obj.is_deleted,
            "is_forwarded":    bool(file_obj.is_forwarded),
            "created_at":      file_obj.created_at,
        }
        for file_obj, access, owner in rows
    ]


# ---------------------------------------------------------------------------
# GET /files/owned
# ---------------------------------------------------------------------------

@router.get(
    "/owned",
    response_model=list[FileListItem],
    summary="List files I uploaded",
)
def list_owned_files(
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
    skip:  int = Query(default=0,  ge=0,          description="Offset for pagination."),
    limit: int = Query(default=50, ge=1, le=200,  description="Max items to return."),
) -> list[dict]:
    """Return a paginated summary list of files uploaded by the current user.

    No ciphertext is included.  Files are returned newest-first.
    Soft-deleted files are excluded.
    """
    # Alias User as the recipient so SQLAlchemy can distinguish it from the
    # owner join used elsewhere in the query.
    RecipientUser = aliased(models.User, name="recipient")

    # Subquery: for each file, pick the *first* FileAccess row by id.
    # This gives us the original direct recipient and avoids duplicate rows
    # when a file has been shared with additional people.
    first_access_sq = (
        select(
            func.min(models.FileAccess.id).label("id"),
            models.FileAccess.file_id,
        )
        .group_by(models.FileAccess.file_id)
        .subquery()
    )

    stmt = (
        select(models.FileObject, RecipientUser)
        .join(first_access_sq, first_access_sq.c.file_id == models.FileObject.id)
        .join(
            models.FileAccess,
            models.FileAccess.id == first_access_sq.c.id,
        )
        .join(
            RecipientUser,
            RecipientUser.id == models.FileAccess.recipient_id,
        )
        .where(
            models.FileObject.owner_id == current_user.id,
            models.FileObject.is_deleted.is_(False),
        )
        .order_by(models.FileObject.created_at.desc())
        .offset(skip)
        .limit(limit)
    )
    rows = db.execute(stmt).all()

    return [
        {
            "id":                 file_obj.id,
            "owner_id":           file_obj.owner_id,
            "owner_username":     current_user.username,
            "recipient_username": recipient.username,
            "subject":            file_obj.subject,
            "filename":           file_obj.filename,
            "content_type":       file_obj.content_type,
            "size_bytes":         file_obj.size_bytes,
            "is_read":            True,   # owner has trivially "read" their own upload
            "is_deleted":         file_obj.is_deleted,
            "created_at":         file_obj.created_at,
        }
        for file_obj, recipient in rows
    ]


# ---------------------------------------------------------------------------
# DELETE /files/{id}
# ---------------------------------------------------------------------------

@router.delete(
    "/{file_id}",
    response_model=DetailResponse,
    summary="Soft-delete an uploaded file",
    responses={
        403: {"description": "Not the owner"},
        404: {"description": "File not found"},
    },
)
def delete_file(
    file_id: int,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    """Soft-delete a file.  Only the owner may do this.

    Sets `is_deleted = True`.  The file row and its BlockchainRecord are
    preserved for audit-chain integrity (the FK is RESTRICT — hard deletion
    would break the chain).  The server will no longer return this file
    in the owner's listings or serve it to the owner; existing recipients
    retain access via their FileAccess rows (use /revoke to cut
    recipients off).
    """
    file_obj = _load_active_file(file_id, db)
    _require_owner(file_obj, current_user)

    file_obj.is_deleted = True
    db.add(file_obj)
    db.commit()

    return {"detail": "File deleted."}


# ---------------------------------------------------------------------------
# POST /files/{id}/share
# ---------------------------------------------------------------------------

@router.post(
    "/{file_id}/share",
    response_model=DetailResponse,
    summary="Share a file with a new recipient",
    responses={
        403: {"description": "No read access to this file"},
        404: {"description": "File or recipient not found"},
        409: {"description": "Recipient already has access"},
    },
)
def share_file(
    file_id: int,
    body: ShareRequest,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    """Grant a new recipient access to an existing file.

    The sharer must be either the owner or an existing recipient.
    Because the ciphertext is encrypted for a specific recipient (the
    content key is derived from that recipient's key pair via HPKE), the
    sharer must:

    1. Decrypt the file on their own device.
    2. Re-encrypt it for the new recipient
       (fresh HPKE encapsulation against the new recipient's public key).
    3. Supply new_ciphertext / new_nonce / new_encrypted_key in this request.

    When all three re-encryption fields are present the backend creates a
    brand-new file row so the new recipient can actually decrypt it.

    The legacy path (no re-encryption fields) only adds an access row that
    shares the original ciphertext — the new recipient can download but
    cannot decrypt it; kept for backward compatibility.
    """
    # Load without the is_deleted gate: an owner's soft-delete only hides the
    # file from the owner's own view; recipients who still have a
    # FileAccess row retain read (and share) access.
    file_obj = db.get(models.FileObject, file_id)
    if file_obj is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="File not found.")

    if file_obj.owner_id == current_user.id:
        # Owner: may not share after they deleted their own copy.
        if file_obj.is_deleted:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                                detail="File not found.")
    else:
        # Recipient: access is controlled by FileAccess row only.
        if _get_access_record(file_obj.id, current_user.id, db) is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                                detail="File not found.")

    new_recipient = _lookup_active_user(body.recipient_username, db)

    # Prevent self-share
    if new_recipient.id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot share a file with yourself.",
        )

    # Idempotency guard — avoid duplicate access rows
    if _get_access_record(file_obj.id, new_recipient.id, db):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="That user already has access to this file.",
        )

    if body.new_ciphertext and body.new_nonce and body.new_encrypted_key:
        # ── Re-encrypted share (preferred) ────────────────────────────
        # The sharer decrypted the original on their device and re-encrypted
        # it for the new recipient.  Create a fresh file row so the new
        # recipient can actually decrypt the content with their own key pair.
        stored_blob = _pack(body.new_nonce, body.new_ciphertext)
        integrity   = bytes(Web3.keccak(text=stored_blob)).hex()  # 64-char hex, no 0x

        shared_file = models.FileObject(
            owner_id=current_user.id,
            ciphertext=stored_blob,
            subject=file_obj.subject,
            filename=file_obj.filename,
            content_type=file_obj.content_type,
            size_bytes=file_obj.size_bytes,
            integrity_hash=integrity,
            is_forwarded=True,
        )
        db.add(shared_file)
        db.flush()   # allocate shared_file.id

        db.add(models.FileAccess(
            file_id=shared_file.id,
            recipient_id=new_recipient.id,
            encrypted_key=body.new_encrypted_key,
        ))

        _append_blockchain_record(shared_file, db)
        db.commit()

        threading.Thread(
            target=_submit_to_chain,
            args=(shared_file.id, shared_file.integrity_hash),
            daemon=True,
        ).start()
    else:
        # ── Legacy path: share existing file_access row ───────────────
        # The new recipient receives the original ciphertext but cannot
        # decrypt it (it was encrypted for the original recipient's key).
        db.add(models.FileAccess(
            file_id=file_obj.id,
            recipient_id=new_recipient.id,
            encrypted_key=body.encrypted_key,
        ))
        db.commit()

    return {"detail": f"File shared with {new_recipient.username}."}


# ---------------------------------------------------------------------------
# POST /files/{id}/revoke
# ---------------------------------------------------------------------------

@router.post(
    "/{file_id}/revoke",
    response_model=DetailResponse,
    summary="Revoke file access",
    responses={
        403: {"description": "Not the owner"},
        404: {"description": "File or recipient not found"},
    },
)
def revoke_access(
    file_id: int,
    body: RevokeRequest,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    """Revoke access to a file.  Only the owner may do this.

    **Without `recipient_username`** — full revocation: removes every
    recipient's `file_access` row so no recipient can download the file.
    The file row, ciphertext, and BlockchainRecord are preserved —
    revocation is an access-control action, not a deletion.  The owner can
    still see the file in their owned list.

    **With `recipient_username`** — targeted revocation: removes that specific
    recipient's `file_access` row.  Other recipients are unaffected.

    Note: revocation is a server-side access control measure.  Any recipient
    who already downloaded and decrypted the file retains their local
    plaintext copy — the server cannot un-decrypt a file already received.
    """
    file_obj = _load_active_file(file_id, db)
    _require_owner(file_obj, current_user)

    if body.recipient_username is None:
        # Full revocation: remove every FileAccess row so no recipient can
        # download the file.
        access_rows = db.scalars(
            select(models.FileAccess).where(
                models.FileAccess.file_id == file_obj.id
            )
        ).all()
        for row in access_rows:
            db.delete(row)
        db.commit()
        return {"detail": "File access revoked for all recipients."}

    # Targeted revocation: remove only this recipient's access row.
    target = _lookup_active_user(body.recipient_username, db)
    access = _get_access_record(file_obj.id, target.id, db)
    if access is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"{target.username} does not have access to this file.",
        )

    db.delete(access)
    db.commit()

    return {"detail": f"Access revoked for {target.username}."}


# ---------------------------------------------------------------------------
# GET /files/{id}/download
# ---------------------------------------------------------------------------

@router.get(
    "/{file_id}/download",
    response_model=FileDownloadResponse,
    summary="Download a file's encrypted payload",
    responses={
        404: {"description": "File not found or no access"},
    },
)
def download_file(
    file_id: int,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    """Return the full encrypted payload needed to decrypt a file.

    Verifies that `current_user` is either the owner or an authorised
    recipient (via `file_access`).  Returns 404 — not 403 — on any
    access failure to prevent IDOR: a 403 would confirm the file exists
    to someone who has no business knowing that.

    **Returned fields for decryption:**
    - `ciphertext`       — the combined stored blob (nonce ‖ ciphertext)
    - `nonce`            — the first 12 decoded bytes, re-encoded as base64
    - `associated_data`  — the canonical context string (informational)
    - `encrypted_key`    — the recipient's HPKE encapsulated key

    Marks the file as read in `file_access` (only for recipients;
    owners are implicitly always "read").
    """
    # Load the raw file row without the is_deleted gate so that recipients
    # can still download a file the owner soft-deleted (delete is owner-only).
    file_obj = db.get(models.FileObject, file_id)
    if file_obj is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="File not found.")

    if file_obj.owner_id == current_user.id:
        # Owner: is_deleted hides the file from their own view.
        if file_obj.is_deleted:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                                detail="File not found.")
        access = None
    else:
        # Recipient: access is controlled solely by the FileAccess row.
        # A missing row means either the file never existed for them, or
        # access was revoked — both surface as 404 to prevent IDOR.
        access = _get_access_record(file_obj.id, current_user.id, db)
        if access is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                                detail="File not found.")

    # ------------------------------------------------------------------
    # Split the stored blob into nonce and ciphertext.
    # _unpack() raises ValueError if the blob is malformed — treat that
    # as a server-side data integrity failure.
    # ------------------------------------------------------------------
    try:
        nonce_b64, _ct_b64 = _unpack(file_obj.ciphertext)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="File data is corrupted.",
        )

    # ------------------------------------------------------------------
    # Mark as read (only recipients have an access row; owners do not).
    # ------------------------------------------------------------------
    if access is not None and not access.is_read:
        access.is_read = True
        access.read_at = datetime.now(timezone.utc)
        db.add(access)
        db.commit()

    # ------------------------------------------------------------------
    # Resolve owner display name (single DB lookup; not in a join because
    # this endpoint returns one row, not a list).
    # ------------------------------------------------------------------
    owner = db.get(models.User, file_obj.owner_id) if file_obj.owner_id else None

    # ------------------------------------------------------------------
    # Canonical AAD string, rebuilt from stored metadata.
    # The downloader IS the recipient in the normal case, so their own
    # username goes in the recipient slot.  (When the owner self-downloads,
    # the string is a placeholder — the owner cannot decrypt their own
    # upload anyway, since the content key derives from the recipient's
    # key pair.)
    #
    # SECURITY NOTE: a recipient must treat this field as advisory — the
    # binding check happens when they build the AAD from the same response
    # fields (owner_username, filename, own username) and the GCM tag
    # verifies.  A server that tampers with filename here also breaks the
    # tag, which is the point of binding it.
    # ------------------------------------------------------------------
    aad = _canonical_aad(
        owner.username if owner else None,
        current_user.username,
        file_obj.filename,
    )

    return {
        "id":              file_obj.id,
        "owner_id":        file_obj.owner_id,
        "owner_username":  owner.username if owner else None,
        "ciphertext":      file_obj.ciphertext,
        "nonce":           nonce_b64,
        "associated_data": aad,
        "encrypted_key":   access.encrypted_key if access else None,
        "subject":         file_obj.subject,
        "filename":        file_obj.filename,
        "content_type":    file_obj.content_type,
        "size_bytes":      file_obj.size_bytes,
        "integrity_hash":  file_obj.integrity_hash,
        "is_read":         access.is_read if access else True,
        "created_at":      file_obj.created_at,
    }


# ---------------------------------------------------------------------------
# GET /files/{id}/blockchain-proof
# ---------------------------------------------------------------------------

@router.get(
    "/{file_id}/blockchain-proof",
    summary="Retrieve on-chain proof for a file",
    responses={
        404: {"description": "File not found or no access"},
    },
)
def get_blockchain_proof(
    file_id: int,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    """Return the blockchain proof for a file.

    Recomputes keccak256 of the stored ciphertext, compares it to the
    persisted integrity_hash, and (if an Ethereum tx hash exists) fetches
    the on-chain hash from the Sepolia contract for final verification.

    Response fields:
      stored_hash   — keccak256 recorded at upload time (from SQLite)
      computed_hash — keccak256 freshly computed from the current ciphertext
      hash_match    — True when stored == computed (ciphertext not tampered)
      eth_tx_hash   — Sepolia tx hash, or null if not yet anchored
      on_chain      — contract record {exists, hash, timestamp, recorder} or null
      on_chain_match— True when on-chain hash == computed hash, or null
    """
    file_obj = db.get(models.FileObject, file_id)
    if file_obj is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="File not found.")

    if file_obj.owner_id == current_user.id:
        if file_obj.is_deleted:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                                detail="File not found.")
    else:
        if _get_access_record(file_obj.id, current_user.id, db) is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                                detail="File not found.")

    rec          = file_obj.blockchain_record
    stored_hash  = file_obj.integrity_hash or ""
    # Recompute using the same algorithm as the upload/share endpoints:
    # bytes(Web3.keccak(text=blob)).hex() — guaranteed 64-char keccak256 hex.
    computed_hash = bytes(Web3.keccak(text=file_obj.ciphertext)).hex()
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
