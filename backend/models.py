"""
models.py — SQLAlchemy ORM table definitions (SQLAlchemy 2.0 style).

Tables
------
  users             — registered accounts
  sessions          — active auth sessions / refresh tokens
  files             — encrypted file payloads (the mailbox contents)
  file_access       — per-recipient access-control records
  blockchain_records — append-only audit log (simulated chain)

Migration note (mailbox pivot)
------------------------------
The former ``messages`` / ``message_access`` tables are renamed to ``files`` /
``file_access`` and gain optional file-metadata columns.  Development databases
are created via ``create_all`` — delete the .db file and restart to pick up the
new schema.  For an existing database that must be preserved:

    ALTER TABLE messages RENAME TO files;
    ALTER TABLE message_access RENAME TO file_access;
    ALTER TABLE file_access RENAME COLUMN message_id TO file_id;
    ALTER TABLE blockchain_records RENAME COLUMN message_id TO file_id;
    ALTER TABLE files RENAME COLUMN sender_id TO owner_id;
    ALTER TABLE files ADD COLUMN filename VARCHAR(255);
    ALTER TABLE files ADD COLUMN content_type VARCHAR(127);
    ALTER TABLE files ADD COLUMN size_bytes INTEGER;
"""

from datetime import datetime, timezone
from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.database import Base


# ---------------------------------------------------------------------------
# Helper – current UTC timestamp
# ---------------------------------------------------------------------------
def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# users
# ---------------------------------------------------------------------------
class User(Base):
    """A registered user account."""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)

    # Public key used for end-to-end encryption (PEM / base64 encoded)
    public_key: Mapped[str | None] = mapped_column(Text, nullable=True)

    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow, nullable=False
    )

    # Relationships
    owned_files: Mapped[list["FileObject"]] = relationship(
        "FileObject", back_populates="owner", foreign_keys="FileObject.owner_id"
    )
    sessions: Mapped[list["Session"]] = relationship("Session", back_populates="user")
    access_records: Mapped[list["FileAccess"]] = relationship(
        "FileAccess", back_populates="recipient"
    )


# ---------------------------------------------------------------------------
# sessions  (auth sessions / refresh tokens)
# ---------------------------------------------------------------------------
class Session(Base):
    """Tracks active authentication sessions for a user."""

    __tablename__ = "sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )

    # Opaque refresh-token stored as a hashed value
    token_hash: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)

    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)   # IPv6 max length
    user_agent: Mapped[str | None] = mapped_column(String(512), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    user: Mapped["User"] = relationship("User", back_populates="sessions")


# ---------------------------------------------------------------------------
# files
# ---------------------------------------------------------------------------
class FileObject(Base):
    """
    An encrypted file in the mailbox.  The ciphertext is stored opaquely; only
    an authorised recipient can decrypt it using their private key.

    ``owner_id`` is the uploading user.  In HPKE terms the owner is the
    *sender* (their static key authenticates the ciphertext); recipients are
    the users holding FileAccess rows.
    """

    __tablename__ = "files"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    owner_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )

    # Encrypted payload (base64-encoded ciphertext)
    ciphertext: Mapped[str] = mapped_column(Text, nullable=False)

    # Optional subject line (may itself be encrypted)
    subject: Mapped[str | None] = mapped_column(String(512), nullable=True)

    # ── File metadata (client-supplied, optional) ────────────────────────
    # Original filename for display and download naming.  Stored as given by
    # the client; may itself be client-side encrypted in a future revision
    # (it is visible to the server — see docs/crypto-design.md §8.5).
    filename: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # MIME type of the *plaintext* (e.g. "application/pdf").  Advisory only —
    # the server never inspects the ciphertext to verify it.
    content_type: Mapped[str | None] = mapped_column(String(127), nullable=True)

    # Size of the plaintext in bytes, as reported by the uploading client.
    size_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # SHA-256 / HMAC integrity tag for tamper detection
    integrity_hash: Mapped[str | None] = mapped_column(String(256), nullable=True)

    is_deleted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    # Marks files created by the share/forward endpoint (re-encrypted for a
    # new recipient).  Existing rows will be NULL (treated as False).
    is_forwarded: Mapped[bool | None] = mapped_column(
        Boolean, default=False, nullable=True, server_default="0"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )

    # Relationships
    owner: Mapped["User"] = relationship(
        "User", back_populates="owned_files", foreign_keys=[owner_id]
    )
    access_records: Mapped[list["FileAccess"]] = relationship(
        "FileAccess", back_populates="file"
    )
    blockchain_record: Mapped["BlockchainRecord | None"] = relationship(
        "BlockchainRecord", back_populates="file", uselist=False
    )


# ---------------------------------------------------------------------------
# file_access  (per-recipient ACL)
# ---------------------------------------------------------------------------
class FileAccess(Base):
    """
    Links a file to each authorised recipient.

    The encrypted_key field stores the HPKE encapsulated key (the ephemeral
    X25519 public key) for this recipient, so only that recipient can derive
    the content key and decrypt.
    """

    __tablename__ = "file_access"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    file_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("files.id", ondelete="CASCADE"), nullable=False, index=True
    )
    recipient_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )

    # HPKE encapsulated key for this recipient (base64)
    encrypted_key: Mapped[str | None] = mapped_column(Text, nullable=True)

    is_read: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    read_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    granted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )

    # Relationships
    file: Mapped["FileObject"] = relationship("FileObject", back_populates="access_records")
    recipient: Mapped["User"] = relationship("User", back_populates="access_records")


# ---------------------------------------------------------------------------
# blockchain_records  (append-only audit log)
# ---------------------------------------------------------------------------
class BlockchainRecord(Base):
    """
    Append-only audit log that links each file to a chain of hashes,
    providing tamper-evidence similar to a blockchain structure.

    Each record stores:
      - A hash of the current file's ciphertext
      - The hash of the *previous* record (chain link)
      - A combined block hash (prev_hash + message_hash)
    """

    __tablename__ = "blockchain_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    file_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("files.id", ondelete="RESTRICT"),   # never delete a chained record
        unique=True,
        nullable=False,
        index=True,
    )

    # SHA-256 of the file ciphertext + metadata
    message_hash: Mapped[str] = mapped_column(String(256), nullable=False)

    # Hash of the immediately preceding BlockchainRecord (genesis block = "0" * 64)
    previous_hash: Mapped[str] = mapped_column(String(256), nullable=False)

    # Combined block hash: SHA-256(previous_hash + message_hash)
    block_hash: Mapped[str] = mapped_column(String(256), nullable=False, unique=True)

    # Sequence number in the chain (1-based)
    block_index: Mapped[int] = mapped_column(Integer, nullable=False)

    # Sepolia transaction hash (populated by background thread after send)
    eth_tx_hash: Mapped[str | None] = mapped_column(String(66), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )

    # Relationships
    file: Mapped["FileObject"] = relationship("FileObject", back_populates="blockchain_record")
