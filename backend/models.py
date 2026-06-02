"""
models.py — SQLAlchemy ORM table definitions (SQLAlchemy 2.0 style).

Tables
------
  users             — registered accounts
  sessions          — active auth sessions / refresh tokens
  messages          — encrypted message payloads
  message_access    — per-recipient access-control records
  blockchain_records — append-only audit log (simulated chain)
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
    sent_messages: Mapped[list["Message"]] = relationship(
        "Message", back_populates="sender", foreign_keys="Message.sender_id"
    )
    sessions: Mapped[list["Session"]] = relationship("Session", back_populates="user")
    access_records: Mapped[list["MessageAccess"]] = relationship(
        "MessageAccess", back_populates="recipient"
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
# messages
# ---------------------------------------------------------------------------
class Message(Base):
    """
    An encrypted message.  The ciphertext is stored opaquely; only the
    intended recipient can decrypt it using their private key.
    """

    __tablename__ = "messages"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    sender_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )

    # Encrypted payload (base64-encoded ciphertext)
    ciphertext: Mapped[str] = mapped_column(Text, nullable=False)

    # Optional subject line (may itself be encrypted)
    subject: Mapped[str | None] = mapped_column(String(512), nullable=True)

    # SHA-256 / HMAC integrity tag for tamper detection
    integrity_hash: Mapped[str | None] = mapped_column(String(256), nullable=True)

    is_deleted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    # Marks messages created by the forward endpoint (re-encrypted for a new recipient).
    # Existing rows will be NULL (treated as False); new DB gets the column via create_all.
    # Migration for existing DB: ALTER TABLE messages ADD COLUMN is_forwarded BOOLEAN DEFAULT 0;
    is_forwarded: Mapped[bool | None] = mapped_column(
        Boolean, default=False, nullable=True, server_default="0"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )

    # Relationships
    sender: Mapped["User"] = relationship(
        "User", back_populates="sent_messages", foreign_keys=[sender_id]
    )
    access_records: Mapped[list["MessageAccess"]] = relationship(
        "MessageAccess", back_populates="message"
    )
    blockchain_record: Mapped["BlockchainRecord | None"] = relationship(
        "BlockchainRecord", back_populates="message", uselist=False
    )


# ---------------------------------------------------------------------------
# message_access  (per-recipient ACL)
# ---------------------------------------------------------------------------
class MessageAccess(Base):
    """
    Links a message to each authorised recipient.

    The encrypted_key field stores the message symmetric key wrapped
    (encrypted) with the recipient's public key, so only that recipient
    can unwrap it.
    """

    __tablename__ = "message_access"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    message_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("messages.id", ondelete="CASCADE"), nullable=False, index=True
    )
    recipient_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )

    # Symmetric key encrypted with recipient's public key (base64)
    encrypted_key: Mapped[str | None] = mapped_column(Text, nullable=True)

    is_read: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    read_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    granted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )

    # Relationships
    message: Mapped["Message"] = relationship("Message", back_populates="access_records")
    recipient: Mapped["User"] = relationship("User", back_populates="access_records")


# ---------------------------------------------------------------------------
# blockchain_records  (append-only audit log)
# ---------------------------------------------------------------------------
class BlockchainRecord(Base):
    """
    Append-only audit log that links each message to a chain of hashes,
    providing tamper-evidence similar to a blockchain structure.

    Each record stores:
      - A hash of the current message
      - The hash of the *previous* record (chain link)
      - A combined block hash (prev_hash + message_hash)
    """

    __tablename__ = "blockchain_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    message_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("messages.id", ondelete="RESTRICT"),   # never delete a chained record
        unique=True,
        nullable=False,
        index=True,
    )

    # SHA-256 of the message ciphertext + metadata
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
    message: Mapped["Message"] = relationship("Message", back_populates="blockchain_record")
