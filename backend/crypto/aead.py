"""
backend/crypto/aead.py — AES-256-GCM authenticated encryption helpers.

Overview
--------
This module provides two functions that together form the complete
encrypt / decrypt cycle for message payloads:

  encrypt(plaintext, key, associated_data) -> (ciphertext, nonce)
  decrypt(ciphertext, key, nonce, associated_data) -> plaintext

Both functions use **AES-256-GCM**, an AEAD (Authenticated Encryption with
Associated Data) cipher.  "AEAD" means a single primitive simultaneously
provides:

  Confidentiality  — an attacker cannot read the plaintext
  Integrity        — any modification to the ciphertext is detected
  Authenticity     — the ciphertext was produced by someone who holds the key

Without authentication (e.g. raw AES-CBC, AES-CTR) an attacker who intercepts
the ciphertext can flip bits, truncate, or splice it.  The decryption will
silently produce garbage or — worse — exploitable plaintext.  AES-GCM's
authentication tag prevents this: ``decrypt`` either returns verified
plaintext or raises ``ValueError`` before a single byte is released.

Wire format
-----------
Callers are responsible for storing and transmitting the three pieces needed
to decrypt:

  nonce       — 12 bytes (96 bits), returned by ``encrypt``
  ciphertext  — len(plaintext) + 16 bytes (the 16-byte GCM tag is appended
                by AESGCM.encrypt and consumed by AESGCM.decrypt; callers
                do not need to separate it)
  aad         — reconstructed by the caller at decrypt time; never stored
                inside the ciphertext

Typical storage in the database::

  messages.ciphertext = base64(nonce + ciphertext_with_tag)

Or as separate columns::

  messages.nonce      = base64(nonce)             # 12 bytes → 16 chars b64
  messages.ciphertext = base64(ciphertext_with_tag)

References
----------
  NIST SP 800-38D — Recommendation for Block Cipher Modes: GCM and GMAC
  RFC 5116       — An Interface and Algorithms for Authenticated Encryption
  cryptography library AEAD docs
    https://cryptography.io/en/latest/hazmat/primitives/aead/
"""

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ---------------------------------------------------------------------------
# Size constants — named so magic numbers never appear in the logic below
# ---------------------------------------------------------------------------

# AES-256 requires a 256-bit (32-byte) key.  AES-128 (16 bytes) and AES-192
# (24 bytes) are also valid AES key sizes, but we fix 256 bits throughout this
# project to match the security level of our other primitives (Argon2id with
# 32-byte output, 256-bit JWT signing key).
KEY_SIZE: int = 32

# GCM is specified for 96-bit (12-byte) nonces.  Other sizes are technically
# valid but require an extra GHASH computation; 12 bytes is the NIST-preferred
# length and what every production system uses.
NONCE_SIZE: int = 12

# AES-GCM always appends a 128-bit (16-byte) authentication tag to the
# ciphertext.  AESGCM.encrypt() output is len(plaintext) + TAG_SIZE bytes.
# AESGCM.decrypt() strips and verifies the tag internally; callers never see
# it as a separate value.
TAG_SIZE: int = 16


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def encrypt(
    plaintext: bytes,
    key: bytes,
    associated_data: bytes | None = None,
) -> tuple[bytes, bytes]:
    """Encrypt *plaintext* with AES-256-GCM and return ``(ciphertext, nonce)``.

    The returned *ciphertext* already contains the 16-byte GCM authentication
    tag appended at the end (this is how ``AESGCM.encrypt`` works).  Pass it
    back to :func:`decrypt` as-is; do not strip the tag manually.

    A fresh 96-bit nonce is generated from the OS entropy pool on every call.
    The nonce is safe to store in plaintext alongside the ciphertext — it is
    not a secret.  It *must* be stored: without it decryption is impossible.

    Parameters
    ----------
    plaintext:
        The raw bytes to encrypt.  Encode strings before calling:
        ``plaintext.encode("utf-8")``.
    key:
        A 32-byte (256-bit) symmetric key.  Generate with ``os.urandom(32)``.
        For end-to-end encryption this is the per-message symmetric key that
        is itself encrypted (wrapped) with the recipient's public key and
        stored in ``message_access.encrypted_key``.
    associated_data:
        Optional bytes that are **authenticated but not encrypted**.  They are
        fed into the GCM authentication tag computation but do not appear in
        the ciphertext output.  The receiver must supply exactly the same bytes
        during decryption or the tag check will fail.

        Use this to bind the ciphertext to its context and prevent reuse
        attacks.  For example::

            aad = f"v1:sender={sender_id}:recipient={recipient_id}:msg={msg_id}"
            ct, nonce = encrypt(body, key, aad.encode())

        If an attacker copies a valid ``(ciphertext, nonce)`` from one
        conversation and presents it in another, the AAD will not match and
        decryption will raise ``ValueError``.

        ``None`` and ``b""`` are treated identically by the underlying library.

    Returns
    -------
    tuple[bytes, bytes]
        ``(ciphertext_with_tag, nonce)``

        *ciphertext_with_tag* — ``len(plaintext) + 16`` bytes.  The last 16
        bytes are the GCM tag; the rest is the encrypted payload.  Opaque to
        callers — pass it to :func:`decrypt` unchanged.

        *nonce* — 12 random bytes.  Store alongside the ciphertext.  Required
        for decryption.  Safe to store in the clear.

    Raises
    ------
    ValueError
        If *key* is not exactly 32 bytes.
    """
    # ------------------------------------------------------------------
    # Key size guard
    # A wrong key size produces a confusing low-level error from the
    # cryptography library; validate early with a clear message.
    # ------------------------------------------------------------------
    if len(key) != KEY_SIZE:
        raise ValueError(
            f"AES-256 key must be exactly {KEY_SIZE} bytes; got {len(key)}."
        )

    # ------------------------------------------------------------------
    # Nonce generation — the single most important correctness requirement
    #
    # AES-GCM is a stream cipher: it XORs the plaintext with a keystream
    # derived from (key, nonce).  If the same (key, nonce) pair is ever
    # used twice, the two keystreams are identical, and XOR-ing the two
    # ciphertexts cancels the keystream entirely:
    #
    #   ct1 ⊕ ct2 = pt1 ⊕ pt2   (two-time pad — both plaintexts recoverable)
    #
    # For GCM specifically, nonce reuse is even worse: it also exposes the
    # GHASH authentication subkey H = AES(key, 0), from which an attacker
    # can forge authentication tags for arbitrary messages.
    #
    # os.urandom(12) reads from the OS CSPRNG (/dev/urandom on Linux, the
    # Windows CryptGenRandom API on Windows).  The birthday-bound collision
    # probability for random 96-bit nonces reaches 1% only after ~4.8 × 10¹²
    # messages per key — for a per-user or per-message key this is negligible.
    # ------------------------------------------------------------------
    nonce = os.urandom(NONCE_SIZE)

    # ------------------------------------------------------------------
    # Encryption
    #
    # AESGCM.encrypt(nonce, plaintext, associated_data) returns:
    #   ciphertext_bytes || tag_bytes   (tag is always the last 16 bytes)
    #
    # The tag is computed over both the ciphertext and the associated_data
    # using GHASH (polynomial hashing over GF(2^128)).  Any modification to
    # either — even a single bit flip — produces a different tag and causes
    # decryption to fail.
    # ------------------------------------------------------------------
    ciphertext_with_tag = AESGCM(key).encrypt(nonce, plaintext, associated_data)

    return ciphertext_with_tag, nonce


def decrypt(
    ciphertext: bytes,
    key: bytes,
    nonce: bytes,
    associated_data: bytes | None = None,
) -> bytes:
    """Decrypt and verify *ciphertext* with AES-256-GCM.

    Before returning any plaintext, AES-GCM recomputes the 128-bit
    authentication tag from the ciphertext and *associated_data* and compares
    it (in constant time) to the tag embedded in *ciphertext*.  If they do not
    match — because the ciphertext was tampered with, the wrong key was used,
    the nonce is incorrect, or the associated data does not match what was
    supplied at encryption time — a ``ValueError`` is raised and no plaintext
    is returned.  There is no partial-decrypt path.

    Parameters
    ----------
    ciphertext:
        The bytes returned by :func:`encrypt` (ciphertext + 16-byte GCM tag).
        Must not be modified between encryption and decryption.
    key:
        The same 32-byte key used for encryption.
    nonce:
        The 12-byte nonce returned alongside *ciphertext* by :func:`encrypt`.
    associated_data:
        Must be identical to the value passed to :func:`encrypt`.  If
        encryption was called with ``associated_data=None``, pass ``None``
        here.  Even a single byte difference causes the tag check to fail.

        This is the mechanism that prevents context-confusion attacks: an
        ``(aad, ciphertext)`` pair produced for one conversation cannot be
        replayed in a different context because the receiver reconstructs the
        AAD from the current context metadata — if the metadata does not match,
        decryption raises ``ValueError``.

    Returns
    -------
    bytes
        The original plaintext, verified authentic.  Every byte of the
        returned value was produced by the legitimate encryptor.

    Raises
    ------
    ValueError
        In any of these cases (all produce the same error to avoid leaking
        which check failed):

        - Authentication tag mismatch: ciphertext was modified, truncated,
          or extended after encryption.
        - Wrong key: the provided key was not used for this ciphertext.
        - Wrong nonce: the nonce does not match the one used for encryption.
        - Wrong associated data: the AAD supplied here differs from the AAD
          supplied at encryption time.
        - Ciphertext too short: fewer than 16 bytes cannot contain a valid tag.
        - Key not 32 bytes or nonce not 12 bytes.
    """
    # ------------------------------------------------------------------
    # Input size guards — catch programming errors before the library does
    # ------------------------------------------------------------------
    if len(key) != KEY_SIZE:
        raise ValueError(
            f"AES-256 key must be exactly {KEY_SIZE} bytes; got {len(key)}."
        )
    if len(nonce) != NONCE_SIZE:
        raise ValueError(
            f"GCM nonce must be exactly {NONCE_SIZE} bytes; got {len(nonce)}."
        )
    # A valid GCM ciphertext is at minimum TAG_SIZE bytes (empty plaintext
    # encrypted produces only the 16-byte tag with no actual ciphertext bytes).
    if len(ciphertext) < TAG_SIZE:
        raise ValueError(
            f"Ciphertext is too short to contain a GCM tag "
            f"(minimum {TAG_SIZE} bytes; got {len(ciphertext)})."
        )

    # ------------------------------------------------------------------
    # Decryption + tag verification
    #
    # AESGCM.decrypt(nonce, ciphertext_with_tag, associated_data):
    #   1. Separates the last 16 bytes of ciphertext_with_tag as the tag.
    #   2. Re-derives the keystream from (key, nonce) and decrypts the
    #      remaining bytes to candidate plaintext.
    #   3. Recomputes the GHASH tag over (associated_data, ciphertext).
    #   4. Compares the recomputed tag to the stored tag in constant time.
    #      Step 4 always touches all 16 tag bytes regardless of where the
    #      first differing bit is — there is no early exit that could leak
    #      information via timing.
    #   5a. Tags match  → returns plaintext.
    #   5b. Tags differ → raises InvalidTag without returning any plaintext.
    #
    # We re-raise as ValueError to give callers a stable, library-agnostic
    # exception type to catch.  The message intentionally does not specify
    # which input was wrong — leaking "wrong nonce" vs "wrong key" vs
    # "tampered ciphertext" could assist an attacker probing the system.
    # ------------------------------------------------------------------
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, associated_data)
    except InvalidTag:
        raise ValueError(
            "Decryption failed: authentication tag mismatch. "
            "The ciphertext may have been tampered with, or the key, "
            "nonce, or associated data is incorrect."
        )
