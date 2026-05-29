"""
backend/crypto/kdf.py — HKDF-SHA256 key derivation helpers.

Overview
--------
This module exposes a single function:

  derive_key(shared_secret, info, salt, length) -> bytes

It wraps HKDF (HMAC-based Key Derivation Function, RFC 5869) with SHA-256
and enforces the domain-separation discipline that makes derived keys safe
to use in independent cryptographic contexts.

Why this module exists
----------------------
A raw shared secret — e.g. the output of an X25519 or ECDH key exchange —
is not suitable as a direct AES-256-GCM key for three reasons:

  1. Non-uniformity
     Elliptic-curve shared secrets are coordinates on a curve.  Not every
     32-byte string is a valid coordinate, so the secret has algebraic
     structure.  AES-256-GCM's security proof assumes the key is drawn
     uniformly from all 2²⁵⁶ bit strings.  Passing a structured value
     violates that assumption.  HKDF's extract phase (an HMAC evaluation)
     maps any distribution onto a uniformly distributed pseudorandom key.

  2. Key reuse across purposes
     Using the same bytes as both an encryption key and a MAC key couples
     their security: a weakness that leaks bits of the encryption key also
     leaks bits of the MAC key.  derive_key() with distinct *info* strings
     produces cryptographically independent keys from the same secret.

  3. Context binding
     A raw shared secret carries no record of who produced it, for what
     purpose, or under which protocol version.  The *info* string binds
     each derived key to its exact context; a key derived for
     "message-encryption" is provably useless for "message-auth" or for
     any other application.

HKDF internals (brief)
-----------------------
HKDF runs two HMAC-SHA256 operations:

  Extract:  PRK = HMAC-SHA256(salt, shared_secret)
            Maps the (possibly structured) shared_secret to a uniform
            pseudorandom key (PRK) of exactly 32 bytes.

  Expand:   OKM = T(1) ‖ T(2) ‖ ...  truncated to *length* bytes
            where T(i) = HMAC-SHA256(PRK, T(i-1) ‖ info ‖ counter)
            Each block is independent; different *info* values produce
            keys that are computationally indistinguishable from
            independent random values even to an attacker who knows the
            PRK.

References
----------
  RFC 5869  — HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
  NIST SP 800-56C Rev.2 — Recommendation for Key-Derivation Methods in
                           Key-Establishment Schemes
"""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# ---------------------------------------------------------------------------
# Size constraints
# ---------------------------------------------------------------------------

# SHA-256 produces 32 bytes per HMAC evaluation.  HKDF-Expand can run at
# most 255 iterations, so the maximum output is 255 × 32 = 8 160 bytes.
# Requesting more is a programming error; we raise before the library does.
_HASH_LEN: int = 32
MAX_DERIVE_LENGTH: int = 255 * _HASH_LEN   # 8 160 bytes


# ---------------------------------------------------------------------------
# Pre-defined info string constants
#
# Domain separation requires that every distinct key use case has a unique
# info string.  Defining named constants here rather than scattering raw
# string literals across the codebase serves two purposes:
#
#   1. Typo safety — a misspelled info string silently derives a different
#      key with no runtime error.  Constants catch the mistake at import
#      time (NameError) rather than at the point of use.
#
#   2. Audit surface — every place in the codebase that derives a key for a
#      specific purpose is visible here.  Adding a new use case requires
#      adding a constant, which is a natural checkpoint for code review.
#
# Format: "<app>:<version>:<purpose>"
#
#   app     — prevents cross-application key collisions if the same shared
#             secret is ever used in another system
#   version — allows future protocol changes to derive different keys
#             without breaking old sessions (increment to v2, v3, etc.)
#   purpose — the specific cryptographic role of the derived key; must be
#             unique within this application and version
#
# IMPORTANT: once a constant is in production use, its value must NEVER
# change.  Changing an info string changes every derived key; any ciphertext
# encrypted under the old key becomes permanently unreadable.
# ---------------------------------------------------------------------------

# Key used to encrypt message body ciphertext with AES-256-GCM.
INFO_MESSAGE_ENCRYPTION: str = "secure-messenger:v1:message-encryption"

# Key used to authenticate message metadata (sender ID, recipient ID,
# timestamp) with HMAC-SHA256.  Separate from the encryption key so that
# a cryptanalytic attack on one does not compromise the other.
INFO_MESSAGE_AUTH: str = "secure-messenger:v1:message-auth"

# Key used to encrypt the session-level handshake payload (e.g. the
# per-message symmetric key wrapped for the recipient's public key).
INFO_SESSION_KEY: str = "secure-messenger:v1:session-key"

# Key used to encrypt optional plaintext header fields (subject line,
# message type tag) that need confidentiality but not the full message
# encryption treatment.
INFO_HEADER_ENCRYPTION: str = "secure-messenger:v1:header-encryption"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def derive_key(
    shared_secret: bytes,
    info: str,
    salt: bytes | None = None,
    length: int = 32,
) -> bytes:
    """Derive a fixed-length cryptographic key from *shared_secret* using
    HKDF-SHA256.

    This function combines the HKDF Extract and Expand phases in a single
    call.  The derived key is uniformly distributed, has full entropy (up to
    the entropy in *shared_secret*), and is cryptographically independent of
    keys derived with any other *info* string from the same secret.

    Parameters
    ----------
    shared_secret:
        The input key material (IKM) — typically the output of a Diffie-
        Hellman key exchange (X25519, ECDH) or any other source of shared
        entropy.  Must be non-empty.  Does not need to be uniformly random;
        HKDF's extract phase removes any bias or algebraic structure.
    info:
        A non-empty string that identifies the exact purpose of the derived
        key.  Use one of the module-level ``INFO_*`` constants:

            from backend.crypto.kdf import derive_key, INFO_MESSAGE_ENCRYPTION
            key = derive_key(secret, INFO_MESSAGE_ENCRYPTION)

        **Domain separation guarantee:** two calls with different *info*
        values produce keys that are computationally indistinguishable from
        independent random values, even to an attacker who knows the
        *shared_secret* and all other *info* strings in use.  This means:

          - A side-channel that leaks bits of the message-encryption key
            reveals nothing about the message-auth key.
          - An attacker cannot use a key derived for one purpose in a
            context expecting a key derived for another purpose.
          - Different protocol versions (v1 vs v2 in the info prefix)
            produce completely different keys from the same secret.

        **The info string must be unique per use case within this application
        and version.**  Two different callers that accidentally use the same
        info string will derive the same key, silently destroying the
        independence guarantee.  This is why raw strings should never be
        passed; always use the named ``INFO_*`` constants.

        The string is encoded to UTF-8 before being passed to HKDF; it is
        not a secret and need not be kept confidential.
    salt:
        Optional bytes mixed into the HKDF Extract phase as the HMAC key::

            PRK = HMAC-SHA256(salt, shared_secret)

        The salt is *not* a secret — it is safe to transmit or store in
        plaintext.  Its purpose is to remove bias from the shared_secret
        distribution and, when unique per session, to ensure that two
        sessions using the same long-term key pair derive different PRKs and
        therefore different encryption keys.

        Recommended practice: use a value exchanged during the handshake,
        such as the concatenation of both parties' ephemeral public nonces::

            salt = alice_nonce + bob_nonce   # both transmitted in the clear

        When ``None`` (the default), HKDF substitutes a block of 32 zero
        bytes per RFC 5869 §2.2.  This is cryptographically valid — the
        extract phase still runs and the output is still uniform — but it
        means two sessions using the same *shared_secret* and same *info*
        will derive the same key.  Provide a session-unique salt whenever
        possible.
    length:
        Number of output bytes to derive.  Defaults to 32 (256 bits), which
        is the correct size for an AES-256 key.  Must be between 1 and 8 160
        (the HKDF-SHA256 maximum: 255 × 32 bytes).

    Returns
    -------
    bytes
        *length* bytes of pseudorandom keying material, suitable for direct
        use as an AES-256-GCM key, HMAC key, or any other fixed-length
        symmetric key.

    Raises
    ------
    ValueError
        If *shared_secret* is empty, *info* is empty, or *length* is outside
        the range [1, 8160].
    TypeError
        If *shared_secret* or *salt* is not bytes, or *info* is not a str.
    """
    # ------------------------------------------------------------------
    # Input validation — catch caller mistakes with clear messages before
    # any cryptographic operation runs.
    # ------------------------------------------------------------------
    if not isinstance(shared_secret, bytes):
        raise TypeError(
            f"shared_secret must be bytes; got {type(shared_secret).__name__}."
        )
    if not shared_secret:
        # An empty IKM provides zero entropy; every call would derive the
        # same key regardless of salt or info, defeating the purpose entirely.
        raise ValueError("shared_secret must not be empty.")

    if not isinstance(info, str):
        raise TypeError(
            f"info must be a str constant (use an INFO_* constant); "
            f"got {type(info).__name__}."
        )
    if not info:
        # An empty info string makes all derive_key() calls with the same
        # shared_secret and length derive the same output, destroying domain
        # separation.  A non-empty info string is the only mechanism that
        # separates "message-encryption" keys from "message-auth" keys.
        raise ValueError(
            "info must be a non-empty string. "
            "Use one of the INFO_* constants defined in this module."
        )

    if salt is not None and not isinstance(salt, bytes):
        raise TypeError(
            f"salt must be bytes or None; got {type(salt).__name__}."
        )

    if not isinstance(length, int) or isinstance(length, bool):
        raise TypeError(f"length must be an int; got {type(length).__name__}.")
    if length < 1:
        raise ValueError(f"length must be at least 1; got {length}.")
    if length > MAX_DERIVE_LENGTH:
        raise ValueError(
            f"length exceeds the HKDF-SHA256 maximum of {MAX_DERIVE_LENGTH} "
            f"bytes (255 × 32); got {length}."
        )

    # ------------------------------------------------------------------
    # Key derivation
    #
    # HKDF is intentionally single-use: calling .derive() a second time on
    # the same instance raises AlreadyFinalized.  We construct a new
    # instance on every call, which is the correct pattern.  The HKDF
    # constructor is cheap — no computation happens until .derive() is
    # called.
    #
    # Parameter mapping
    # -----------------
    #   algorithm — SHA-256; determines hash output length (32 bytes) and
    #               the maximum derivable output (255 × 32 = 8 160 bytes).
    #   length    — exact byte count of the derived key.
    #   salt      — passed through as-is; the library substitutes a
    #               zeroed 32-byte block when None (RFC 5869 §2.2).
    #   info      — encoded to UTF-8 here so callers work with readable
    #               Python str constants rather than b-prefixed bytes.
    #               The encoding is stable and portable across platforms.
    # ------------------------------------------------------------------
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info.encode("utf-8"),
    )
    return hkdf.derive(shared_secret)
