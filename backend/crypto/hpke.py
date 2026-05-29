"""
backend/crypto/hpke.py — HPKE Mode_Auth over X25519 + HKDF-SHA256 + AES-256-GCM.

Overview
--------
This module provides authenticated hybrid public-key encryption using a
manual implementation of HPKE Mode_Auth (RFC 9180) built from three
components available in the ``cryptography`` library:

  KEM  — DHKEM(X25519)      X25519 Diffie-Hellman key agreement
  KDF  — HKDF-SHA256        key derivation from the shared secret
  AEAD — AES-256-GCM        symmetric authenticated encryption

Public API
----------
  generate_keypair()                            -> (private_key, public_key)
  encapsulate(recip_pub, sender_priv, pt, info) -> (ciphertext, enc_key)
  decapsulate(recip_priv, sender_pub, ct, enc, info) -> plaintext

Why not use Mode_Base?
----------------------
Mode_Base is unauthenticated: any party can produce a ciphertext that
passes the recipient's decryption.  An attacker who intercepts a message
can replace it with their own message; the recipient has no way to tell.

Mode_Auth incorporates the sender's static private key into the shared
secret derivation.  Only a party who holds ``sender_priv`` can produce a
ciphertext that the recipient can successfully decrypt using the
corresponding ``sender_pub``.  Decryption is an implicit proof of sender
identity.

HPKE Mode_Auth construction
----------------------------
Sender (encapsulate):
  1. Generate a fresh ephemeral X25519 key pair (ek_priv, ek_pub).
  2. Compute two DH values:
       dh1 = X25519(ek_priv,     recipient_pub)   ← standard DH
       dh2 = X25519(sender_priv, recipient_pub)   ← auth DH
  3. Derive a 44-byte OKM with HKDF-SHA256:
       ikm  = dh1 ‖ dh2
       salt = ek_pub (the encapsulated key)
       OKM  = HKDF-SHA256(ikm, salt, info, length=44)
       aes_key = OKM[0:32]   (256-bit AES key)
       nonce   = OKM[32:44]  (96-bit GCM nonce)
  4. Encrypt: ct = AES-256-GCM(aes_key, nonce, plaintext)
  5. Transmit: (ct, ek_pub)

Recipient (decapsulate):
  1. Receive (ct, ek_pub) from sender.
  2. Recompute the same two DH values (commutativity of X25519):
       dh1 = X25519(recipient_priv, ek_pub)         = dh1 sender
       dh2 = X25519(recipient_priv, sender_pub)     = dh2 sender
  3. Re-run HKDF with identical inputs → identical (aes_key, nonce).
  4. Decrypt: AES-256-GCM.open(aes_key, nonce, ct)
     → InvalidTag if any input is wrong → re-raised as ValueError.

Why the nonce is derived rather than random
--------------------------------------------
In our standalone aead.py, the nonce is generated with os.urandom(12)
and transmitted alongside the ciphertext.  In HPKE, the nonce comes from
the key schedule: HKDF mixes the ephemeral key (which is random) into the
output, so the (aes_key, nonce) pair is unique per message without needing
an additional random draw.  The nonce is therefore deterministic given
(ek_priv, sender_priv, recipient_pub) but unpredictable to anyone who does
not hold all three.

Trust model — TOFU
------------------
HPKE Mode_Auth provides sender authentication, meaning Bob is guaranteed
that a message decryptable with Alice's public key was produced by whoever
holds Alice's private key.  It does NOT guarantee that the public key
stored as "Alice" in the database actually belongs to Alice.  That is the
key distribution problem.

We solve this with TOFU (Trust On First Use):

  First contact:  the recipient downloads and stores the sender's public
                  key.  They have no prior relationship, so they trust it.

  Subsequent:     they compare new keys against the stored fingerprint.
                  A mismatch triggers a warning — the standard "safety
                  number changed" pattern used by Signal and WhatsApp.

TOFU is vulnerable to a man-in-the-middle at the very first key exchange.
This is an acceptable trade-off for a university project because:

  1. The first-contact MitM requires active infrastructure access at a
     precise moment — a nation-state-level attack, not a passive attacker
     reading a database dump.
  2. Mode_Auth stops the attacker from relaying forged messages: even if
     Eve captured Alice's trust-grant with Eve's own key, Eve cannot
     produce a valid Mode_Auth ciphertext that Bob will accept as from
     Alice (she does not hold Alice's private key).
  3. The architecture supports out-of-band fingerprint verification as a
     future upgrade, identical to Signal's "verify safety number" flow.

References
----------
  RFC 9180 — Hybrid Public Key Encryption
  RFC 7748 — Elliptic Curves for Diffie-Hellman Key Agreement (X25519)
  cryptography library: hazmat.primitives.asymmetric.x25519
"""

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)


# ---------------------------------------------------------------------------
# Size constants
# ---------------------------------------------------------------------------

# X25519 keys (private and public) are always exactly 32 bytes in raw form.
KEY_SIZE: int = 32

# The encapsulated key transmitted from sender to recipient is the ephemeral
# X25519 public key — also 32 bytes.
ENCAPSULATED_KEY_SIZE: int = KEY_SIZE

# HKDF output length: 32 bytes for the AES-256 key + 12 bytes for the
# GCM nonce = 44 bytes total.
_KDF_OUTPUT_LEN: int = 44


# ---------------------------------------------------------------------------
# Internal serialisation helpers
# ---------------------------------------------------------------------------

def _load_private(raw: bytes) -> X25519PrivateKey:
    """Deserialise a raw 32-byte private key into an X25519PrivateKey object."""
    if len(raw) != KEY_SIZE:
        raise ValueError(
            f"Private key must be exactly {KEY_SIZE} bytes; got {len(raw)}."
        )
    return X25519PrivateKey.from_private_bytes(raw)


def _load_public(raw: bytes) -> X25519PublicKey:
    """Deserialise a raw 32-byte public key into an X25519PublicKey object."""
    if len(raw) != KEY_SIZE:
        raise ValueError(
            f"Public key must be exactly {KEY_SIZE} bytes; got {len(raw)}."
        )
    return X25519PublicKey.from_public_bytes(raw)


def _raw_private(key: X25519PrivateKey) -> bytes:
    return key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())


def _raw_public(key: X25519PublicKey) -> bytes:
    return key.public_bytes(Encoding.Raw, PublicFormat.Raw)


# ---------------------------------------------------------------------------
# Mode_Auth key schedule
# ---------------------------------------------------------------------------

def _derive_key_and_nonce(
    dh1: bytes,
    dh2: bytes,
    encapsulated_key: bytes,
    info: bytes,
) -> tuple[bytes, bytes]:
    """Run the HKDF key schedule for HPKE Mode_Auth.

    Parameters
    ----------
    dh1:
        Output of X25519(ephemeral_private, recipient_public) on the sender
        side, or X25519(recipient_private, ephemeral_public) on the recipient
        side.  These are equal by commutativity of X25519.
    dh2:
        Output of X25519(sender_static_private, recipient_public) on the
        sender side, or X25519(recipient_private, sender_static_public) on the
        recipient side.  Equal by the same commutativity property.
    encapsulated_key:
        Raw bytes of the ephemeral public key (ek_pub).  Used as the HKDF
        salt so the key derivation is tied to this specific encapsulation.
    info:
        Application context string.  Different values produce different keys,
        providing domain separation between applications and protocol versions.

    Returns
    -------
    tuple[bytes, bytes]
        (aes_key, nonce) — 32-byte AES-256 key and 12-byte GCM nonce.
    """
    # Concatenate the two DH outputs as the HKDF input key material (IKM).
    # Using both DH outputs is what distinguishes Mode_Auth from Mode_Base:
    # - dh1 alone would give an unauthenticated scheme (any party could
    #   produce a valid encapsulation to the recipient).
    # - dh2 ties the derivation to the sender's static private key: only
    #   the holder of sender_static_priv can compute dh2 = X25519(sender_priv,
    #   recip_pub), so only they can derive the correct (aes_key, nonce).
    ikm = dh1 + dh2

    # HKDF-SHA256:
    #   salt = encapsulated_key (the ephemeral public key)
    #     → ties the derived keys to this specific encapsulation; reusing
    #       the same (sender_priv, recip_pub) pair with a different ephemeral
    #       key still produces different output.
    #   info = application context
    #     → domain-separates key material for different applications or
    #       protocol versions even if the same key pairs are reused.
    #   length = 44 = 32 (AES-256 key) + 12 (GCM nonce)
    #     → single HKDF call produces both values; they are cryptographically
    #       independent because they come from different offset positions in
    #       the same uniformly distributed output stream.
    okm = HKDF(
        algorithm=hashes.SHA256(),
        length=_KDF_OUTPUT_LEN,
        salt=encapsulated_key,
        info=info,
    ).derive(ikm)

    aes_key = okm[:32]   # bytes 0–31: AES-256 key
    nonce   = okm[32:]   # bytes 32–43: 12-byte GCM nonce (96 bits)
    return aes_key, nonce


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_keypair() -> tuple[bytes, bytes]:
    """Generate a fresh X25519 key pair for use with encapsulate/decapsulate.

    The private key is the value that must be kept secret on the user's
    device and NEVER transmitted or stored on the server.  The public key
    is stored in ``users.public_key`` and shared freely.

    Returns
    -------
    tuple[bytes, bytes]
        ``(private_key, public_key)`` — each is 32 raw bytes.

        private_key:
            32-byte X25519 scalar.  Store securely on the client; never
            upload to the server.  Loss of this key means the user cannot
            decrypt any messages received while it was active.

        public_key:
            32-byte X25519 point (the Montgomery u-coordinate).  Upload to
            ``users.public_key`` at registration.  Safe to store and
            transmit in plaintext — it is the basis of the TOFU trust grant.
    """
    priv = X25519PrivateKey.generate()
    pub  = priv.public_key()
    return _raw_private(priv), _raw_public(pub)


def encapsulate(
    recipient_public_key: bytes,
    sender_private_key: bytes,
    plaintext: bytes,
    info: bytes = b"secure-messenger",
) -> tuple[bytes, bytes]:
    """Encrypt *plaintext* for *recipient_public_key* in HPKE Mode_Auth.

    Mode_Auth means the ciphertext is cryptographically bound to both the
    recipient's public key AND the sender's static private key.  The
    recipient can only decrypt if they hold ``recipient_private_key``, and
    they are guaranteed that the ciphertext was produced by whoever holds
    ``sender_private_key``.

    A fresh ephemeral X25519 key pair is generated on every call.  The
    ephemeral private key is discarded immediately after the DH computation;
    it never appears in the output or in persistent storage.

    Parameters
    ----------
    recipient_public_key:
        Raw 32-byte X25519 public key of the intended recipient.  Fetched
        from ``users.public_key`` and used for the DH computation.  The
        sender does not need to verify this key out-of-band for the
        cryptography to work; TOFU provides the trust model (see module
        docstring).
    sender_private_key:
        Raw 32-byte X25519 private key of the sender.  This is the static
        key that proves sender identity: only the holder of this key can
        produce a valid ciphertext that passes the recipient's decapsulation
        with the corresponding ``sender_public_key``.
    plaintext:
        The message bytes to encrypt.  The server never sees this value —
        it is encrypted entirely on the sender's device before transmission.
        An empty plaintext (``b""``) is valid.
    info:
        Application context bytes mixed into the HKDF key schedule.  The
        default ``b"secure-messenger"`` domain-separates this application
        from any other system that might use the same key pairs.  Change
        this if you need to produce keys for a different protocol context.

    Returns
    -------
    tuple[bytes, bytes]
        ``(ciphertext, encapsulated_key)``

        ciphertext:
            AES-256-GCM encrypted plaintext with the 16-byte authentication
            tag appended.  Length = ``len(plaintext) + 16`` bytes.  Store in
            ``messages.ciphertext`` (combined with ``encapsulated_key``).

        encapsulated_key:
            32-byte ephemeral X25519 public key (ek_pub).  This is the
            "encrypted key" that the recipient uses during decapsulation to
            recompute the same shared secret.  It is safe to store and
            transmit in plaintext — without ``recipient_private_key`` it
            yields no information about the AES key or plaintext.  Store
            in ``messages.ciphertext`` prepended to *ciphertext*, or in a
            separate column.

    Raises
    ------
    ValueError
        If either key is not exactly 32 bytes.
    """
    # ------------------------------------------------------------------
    # Load keys from raw bytes (validates length)
    # ------------------------------------------------------------------
    recip_pub   = _load_public(recipient_public_key)
    sender_priv = _load_private(sender_private_key)

    # ------------------------------------------------------------------
    # Generate ephemeral key pair.
    # ek_priv is used once and then goes out of scope — Python's garbage
    # collector will free it.  It NEVER appears in the function output.
    # ek_pub (the encapsulated key) is transmitted to the recipient so
    # they can replicate the DH computation on their side.
    # ------------------------------------------------------------------
    ek_priv = X25519PrivateKey.generate()
    ek_pub  = ek_priv.public_key()
    enc     = _raw_public(ek_pub)   # 32 bytes: the encapsulated key

    # ------------------------------------------------------------------
    # Two DH operations — the core of Mode_Auth
    #
    # dh1 = X25519(ek_priv, recip_pub)
    #   Standard unauthenticated DH.  Any party with an ephemeral key pair
    #   could compute this.
    #
    # dh2 = X25519(sender_priv, recip_pub)
    #   The authentication contribution.  Only the holder of sender_priv
    #   can compute this value.  On the recipient side, dh2 is recomputed
    #   as X25519(recip_priv, sender_pub); X25519 commutativity guarantees
    #   both sides arrive at the same 32-byte result.
    # ------------------------------------------------------------------
    dh1 = ek_priv.exchange(recip_pub)      # ephemeral × recipient
    dh2 = sender_priv.exchange(recip_pub)  # static sender × recipient

    # ------------------------------------------------------------------
    # Derive AES-256 key and GCM nonce from the two DH outputs.
    # The nonce is deterministic (derived from the key schedule) rather
    # than randomly generated.  Uniqueness is guaranteed by the fresh
    # ephemeral key: even for the same (sender, recipient, plaintext),
    # a different ek_priv produces a completely different (dh1, enc,
    # aes_key, nonce) tuple.
    # ------------------------------------------------------------------
    aes_key, nonce = _derive_key_and_nonce(dh1, dh2, enc, info)

    # ------------------------------------------------------------------
    # Symmetric encryption with AES-256-GCM.
    # The 16-byte authentication tag is appended to the ciphertext by the
    # library.  associated_data is None — context binding is already
    # provided by the info string in the HKDF step, which is stronger
    # (it binds the key itself, not just the ciphertext).
    # ------------------------------------------------------------------
    ciphertext = AESGCM(aes_key).encrypt(nonce, plaintext, None)

    return ciphertext, enc


def decapsulate(
    recipient_private_key: bytes,
    sender_public_key: bytes,
    ciphertext: bytes,
    encapsulated_key: bytes,
    info: bytes = b"secure-messenger",
) -> bytes:
    """Decrypt *ciphertext* and verify sender identity in HPKE Mode_Auth.

    Replicates the sender's key schedule using the encapsulated key and the
    sender's static public key, then decrypts with AES-256-GCM.

    Decryption succeeds if and only if:
      - *recipient_private_key* is the private key matching the public key
        used during encapsulation.
      - *sender_public_key* is the public key matching the private key used
        during encapsulation (the claimed sender actually sent this message).
      - *encapsulated_key* was produced by the same encapsulate() call.
      - *ciphertext* has not been tampered with.
      - *info* matches the value used during encapsulation.

    If any of these conditions fails, decryption raises ``ValueError``.
    This is the Mode_Auth guarantee: a failed decryption is evidence of
    either tampering or impersonation — the ciphertext was not produced by
    the claimed sender.

    Trust model note: this guarantee holds only if *sender_public_key* is
    authentic — i.e. it really belongs to the claimed sender.  TOFU provides
    this assurance after the first key exchange (see module docstring).  If
    an attacker replaced the sender's public key at the moment of first
    contact, decryption may succeed with the wrong sender's key.  Mitigate
    this with out-of-band fingerprint verification.

    Parameters
    ----------
    recipient_private_key:
        Raw 32-byte X25519 private key of the recipient.  Must match the
        public key the sender used during encapsulation.  This key never
        leaves the recipient's device.
    sender_public_key:
        Raw 32-byte X25519 static public key of the claimed sender.  Loaded
        from ``users.public_key`` using the TOFU-stored fingerprint.
    ciphertext:
        The ``ciphertext`` bytes returned by :func:`encapsulate`.  Includes
        the 16-byte GCM authentication tag at the end.
    encapsulated_key:
        The ``encapsulated_key`` bytes returned by :func:`encapsulate`.
        The 32-byte ephemeral public key (ek_pub) used to replicate the DH.
    info:
        Must exactly match the value passed to :func:`encapsulate`.  Even a
        single byte difference produces a completely different (aes_key,
        nonce) pair and causes decryption to fail.

    Returns
    -------
    bytes
        The original plaintext, verified authentic.

    Raises
    ------
    ValueError
        If any key is not 32 bytes, ciphertext is too short, or the
        authentication tag does not verify.  All failure cases produce the
        same exception type to avoid leaking which check failed.
    """
    # ------------------------------------------------------------------
    # Input size guards
    # ------------------------------------------------------------------
    if len(encapsulated_key) != ENCAPSULATED_KEY_SIZE:
        raise ValueError(
            f"encapsulated_key must be {ENCAPSULATED_KEY_SIZE} bytes; "
            f"got {len(encapsulated_key)}."
        )
    if len(ciphertext) < 16:
        # Minimum: empty plaintext + 16-byte GCM tag
        raise ValueError(
            f"ciphertext is too short to contain a GCM tag "
            f"(minimum 16 bytes; got {len(ciphertext)})."
        )

    # ------------------------------------------------------------------
    # Load keys (validates 32-byte length)
    # ------------------------------------------------------------------
    recip_priv  = _load_private(recipient_private_key)
    sender_pub  = _load_public(sender_public_key)
    ek_pub      = _load_public(encapsulated_key)

    # ------------------------------------------------------------------
    # Replicate the two DH operations from encapsulate().
    #
    # X25519 commutativity guarantees:
    #   X25519(ek_priv,     recip_pub) == X25519(recip_priv, ek_pub)  ← dh1
    #   X25519(sender_priv, recip_pub) == X25519(recip_priv, sender_pub) ← dh2
    #
    # The recipient can compute both without ever seeing ek_priv or
    # sender_priv.  If sender_pub does not match the key used at encrypt
    # time, dh2 is wrong, the derived (aes_key, nonce) differ from the
    # sender's, and the GCM tag verification fails.
    # ------------------------------------------------------------------
    dh1 = recip_priv.exchange(ek_pub)      # recipient × ephemeral
    dh2 = recip_priv.exchange(sender_pub)  # recipient × static sender

    aes_key, nonce = _derive_key_and_nonce(dh1, dh2, encapsulated_key, info)

    # ------------------------------------------------------------------
    # Decrypt and verify the authentication tag.
    # AESGCM.decrypt() raises InvalidTag if the tag does not verify.
    # We re-raise as ValueError to give callers a stable, library-agnostic
    # exception.  The error message is intentionally generic — specifying
    # "wrong sender key" vs "tampered ciphertext" vs "wrong recipient key"
    # would help an attacker understand which check failed.
    # ------------------------------------------------------------------
    try:
        return AESGCM(aes_key).decrypt(nonce, ciphertext, None)
    except InvalidTag:
        raise ValueError(
            "Decryption failed: authentication tag mismatch. "
            "The ciphertext was tampered with, or the sender key, "
            "recipient key, encapsulated key, or info string is incorrect."
        )
