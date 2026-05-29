"""
backend/crypto — cryptographic helpers for the secure messenger backend.

Public re-exports
-----------------
Password hashing (Argon2id):
  hash_password     — hash a plaintext password with Argon2id
  verify_password   — constant-time verify against a stored PHC hash
  needs_rehash      — detect whether a stored hash should be upgraded
  DUMMY_HASH        — a valid pre-computed hash for timing-safe "user not
                      found" responses (prevents user-enumeration attacks)

Authenticated encryption (AES-256-GCM):
  encrypt           — encrypt bytes; returns (ciphertext_with_tag, nonce)
  decrypt           — decrypt and verify; raises ValueError on tag mismatch
  KEY_SIZE          — required key length in bytes (32)
  NONCE_SIZE        — nonce length in bytes (12)
  TAG_SIZE          — GCM authentication tag length in bytes (16)

Key derivation (HKDF-SHA256):
  derive_key             — derive a fixed-length key from a shared secret
  INFO_MESSAGE_ENCRYPTION — info constant: message body encryption key
  INFO_MESSAGE_AUTH       — info constant: message metadata auth key
  INFO_SESSION_KEY        — info constant: session handshake key
  INFO_HEADER_ENCRYPTION  — info constant: header field encryption key
  MAX_DERIVE_LENGTH       — maximum bytes derive_key() can produce (8 160)

HPKE Mode_Auth (DHKEM-X25519 + HKDF-SHA256 + AES-256-GCM):
  generate_keypair      — generate an X25519 static key pair (priv, pub)
  encapsulate           — authenticated hybrid encrypt; returns (ct, enc_key)
  decapsulate           — authenticated hybrid decrypt; raises ValueError on fail
  HPKE_KEY_SIZE         — X25519 key size in bytes (32)
  HPKE_ENCAPSULATED_SIZE — encapsulated (ephemeral public) key size in bytes (32)
"""

from backend.crypto.password import (
    hash_password,
    verify_password,
    needs_rehash,
    DUMMY_HASH,
)
from backend.crypto.aead import (
    encrypt,
    decrypt,
    KEY_SIZE,
    NONCE_SIZE,
    TAG_SIZE,
)
from backend.crypto.kdf import (
    derive_key,
    INFO_MESSAGE_ENCRYPTION,
    INFO_MESSAGE_AUTH,
    INFO_SESSION_KEY,
    INFO_HEADER_ENCRYPTION,
    MAX_DERIVE_LENGTH,
)
from backend.crypto.hpke import (
    generate_keypair,
    encapsulate,
    decapsulate,
    KEY_SIZE   as HPKE_KEY_SIZE,
    ENCAPSULATED_KEY_SIZE as HPKE_ENCAPSULATED_SIZE,
)

__all__ = [
    # password
    "hash_password",
    "verify_password",
    "needs_rehash",
    "DUMMY_HASH",
    # aead
    "encrypt",
    "decrypt",
    "KEY_SIZE",
    "NONCE_SIZE",
    "TAG_SIZE",
    # kdf
    "derive_key",
    "INFO_MESSAGE_ENCRYPTION",
    "INFO_MESSAGE_AUTH",
    "INFO_SESSION_KEY",
    "INFO_HEADER_ENCRYPTION",
    "MAX_DERIVE_LENGTH",
    # hpke
    "generate_keypair",
    "encapsulate",
    "decapsulate",
    "HPKE_KEY_SIZE",
    "HPKE_ENCAPSULATED_SIZE",
]
