"""
backend/crypto — cryptographic helpers for the secure mailbox backend.

Public re-exports
-----------------
Password hashing (Argon2id):
  hash_password     — hash a plaintext password with Argon2id
  verify_password   — constant-time verify against a stored PHC hash
  needs_rehash      — detect whether a stored hash should be upgraded
  DUMMY_HASH        — a valid pre-computed hash for timing-safe "user not
                      found" responses (prevents user-enumeration attacks)

HPKE Mode_Auth (DHKEM-X25519 + HKDF-SHA256 + AES-256-GCM):
  generate_keypair      — generate an X25519 static key pair (priv, pub)
  encapsulate           — authenticated hybrid encrypt; returns (ct, enc_key, nonce)
  decapsulate           — authenticated hybrid decrypt; raises ValueError on fail
  build_file_aad        — canonical associated-data bytes for a file transfer
  HPKE_KEY_SIZE         — X25519 key size in bytes (32)
  HPKE_ENCAPSULATED_SIZE — encapsulated (ephemeral public) key size in bytes (32)

Note: the former kdf.py (generic HKDF wrapper + INFO_* domain-separation
constants) and aead.py (standalone AES-GCM helpers with random nonces) were
reference modules never called from any production path — the live server
path is hpke.py + password.py only — and were removed in the docs-cleanup
chunk to keep the crypto surface equal to what is actually reviewed and
tested (see docs/crypto-design.md §8).  They remain available in git history.
"""

from backend.crypto.password import (
    hash_password,
    verify_password,
    needs_rehash,
    DUMMY_HASH,
)
from backend.crypto.hpke import (
    generate_keypair,
    encapsulate,
    decapsulate,
    build_file_aad,
    KEY_SIZE   as HPKE_KEY_SIZE,
    ENCAPSULATED_KEY_SIZE as HPKE_ENCAPSULATED_SIZE,
)

__all__ = [
    # password
    "hash_password",
    "verify_password",
    "needs_rehash",
    "DUMMY_HASH",
    # hpke
    "generate_keypair",
    "encapsulate",
    "decapsulate",
    "build_file_aad",
    "HPKE_KEY_SIZE",
    "HPKE_ENCAPSULATED_SIZE",
]
