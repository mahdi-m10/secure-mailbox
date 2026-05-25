"""
backend/crypto — cryptographic helpers for the secure messenger backend.

Public re-exports
-----------------
  hash_password     — hash a plaintext password with Argon2id
  verify_password   — constant-time verify against a stored PHC hash
  needs_rehash      — detect whether a stored hash should be upgraded
  DUMMY_HASH        — a valid pre-computed hash for timing-safe "user not
                      found" responses (prevents user-enumeration attacks)
"""

from backend.crypto.password import (
    hash_password,
    verify_password,
    needs_rehash,
    DUMMY_HASH,
)

__all__ = [
    "hash_password",
    "verify_password",
    "needs_rehash",
    "DUMMY_HASH",
]
