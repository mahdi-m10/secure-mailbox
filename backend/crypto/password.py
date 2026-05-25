"""
backend/crypto/password.py — Argon2id password hashing helpers.

Overview
--------
This module wraps the ``argon2-cffi`` library and exposes a small, focused
API for the two operations that touch passwords in our system:

  hash_password(password)       — called once at registration
  verify_password(password, hash) — called once at every login attempt

It also exports:

  needs_rehash(hash)  — used after a successful login to transparently
                        upgrade weak/old hashes without forcing a password reset

  DUMMY_HASH          — a pre-computed valid hash to use when a username is
                        not found, so "user does not exist" and "wrong password"
                        take the same ~300 ms and cannot be distinguished by
                        response-time measurement (user enumeration defence).

PHC string format
-----------------
argon2-cffi always returns and expects the PHC (Password Hashing Competition)
string format — a single self-contained string that embeds the algorithm,
version, every parameter, the salt, and the digest:

    $argon2id$v=19$m=65536,t=3,p=4$<base64-salt>$<base64-hash>

This ~97-character string is stored verbatim in ``users.hashed_password``.
No separate salt column is needed.

Parameter rationale
-------------------
All three cost parameters are chosen from the OWASP Password Storage Cheat
Sheet (2024) "Type 2" profile and RFC 9106 §4 "Recommended Parameters for
Argon2id":

  memory_cost = 65 536 KiB (64 MB)
    The primary defence against GPU/ASIC offline cracking.  Each guess must
    allocate and fill a 64 MB block before the digest can be computed.  A
    GPU with 8 GB VRAM can run at most ~128 simultaneous guesses; contrast
    with SHA-256 where the same GPU can try ~10 billion per second.

  time_cost = 3  (iterations)
    The number of full passes made over the memory block.  Three passes is
    the OWASP/RFC 9106 minimum when memory_cost = 64 MB.  Increasing this
    to 4–5 is appropriate for low-frequency endpoints (password reset, admin
    login) where slightly longer latency is tolerable.

  parallelism = 4  (lanes)
    The number of independent memory lanes processed in parallel.  This sets
    a hard lower bound on attacker resources: they cannot reduce work by
    running fewer than 4 threads without computing a different hash.  Four
    lanes matches a typical 4-core server CPU.

References
----------
  OWASP Password Storage Cheat Sheet
    https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
  RFC 9106 — Argon2 Memory-Hard Function
    https://www.rfc-editor.org/rfc/rfc9106
  argon2-cffi documentation
    https://argon2-cffi.readthedocs.io/
"""

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

# ---------------------------------------------------------------------------
# Shared PasswordHasher instance
#
# PasswordHasher is stateless (it just holds configuration) and thread-safe,
# so a single module-level instance is the correct pattern — there is no cost
# to sharing it across requests.
# ---------------------------------------------------------------------------
_hasher = PasswordHasher(
    # ------------------------------------------------------------------ #
    # memory_cost — KiB of RAM required per hash attempt                  #
    # ------------------------------------------------------------------ #
    # 65 536 KiB = 64 MB.  This is the dominant cost parameter.           #
    # Argon2id fills a 64 MB block with pseudo-random data derived from   #
    # the password and salt; the block must fit in RAM, so memory cannot  #
    # be traded away for speed.  An attacker with a high-end GPU gets     #
    # ≈128 parallel guesses per 8 GB VRAM — not the billions per second  #
    # they would achieve against a memory-cheap function like SHA-256.    #
    memory_cost=65_536,

    # ------------------------------------------------------------------ #
    # time_cost — number of passes over the memory block                  #
    # ------------------------------------------------------------------ #
    # 3 passes is the OWASP and RFC 9106 minimum for the 64 MB profile.   #
    # Each additional pass multiplies wall-clock time linearly but does   #
    # not increase peak RAM usage.  For endpoints called infrequently     #
    # (password reset, MFA recovery) consider raising this to 4–5.       #
    time_cost=3,

    # ------------------------------------------------------------------ #
    # parallelism — number of independent lanes                           #
    # ------------------------------------------------------------------ #
    # 4 lanes means the algorithm spawns 4 threads internally and fills  #
    # 4 independent 16 MB sub-blocks.  An attacker cannot hash with      #
    # fewer than 4 threads without producing a different digest value,   #
    # so they cannot trade parallelism for cheaper hardware.             #
    parallelism=4,

    # ------------------------------------------------------------------ #
    # hash_len — byte length of the output digest                         #
    # ------------------------------------------------------------------ #
    # 32 bytes = 256 bits, matching AES-256 key strength.  argon2-cffi   #
    # and RFC 9106 both default to 32.  Values above 64 bytes provide no #
    # practical security benefit.                                         #
    hash_len=32,

    # ------------------------------------------------------------------ #
    # salt_len — byte length of the random salt                           #
    # ------------------------------------------------------------------ #
    # 16 bytes = 128 bits.  argon2-cffi generates a fresh cryptographic  #
    # random salt (via os.urandom) for every call to .hash().  The salt  #
    # is embedded in the returned PHC string — no separate salt column   #
    # is needed.  128 bits is the NIST SP 800-132 minimum; 32 bytes is   #
    # fine too but adds no meaningful security here.                      #
    salt_len=16,

    # ------------------------------------------------------------------ #
    # encoding — how the password string is converted to bytes            #
    # ------------------------------------------------------------------ #
    # Passwords are Python str objects containing arbitrary Unicode.      #
    # UTF-8 encodes every code point faithfully without loss, so users   #
    # with non-ASCII passwords (e.g. emoji, accented characters) are     #
    # handled correctly.                                                  #
    encoding="utf-8",
)


# ---------------------------------------------------------------------------
# DUMMY_HASH
#
# A pre-computed Argon2id hash of the string "dummy" using the same
# parameters as _hasher.  Use this when a username does not exist in the
# database:
#
#   user = db.get_by_username(username)
#   stored_hash = user.hashed_password if user else DUMMY_HASH
#   ok = verify_password(submitted_password, stored_hash)
#   if not user or not ok:
#       raise HTTPException(401, "Invalid credentials")
#
# Without the dummy verify, the "user not found" branch returns in < 1 ms
# while the "wrong password" branch takes ~300 ms.  An attacker making
# many requests can measure that difference and enumerate valid usernames.
# Running the dummy hash collapses both timings to ~300 ms.
# ---------------------------------------------------------------------------
DUMMY_HASH: str = _hasher.hash("dummy")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def hash_password(password: str) -> str:
    """Hash *password* with Argon2id and return the self-contained PHC string.

    The PHC string embeds the algorithm identifier, version number, all cost
    parameters, a fresh random salt, and the computed digest.  Store it
    verbatim in the ``users.hashed_password`` column.  Example output::

        $argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG

    A new random 128-bit salt is generated on every call, so hashing the
    same password twice produces two different (but both valid) hashes.

    Parameters
    ----------
    password:
        The plaintext password received from the registration form.  The
        caller is responsible for basic length validation (e.g. 8–128 chars)
        before calling this function.  Empty strings are accepted by
        argon2-cffi but should be rejected at the schema/validation layer.

    Returns
    -------
    str
        A PHC-formatted Argon2id hash string (approximately 97 characters).
        Safe to store directly in the database.
    """
    return _hasher.hash(password)


def verify_password(password: str, hash: str) -> bool:
    """Verify *password* against a stored Argon2id *hash*.

    Re-derives the hash from *password* using the parameters and salt
    embedded in *hash*, then compares the result using a constant-time
    equality check — the comparison always runs to completion regardless of
    how many bytes match, preventing byte-by-byte timing oracle attacks.

    Parameters
    ----------
    password:
        The plaintext password submitted at login.
    hash:
        The PHC string previously returned by :func:`hash_password` and
        loaded from the database.  Pass :data:`DUMMY_HASH` when the user
        does not exist so that the call takes the same time as a real verify
        (see :data:`DUMMY_HASH` docstring for the full pattern).

    Returns
    -------
    bool
        ``True``  — the password matches the stored hash.
        ``False`` — the password is wrong, *or* the hash string is malformed
                    or corrupt.  Callers always receive a plain boolean; this
                    function never raises on a bad password.

    Notes
    -----
    Always call this function even when the username is not found in the
    database (using :data:`DUMMY_HASH`) to prevent user-enumeration via
    response timing.
    """
    try:
        # .verify() runs the full Argon2id derivation and then does a
        # constant-time comparison.  It raises VerifyMismatchError on a wrong
        # password and returns True on a correct one.
        return _hasher.verify(hash, password)
    except VerifyMismatchError:
        # Correct hash format, wrong password — the expected failure path.
        return False
    except (VerificationError, InvalidHashError):
        # Malformed, truncated, or tampered hash string.  Treat as a non-match
        # so callers always get a plain bool rather than an unexpected exception.
        return False


def needs_rehash(hash: str) -> bool:
    """Return ``True`` if *hash* was created with weaker or different parameters.

    Call this *after* a successful :func:`verify_password` during login.  If
    it returns ``True``, re-hash the verified plaintext password with the
    current parameters and overwrite the stored value.  This provides a
    transparent upgrade path whenever cost parameters are increased — users
    never notice, and no mass password-reset is needed.

    Parameters
    ----------
    hash:
        The PHC string loaded from the database.

    Returns
    -------
    bool
        ``True``  — the hash used different parameters (old time_cost,
                    smaller memory_cost, etc.) and should be upgraded.
        ``False`` — the hash already matches current ``_hasher`` parameters;
                    no action is needed.

    Example
    -------
    ::

        ok = verify_password(submitted_password, user.hashed_password)
        if ok and needs_rehash(user.hashed_password):
            user.hashed_password = hash_password(submitted_password)
            db.commit()
    """
    return _hasher.check_needs_rehash(hash)
