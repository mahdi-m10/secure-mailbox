# Cryptographic Design Document — Asynchronous Secure Mailbox

| | |
|---|---|
| **Module** | CS4436/CS4455 Cybersecurity — Epic Project (July 2026 repeat) |
| **Component** | Cryptography (Eoin O'Brien) |
| **Version** | 0.1 (draft) |
| **Status** | Describes the implementation as it exists today. Sections 7–9 name gaps honestly and map them to planned remediation steps. |

---

## 1. Scope and system overview

This system is an asynchronous secure mailbox: a sender encrypts a file to a known
recipient's public key, hands the ciphertext to an untrusted store-and-forward
server, and the recipient pulls and decrypts it later. The server stores opaque
ciphertext at rest and is assumed malicious.

Three components share one wire-compatible encryption scheme:

- **Backend** — Python / FastAPI / SQLite (`backend/`). Stores ciphertext, enforces
  authentication and access control, never holds plaintext or private keys.
- **Web client** — HTML/JS using the Web Crypto API (`web-client/`).
- **C++ desktop client** — libsodium + libcurl (`cpp-client/`).

**Terminology note.** The codebase currently uses *message* terminology
(`Message`, `/messages/send`, …) inherited from the previous iteration of the
project; the rename to file terminology (`FileObject`, `/files/upload`, …) is a
separate, purely mechanical refactor. Cryptographically a "file" is a byte string
exactly like a "message"; nothing in this document changes with the rename. This
document uses mailbox terms (*upload*, *download*, *file*) throughout.

**Scheme summary.** End-to-end encryption uses HPKE **Mode_Auth**
(RFC 9180 [1]) assembled from vetted primitives:
DHKEM-style X25519 key agreement (RFC 7748 [2]), HKDF-SHA256 (RFC 5869 [3]),
and AES-256-GCM (NIST SP 800-38D [4]). Server-side password verification uses
Argon2id (RFC 9106 [5]). Section 6 states precisely what is retained,
simplified, and omitted relative to RFC 9180 — this is a from-primitives
implementation, **not** a conformant RFC 9180 stack.

---

## 2. Keys, notation, and where things live

| Symbol | What | Size | Lives where |
|---|---|---|---|
| `(skS, pkS)` | Sender static X25519 key pair | 32 B each | Private: client device only. Public: `users.public_key` on server |
| `(skR, pkR)` | Recipient static X25519 key pair | 32 B each | Same as above |
| `(skE, pkE)` | Ephemeral X25519 key pair, fresh per encryption | 32 B each | `skE` exists only inside one `encrypt` call, then zeroed/discarded; `pkE` is transmitted (the *encapsulated key*, `enc`) |
| `k` | AES-256 content key | 32 B | Derived, never stored or transmitted |
| `n` | AES-GCM nonce | 12 B | Derived (see §5.3); also stored beside ciphertext for API symmetry, but the recipient re-derives it and does not trust the stored copy |
| `ct` | AES-256-GCM ciphertext ‖ 16-B tag | len(pt)+16 | Server DB, base64 |

The server persists, per file: `base64(n ‖ ct)` in a TEXT column, the sender's
user ID, an optional plaintext subject/filename, a keccak256 digest of the stored
blob (blockchain anchor — out of scope here), and one access-control row per
recipient carrying `base64(pkE)` in its `encrypted_key` field.

---

## 3. Threat model

Four attacker classes, per the project brief. ✔ = property holds, ✘ = does not.

| Property | (a) Passive network | (b) Active network | (c) Honest-but-curious server | (d) Compromised server |
|---|---|---|---|---|
| File confidentiality | ✔ | ✔ | ✔ | ✔ |
| File integrity (tamper detection) | ✔ | ✔ | ✔ | ✔ |
| Sender authenticity | ✔ | ✔ | ✔ | **partial — TOFU-pinned pairs ✔, first contact ✘ (see below)** |
| Metadata confidentiality | ✔ (TLS) | ✔ (TLS) | ✘ | ✘ |
| Availability / delivery | ✔ | ✘ | ✔ | ✘ |
| Replay / duplicate detection | ✔ (TLS) | ✔ (TLS) | ✘ | ✘ |
| Forward secrecy | ✘ | ✘ | ✘ | ✘ |

**(a) Passive network attacker** — reads all client↔server traffic.
All traffic is inside TLS, so this attacker learns nothing beyond traffic
analysis. Even with TLS stripped away, they hold only `(n ‖ ct, pkE)`:
confidentiality reduces to the Gap-DH assumption on Curve25519 plus
AES-256-GCM IND-CPA security.

**(b) Active network attacker** — can additionally modify, drop, replay, or
inject traffic. TLS with certificate verification (browsers natively; the C++
client via libcurl with `CURLOPT_SSL_VERIFYPEER/VERIFYHOST` on by default)
blocks interception. Beneath TLS, any bit-flip in `ct`, `n`, or `pkE` changes
the derived key/nonce or the GCM tag check input, so decryption fails closed
(GCM tag mismatch). Injection requires producing a ciphertext that decrypts
under `dh2 = X25519(skS, pkR)` — impossible without `skS` or `skR`.

**(c) Honest-but-curious server** — runs the protocol faithfully but logs
everything. Sees: ciphertext, `pkE`, all public keys, usernames, email
addresses, the social graph (who sends to whom, when, how often), file sizes,
and any plaintext subject/filename field the sender chose to fill in.
Cannot see: file contents, private keys, the content key `k` (deriving it
requires `skE`+`skS` or `skR`, none of which the server ever holds).
Passwords are protected by Argon2id (§5.5); a database breach yields no
reusable credentials, and refresh tokens are stored only as SHA-256 digests
of 256-bit random values.

**(d) Fully compromised server** — attacker controls the database and can send
arbitrary responses.

*Properties that survive:*

- **Confidentiality.** The server never possesses plaintext or key material for
  any file exchanged between users whose keys it did not substitute (see below).
  This is demonstrable at the demo directly from the database: every payload
  column contains only base64 AEAD output.
- **Integrity.** The server cannot modify a stored ciphertext undetectably: any
  change fails the recipient's GCM tag verification, because the tag is bound to
  a key the server cannot derive.
- **Cross-context replay.** A ciphertext cannot be re-targeted: the content key
  binds sender and recipient identities via `dh2` (§5.2), so serving Alice→Bob
  ciphertext to Carol, or attributing it to Dave, fails decryption.

*Properties that do NOT survive (stated explicitly, per the brief):*

1. **Sender authenticity via key substitution — mitigated by TOFU pinning,
   residual first-contact gap.** Mode_Auth authenticates *whoever holds the
   private key matching the public key the recipient uses for `dh2`*; that
   public key comes from the server's directory, so a compromised server can
   register its own key pair under Alice's username. **Both clients now pin
   peer keys on first use** (web: IndexedDB pin store per local account;
   C++: per-account pin file) and compare the server-returned key against the
   pin on *every* subsequent fetch — before encrypting to a recipient and
   before decrypting from a sender. A mismatch hard-blocks the operation and
   shows both SHA-256 fingerprints; proceeding requires an explicit user
   override (which re-pins) — Signal's safety-number model. Consequence:
   once a pair has communicated, the server cannot substitute keys
   undetectably. What TOFU cannot fix: the **first** contact — a server that
   substitutes a key before any pin exists still wins that pair, and a user
   who blindly clicks through the override warning re-opens the hole.
   Out-of-band fingerprint comparison (both clients display fingerprints) or
   the proposed blockchain key registry would close first-contact trust.
   **Status: the on-chain `KeyRegistry` contract now exists** (registration,
   rotation, revocation, public `getKey` lookup — §9), but as of this chunk
   no client consults it before encrypting; TOFU pinning remains the only
   live mitigation until the client-integration sub-chunk lands. See §8.1
   for the registry's own trust-model residual once it is wired in.
2. **Availability & completeness.** The server can drop, withhold, reorder, or
   duplicate files, or lie in listings. Asynchronous store-and-forward cannot
   prevent this; it can at best be made evident (out of scope here; the
   blockchain component may address receipt evidence).
3. **Replay to the same recipient.** The server can re-deliver a stored
   Alice→Bob ciphertext as a "new" file. It decrypts correctly and appears as a
   duplicate. Binding to a per-file identifier via AEAD associated data would
   close this — see §7.
4. **Metadata.** Social graph, timing, sizes, plaintext subjects/filenames.
5. **Forward secrecy — none.** Static–static Mode_Auth with no ratchet: an
   attacker who records ciphertexts and *later* obtains a recipient's long-term
   private key decrypts everything ever sent to that key. Acknowledged
   deliberately: asynchronous single-shot file delivery to possibly-offline
   recipients makes DH-ratchet-style FS a poor fit for the project scope.
6. **Key-compromise impersonation (KCI).** Inherent to Mode_Auth
   (RFC 9180 §9.1.1): an attacker holding Bob's *private* key can compute
   `dh2 = X25519(skR, pkS)` and forge files *to Bob* that verify as "from
   Alice". Compromise of the recipient's own key already loses confidentiality,
   so this adds impersonation-toward-the-victim only; noted for completeness.

---

## 4. Construction walkthrough

### 4.1 Registration and password authentication

```
Client                                     Server
  │  POST /auth/register {username,       │
  │        email, password}  ──────────►  │ validate (Pydantic: len 8–128,
  │                                       │ username charset ^[a-zA-Z0-9_.-]{3,64}$)
  │                                       │ h = Argon2id(password)         §5.5
  │                                       │ store h (PHC string, embeds salt+params)
  │  POST /auth/login {username,password} │
  │  ──────────────────────────────────►  │ fetch user; if absent use DUMMY_HASH
  │                                       │ Argon2id-verify ALWAYS runs (~300 ms;
  │                                       │ no timing oracle for enumeration)
  │  ◄──  {access_token: JWT HS256,       │ JWT: 30 min expiry, "type":"access"
  │        refresh_token: 32B urandom}    │ store SHA-256(refresh_token) only
```

Login is rate-limited (5/minute/IP). A password change re-verifies the old
password and invalidates every active session. Rehash-on-login upgrades stored
hashes transparently if parameters are ever raised.

### 4.2 Key generation and publication

```
Client (once per account/device)          Server
  │ (sk, pk) ← X25519 keygen (CSPRNG)     │
  │   web: crypto.subtle.generateKey,     │
  │        private key non-extractable    │
  │   C++: libsodium crypto_box_keypair   │
  │  POST /users/keys {pk: b64, JWT} ───► │ validate: base64, exactly 32 bytes
  │                                       │ store in users.public_key
  │                                       │
Sender (before upload)                    │
  │  GET /users/{recipient}  ───────────► │ return {id, username, public_key}
  │  ◄── pkR (UNAUTHENTICATED directory   │ (no email/PII on this endpoint)
  │       lookup — trust model in §3(d)1) │
```

The key directory is the server. **Trust model: TOFU-with-pinning**, pin
implemented and enforced in both clients (§3(d)1, §8.1). The on-chain
KeyRegistry (§8.11) is an additional, complementary check on this same
lookup — not yet consulted by any client as of this chunk (§9).

### 4.3 Upload (encrypt) — HPKE Mode_Auth encapsulation

Identical logic in `backend/crypto/hpke.py::encapsulate`,
`web-client/js/crypto.js::encryptMessage`, `cpp-client` `hpke_encapsulate`.

```
Sender (holds skS; fetched pkR)
  1. (skE, pkE) ← fresh X25519 key pair          ─ per-upload, CSPRNG
  2. dh1 ← X25519(skE, pkR)                      ─ ephemeral–static
     dh2 ← X25519(skS, pkR)                      ─ static–static (sender auth)
  3. okm ← HKDF-SHA256(ikm = dh1 ‖ dh2,
                        salt = pkE,
                        info = "secure-messenger",
                        L = 44)
     k ← okm[0..31]   (AES-256 key)
     n ← okm[32..43]  (96-bit GCM nonce)
  4. ct ← AES-256-GCM-Encrypt(k, n, plaintext, aad = ∅)   ─ see §7 re: aad
  5. zero skE, dh1, dh2, okm, k
  6. POST /files/upload { ciphertext: b64(ct), nonce: b64(n),
                          encrypted_key: b64(pkE), recipient }

Server: validates base64 shapes (nonce = 12 B, ct ≥ 16 B), packs and stores
        base64(n ‖ ct); records pkE in the recipient's access row; never
        decrypts anything.
```

### 4.4 Download (decrypt) — decapsulation

```
Recipient (holds skR)
  1. GET /files/{id}/download  → { b64(n ‖ ct), b64(pkE), sender_username, … }
     GET /users/{sender}       → pkS            (see §3(d)1 — unpinned today)
  2. dh1 ← X25519(skR, pkE)        =  sender's dh1   (X25519 commutativity)
     dh2 ← X25519(skR, pkS)        =  sender's dh2
  3. (k, n) ← same HKDF call as §4.3 — the recipient RE-DERIVES the nonce
     and ignores the transmitted copy
  4. pt ← AES-256-GCM-Decrypt(k, n, ct, aad = ∅)
     — fails closed (tag mismatch ⇒ error, zero plaintext released) if the
       ciphertext, pkE, either public key, or the info string differ in any bit
```

A successful decrypt is an implicit proof that the file was produced by the
holder of `skS` *for* the holder of `skR` — this is the Mode_Auth guarantee,
conditional on `pkS` being authentic (§3(d)1).

### 4.5 Storage at rest

**Server.** One TEXT column holds `base64(n ‖ ct)`; the 12-byte nonce prefix is
split out again at download time. Rationale: a single opaque blob cannot suffer
a nonce/ciphertext row mismatch. A keccak256 digest of the blob is stored for
the blockchain integrity anchor (separate subject; not a crypto control against
the server, which computes it). Base64-in-SQLite is a deliberate simplicity
trade-off with real limits — see §8.6.

**Web client keys.** The X25519 private key is stored in IndexedDB **only in
passphrase-wrapped form**: AES-256-GCM ciphertext produced by
`crypto.subtle.wrapKey()` under a key derived from a user-chosen vault
passphrase (required to differ from the login password) with
**PBKDF2-HMAC-SHA256, 600 000 iterations** (OWASP minimum for this
construction), random 16-byte salt, parameters stored in the record for
future upgrades. A copied IndexedDB store is useless without the passphrase.

The non-extractable/wrapping tension is resolved with the
`wrapKey`/`unwrapKey` pair: the key is *generated* extractable, but the
reference is transient — it goes straight into `wrapKey()`, whose
export-and-encrypt happens inside the browser crypto engine (the raw bytes
never appear in JS-visible memory), and is then dropped; only the wrapped
blob is persisted. On unlock, `unwrapKey()` decrypts and imports in one
engine-internal step, producing a **non-extractable** session key
(`deriveBits` only) held in a page-scoped variable — so at rest the key is
passphrase-encrypted AND at runtime XSS can still only use, never export,
it. A wrong passphrase fails the GCM tag: unlock returns null, never a
garbage key. There is no unwrapped storage path and no way to obtain a
usable key without the passphrase; pre-vault records (whose non-extractable
keys *cannot* be re-wrapped — extractability is fixed at creation) are
replaced via an explicit key-upgrade flow, not grandfathered in.

Honest residuals: (1) at the instant of generation the key object is
extractable, so script already executing at that exact moment could export
it — after `wrapKey()` returns, never again; (2) PBKDF2 is not memory-hard,
so offline brute-force of a stolen store is cheaper than against Argon2id
(§8.3 records why Argon2id was not used here). The KDF is distinct from the
server-side login hashing by construction: different algorithm, different
salt, different secret.

KDF choice: PBKDF2 is the only password KDF native to Web Crypto; Argon2id
would require shipping a third-party WASM build into a CSP-locked page with
no build system — worse supply-chain exposure for a marginal gain at this
threat level.

**C++ client keys.** Persisted in a passphrase-encrypted **key vault**
(`~/.securemailbox/<username>/vault.json`, mode 0600). The private key is
wrapped with XSalsa20-Poly1305 (`crypto_secretbox`) under a key derived from
the user's passphrase with **Argon2id** (libsodium `crypto_pwhash`,
ARGON2ID13, opslimit 3, memlimit 256 MiB, random 16-byte salt stored in the
file) — parameters deliberately distinct from the server-side login hashing
(m=64 MiB, t=3, p=4), as the brief requires. The wrap cipher is the one
deliberate departure from AES-256-GCM in this system: libsodium's AES-GCM
needs AES-NI hardware, so a GCM-wrapped vault would be unopenable on CPUs
without it — locking the user out of their own key — whereas
XSalsa20-Poly1305 is a pure-software AEAD that is available unconditionally,
and its 24-byte nonce is safe to draw at random. A wrong passphrase fails
the Poly1305 MAC (the vault cannot yield garbage key bytes). The key is
never printed and never persisted unwrapped; generation and import both
*require* vault creation — there is no in-memory-only key path. In-memory
copies are zeroed with `sodium_memzero` on logout/exit.

**Tokens.** Access JWT + refresh token in browser `localStorage`
(XSS-readable — accepted risk, mitigated by CSP and short JWT expiry);
C++ client holds tokens in memory only.

---

## 5. Primitive justification (parameter level)

### 5.1 KEM: X25519 (DHKEM-style)

- **What:** Diffie–Hellman on Curve25519, RFC 7748 §5; the KEM shape follows
  RFC 9180 §4.1 `AuthEncap`/`AuthDecap` (encapsulated key = ephemeral public key;
  authenticated variant concatenates two DH outputs).
- **Parameters:** 32-byte keys; ~128-bit security level (RFC 7748 §1), matching
  the 256-bit AEAD key it feeds (no weakest-link mismatch).
- **Why this curve:** constant-time ladder implementations by construction, no
  invalid-curve point attacks of the short-Weierstrass kind, identical raw
  32-byte key format across all three libraries used
  (`cryptography` ≙ libsodium `crypto_scalarmult_curve25519` ≙ Web Crypto
  X25519), which is what makes the three clients wire-compatible.
  Contributory-behaviour caveat (all-zero output on low-order points,
  RFC 7748 §6.1) is handled: libsodium returns −1 and the C++ code aborts;
  outputs feed HKDF together with a second DH value either way.

### 5.2 Mode_Auth: why not Mode_Base

Mode_Base (single DH) gives confidentiality only — anyone can encrypt to `pkR`,
so a compromised server could inject files "from Alice". Mode_Auth mixes
`dh2 = X25519(skS, pkR)` into the KDF input (RFC 9180 §5.1.3 rationale): only
the holder of `skS` can derive `k`, so a valid GCM tag is an implicit sender
signature, and the same value binds the ciphertext to the recipient (only
`skR` recomputes `dh2` on the other side). This yields the brief's requirement
that recipients verify origin — with the §3(d)1 caveat about key directory
trust, and the §3(d)6 KCI caveat inherent to the mode.

### 5.3 KDF: HKDF-SHA256, and the nonce strategy

- **What:** RFC 5869 extract-then-expand; extract = HMAC-SHA256(salt, ikm)
  (§2.2), expand to `L` bytes (§2.3, max 255·32 = 8160 B; we use 44).
- **Inputs:** `ikm = dh1 ‖ dh2` (64 B); `salt = pkE`, tying the derivation to
  this specific encapsulation; `info = "secure-messenger"` for application
  domain separation. Output split: `k = okm[0..31]`, `n = okm[32..43]` —
  the two are computationally independent segments of one PRF stream.
- **Why HKDF at all:** raw DH outputs are group elements, not uniform bit
  strings; AES-GCM's proofs assume uniformly random keys. HKDF-extract maps the
  structured secret to a uniform PRK (RFC 5869 §3.1; NIST SP 800-56C rev. 2).
- **Nonce strategy (rubric item: "principled and demonstrably collision-free").**
  The nonce is *derived, not random*, and each derived key `k` encrypts
  **exactly one** payload, because a fresh `skE` is drawn per upload. Nonce
  reuse under the same key — the catastrophic GCM failure mode (keystream
  reuse ⇒ XOR of plaintexts; GHASH subkey recovery ⇒ forgeries, Joux [7]) —
  would require two uploads to derive the same `k`, i.e. an X25519 ephemeral
  collision, probability ≈ 2⁻¹²⁸·birthday terms; negligible. This is *stronger*
  than the 2³² random-IV invocation bound of SP 800-38D §8.3, because the
  key changes every time. The C++ AES path additionally requires AES-NI
  (libsodium exposes AES-256-GCM only where hardware-accelerated, avoiding
  table-based software AES timing channels).
- The 12-byte nonce length is the SP 800-38D §5.2.1.1 recommended 96-bit IV
  (any other length triggers an extra GHASH and has worse bounds).

### 5.4 AEAD: AES-256-GCM

- **What:** NIST SP 800-38D; 256-bit key, 96-bit nonce, **128-bit tag**
  (the full tag length — truncated tags weaken forgery bounds, §5.2.1.2).
  AEAD id 0x0002 in RFC 9180 §7.3 terms.
- **Why AEAD (rubric):** encryption alone is malleable; GCM's GHASH-based tag
  makes any ciphertext modification detectable before one byte of plaintext is
  released, and all three libraries verify in constant time and fail closed.
  Encrypt-and-MAC / MAC-then-Encrypt compositions and non-AEAD modes are
  forbidden by the brief and not used anywhere.
- **Why AES-256-GCM specifically over ChaCha20-Poly1305:** native support in
  *all three* required stacks (Web Crypto has no ChaCha20; libsodium and
  `cryptography` have both) — cross-client interoperability decided it.
  Cost: the C++ client refuses to encrypt on CPUs without AES-NI rather than
  fall back to soft AES.
- **Associated data: currently empty** — see §7, which is the honest,
  load-bearing section on this.

### 5.5 Password hashing: Argon2id

Parameters (in `backend/crypto/password.py`, argon2-cffi):

| Parameter | Value | Justification |
|---|---|---|
| variant | Argon2**id** | Hybrid side-channel/GPU resistance — RFC 9106 §9.4 recommends id for password hashing |
| memory | 65 536 KiB (64 MiB) | RFC 9106 §4 second recommended option; ~128 concurrent guesses max per 8 GB GPU vs billions/s for SHA-2 |
| iterations | t = 3 | RFC 9106 §4 pairing for the 64 MiB profile; ~300 ms/verify on the target host — tolerable at login frequency, expensive at cracking frequency |
| parallelism | p = 4 | Matches the §4 recommendation; sets a floor on attacker thread cost |
| tag length | 32 B | 256-bit preimage space; larger adds nothing |
| salt | 16 B, CSPRNG per hash | ≥128-bit NIST SP 800-132 minimum; embedded in PHC string |

Comfortably above the OWASP Password Storage Cheat Sheet minimum for Argon2id
(19 MiB / t=2 / p=1). Supporting measures: constant-work login via a
precomputed `DUMMY_HASH` for nonexistent users (anti-enumeration), password
length cap of 128 chars (anti-DoS on the 64 MiB hash), transparent
rehash-on-login, generic error strings.

**Contrast — refresh tokens** are hashed with plain SHA-256 before storage.
Correct, not an inconsistency: the input is a 256-bit `os.urandom` value, not a
low-entropy password, so memory-hardness buys nothing; SHA-256 preimage
resistance suffices.

### 5.6 Randomness

All randomness comes from OS CSPRNGs: `os.urandom` (via `cryptography` and
`secrets`), libsodium `randombytes_buf`, and Web Crypto `generateKey` /
`getRandomValues`. No `rand()`, no `Math.random()`, no seeds in code.

### 5.7 Explicitly forbidden items — compliance check

No MD5/SHA-1 in security roles, no DES/3DES/RC4, no ECB, no textbook RSA, no
hand-rolled *primitives* (the from-primitives HPKE composition is addressed in
§6), no hardcoded keys or IVs (JWT `SECRET_KEY` must come from the environment;
startup fails loudly if unset). keccak256 appears only in the blockchain
integrity anchor where the smart contract requires it — not in any
confidentiality/authentication role.

---

## 6. RFC 9180 conformance: retained, simplified, omitted

This is a **from-primitives implementation of the Mode_Auth structure**, not a
conformant RFC 9180 implementation, and it is **not wire-compatible** with
RFC 9180 libraries (pyhpke/hpke-js). All three of *our* clients interoperate
because all three implement the same simplified schedule. The brief permits
composition from vetted primitives with justification; this section is that
justification, per brief item 5(d).

| RFC 9180 element | Ours | Status |
|---|---|---|
| AuthEncap/AuthDecap two-DH structure, `enc` = ephemeral pk (§4.1) | `dh1 ‖ dh2` exactly as specified | **Retained** — this is the element carrying the sender-auth security argument |
| Ciphersuite: DHKEM(X25519, HKDF-SHA256)=0x0020, HKDF-SHA256=0x0001, AES-256-GCM=0x0002 (§7) | Same three algorithms | **Retained** |
| Fail-closed AEAD open, generic errors (§5.2) | Same | **Retained** |
| `LabeledExtract`/`LabeledExpand` with `"HPKE-v1" ‖ suite_id` labels (§4) | Plain HKDF; domain separation via `info="secure-messenger"` only | **Simplified.** RFC labels prevent cross-suite/cross-protocol key reuse; our single fixed suite and app-specific info string achieve app-level separation but not the RFC's cryptographic agility hygiene |
| Key schedule context `mode ‖ psk_id_hash ‖ info_hash`, separate `key`/`base_nonce`/`exporter_secret` expansions (§5.1) | Single 44-byte expand, `salt = enc` | **Simplified.** RFC uses the *shared secret* as extract input keyed by labeled salt; we use `enc` as salt directly. Same extract-then-expand security core, different transcript binding |
| Nonce = `base_nonce XOR seq` for multi-message contexts (§5.2) | Nonce = last 12 bytes of the single expand; one message per context | **Simplified** — sound *because* each context encrypts exactly once (§5.3) |
| Multi-message contexts, `Export()` API | — | **Omitted** — single-shot only, no session traffic |
| PSK modes (mode_psk, mode_auth_psk) | — | **Omitted** — no pre-shared-key relationships exist in the system |

**Consequence stated plainly:** the security of the composition rests on the
two-DH Mode_Auth structure and standard HKDF/GCM properties, and has been
reasoned about by hand (this document) rather than inherited from the RFC's
formal analysis (Alwen et al. [8]) verbatim. The trade was made for
three-stack wire compatibility (Web Crypto has no HPKE and hpke-js/libsodium/
cryptography do not share one) and for demonstrable understanding of every
step, which this module examines orally.

---

## 7. Context binding and the `associated_data` field

**Canonical AAD (current design):**

    smx:v1:sender={sender_username}:recipient={recipient_username}:filename={filename}

UTF-8 bytes; single definition per stack (`backend.crypto.build_file_aad`,
`crypto.js buildFileAad`, C++ `build_file_aad`). The sender builds it from
values it knows at encrypt time and binds it as GCM associated data; the
recipient rebuilds it locally from the download metadata and its own
username. Contents rationale:

- **Usernames, not numeric IDs** — both parties know usernames at
  encrypt/decrypt time; clients never learn their own numeric ID. Usernames
  are immutable and validated `[a-zA-Z0-9_.-]` (no `:`), and filename is the
  final field, so the encoding is unambiguous.
- **Filename included** — this is the concrete gain over key-schedule-only
  binding: the server stores the filename in plaintext, and without AAD it
  could relabel a stored ciphertext undetectably. With it, a swapped
  filename fails the recipient's tag check. (Verified by cross-implementation
  tests: C++↔Python round-trips succeed with matching AAD and fail on a
  relabelled filename, both directions.)
- **File ID deliberately excluded** — it is server-assigned *after* upload,
  so a client cannot bind it at encrypt time. Consequence: a compromised
  server can still re-deliver an identical record as a duplicate (§3(d)3
  stands); AAD closes relabelling, not duplication.

The upload endpoint cross-checks a client-supplied `associated_data` against
the canonical form (400 on mismatch) to catch construction bugs at upload
time. This is a debugging aid, not the security control — the server cannot
verify the AEAD binding (it has no key); the recipient's local tag
verification is the enforcement point, so clients must **rebuild** the AAD
locally rather than trusting the server-returned string.

What the key schedule binds regardless of AAD: sender identity, recipient
identity, and the specific encapsulation (`dh2` binds both static keys;
`salt = pkE` binds the ephemeral) — no cross-pair replay, no re-attribution.

**Status — enforcement is live in both shipped clients.** Every encrypt and
decrypt call site now binds the canonical AAD:

- **Web client**: upload builds it from `(me, recipient, file.name)`;
  download and share rebuild it locally from the response metadata plus the
  client's own username.
- **C++ client**: identical pattern at upload, download, and share
  (re-encrypt) call sites.

Neither client falls back to AAD-less decryption on failure — a retry
without AAD would let a malicious server strip the relabelling protection
(downgrade attack). Deliberate consequence: ciphertexts uploaded by the
pre-AAD message clients are no longer decryptable in the current clients.
Verified end-to-end: relabelling a stored file's filename directly in the
server database causes both clients' downloads to fail the GCM tag check,
and cross-stack tests (C++↔Python↔Web Crypto) accept matching AAD and
reject a relabelled filename in every direction. The crypto-layer
parameters still default to no AAD, so the primitives remain usable for
legacy data in tests — but no shipped call site passes empty AAD.

---

## 8. Known limitations

1. **First-contact key trust** (§3(d)1). TOFU pinning is implemented in both
   clients (pin on first use, hard-block with fingerprints on change,
   explicit override re-pins), so key substitution against established pairs
   is detected. The residual gap is inherent to TOFU: the very first fetch of
   a peer's key is trusted unverified, and a user can click through the
   mismatch warning. **The on-chain `KeyRegistry` contract (blockchain
   scope, contracts + unit tests landed this chunk) is the mitigation this
   section anticipated**: a server-custodial registrar posts each user's key
   on Sepolia at registration, so a substitution is either publicly visible
   as a contradicting on-chain event or requires the server to serve a key
   that disagrees with the chain — detectable by any client that checks.
   Precise scope of the claim, stated so it is not overclaimed: this is a
   **public transparency log**, not a trustless PKI — a registrar that lies
   from a user's very first registration is still undetectable, and until
   the client-integration sub-chunk lands, no client actually performs the
   on-chain check, so TOFU remains the only *live* mitigation today.
   Out-of-band fingerprint comparison remains a complementary defence
   either way.
2. **No forward secrecy / no post-compromise security** (§3(d)5) — accepted
   for scope; would require a ratchet or per-session ephemeral–ephemeral
   exchange, which asynchronous offline delivery complicates.
3. **Private key at rest — closed in both clients** (§4.5). C++: Argon2id →
   XSalsa20-Poly1305 vault. Web: PBKDF2-HMAC-SHA256 (600k) →
   AES-256-GCM `wrapKey`, non-extractable on unlock. Residuals, stated
   precisely: the web KDF is PBKDF2, not memory-hard — GPU brute-force of a
   stolen IndexedDB store is cheaper than against Argon2id (mitigated by a
   mandatory separate passphrase; Argon2id rejected to avoid third-party
   WASM crypto in a CSP-locked page); and the web key is briefly extractable
   at generation time (see §4.5). Both derivations use salts/parameters
   distinct from server-side login hashing, per brief item 3c.
4. **AAD closes relabelling, not duplication** (§7): enforcement is live at
   every call site in both shipped clients. Same-pair *duplication* remains
   possible regardless, since the server-assigned file ID cannot be bound at
   encrypt time. Ciphertexts from the pre-AAD message clients are no longer
   decryptable in the current clients (deliberate — no downgrade fallback).
5. **Metadata exposure** (§3(c)): social graph, timing, sizes, and plaintext
   subject/filename are visible to the server. Filenames could be
   client-side-encrypted later; traffic analysis is out of scope.
6. **Storage scalability — base64 in a SQLite TEXT column.** +33 % size
   inflation; whole blob materialised in RAM on every request (no streaming);
   SQLite is comfortable to a few MB per row, not hundreds. Acceptable for the
   project demo with an enforced upload cap; a production design would stream
   ciphertext to object storage keyed by content hash. Deliberate simplicity
   trade, revisited in the upload-endpoint chunk.
7. **Revocation is access control, not cryptography.** Revoking/deleting stops
   the server serving ciphertext; a recipient who already downloaded keeps
   their plaintext. No DRM claim is made.
8. **Residual JWT validity** after logout/password change: stateless access
   tokens stay cryptographically valid up to 30 min. Standard trade; refresh
   tokens *are* revoked server-side immediately.
9. **Dead code honesty — resolved by removal:** `backend/crypto/kdf.py`
   (generic `derive_key` + `INFO_*` domain-separation constants) and
   `backend/crypto/aead.py` (standalone AES-GCM helpers with random nonces)
   were reference modules **no production path ever called**. The key-wrap
   work (limitation 3) once looked like their natural consumer but landed
   entirely client-side (Web Crypto / libsodium), so they were removed in
   the docs-cleanup chunk — a security review should not have to audit code
   that cannot run. They remain in git history. The live crypto surfaces
   are `hpke.py` + `password.py` (server), `crypto.js` (web), and
   `Crypto.cpp` (C++).
10. **Denial of service:** rate limiting exists on login only; upload
    endpoints need size caps + rate limits (networks/pentest work item, noted
    here for completeness).
11. **`KeyRegistry`/`MessageReceipt` trust boundaries.**
    (a) Registrar-custodial model: the registry's integrity depends on the
    server's registrar wallet key; a compromised server can post arbitrary
    (mis)registrations as easily as it can lie off-chain — the value is
    *making a substitution publicly visible and non-repudiable*, not
    preventing the server from acting maliciously. (b) `MessageReceipt` proves
    the server accepted a specific ciphertext at a specific time; it does
    NOT prove the server will keep serving it — a server can still simply
    withhold a file it never posted a receipt for, which the uploading
    client detects at upload time by the *absence* of a receipt, not
    after the fact. (c) **Backend integration landed** (B2): the server
    registers/rotates a user's key on-chain in the background whenever a
    public key is uploaded (at registration or via `POST /users/keys`),
    and posts a `MessageReceipt` in the background after every accepted
    upload/share. `GET /users/{username}?onchain=1` exposes a live registry
    read (opt-in — see the rationale below); `GET /files/{id}/download` and
    `.../blockchain-proof` expose receipt status. **No client yet performs
    the pre-encrypt registry check or refuses on a revoked key** — that is
    B3 (client integration); see the remediation map.
    (d) **Shared-wallet nonce race, found and fixed during B2 integration
    testing**: `MessageDigest`, `KeyRegistry`, and `MessageReceipt` are all
    signed by the same registrar/deployer wallet, and a single upload fires
    a digest-anchor thread and a receipt thread concurrently — both read
    `get_transaction_count(..., "pending")` before broadcasting, which is
    not atomic, so the second send was rejected ("nonce too low") when
    tested against a live local node. Fixed with a process-wide lock held
    only across the nonce-read→sign→broadcast step (not the slower
    confirmation wait), shared by all three contracts' send paths.
    (e) `?onchain=1` is opt-in on `GET /users/{username}` and not offered on
    the bulk `GET /users` listing at all — a per-user live RPC read for a
    500-row page would mean up to 500 sequential RPC calls per request.
    On-chain lookups here fail open (`onchain: null` + `onchain_error`);
    this is informational display, not the security gate — the client-side
    pre-encrypt check that must fail closed is still B3.
    (f) **Client-side registry reads (B3a, landed)** deliberately bypass the
    mailbox server entirely: each client computes `keccak256(username)`
    itself (Keccak-256 implemented from scratch in both clients — no
    browser or libsodium primitive provides the Ethereum variant, whose
    0x01 padding predates and differs from standardized SHA-3's 0x06;
    both implementations are tested against fixed vectors and against
    values observed live on-chain), builds the `getKey(bytes32)` calldata
    locally (hardcoded 4-byte selector, self-checked in tests against the
    local Keccak), and issues `eth_call` directly against a **public,
    keyless Sepolia RPC endpoint** (publicnode.com). Keyless is a
    deliberate trade: an API-keyed provider URL embedded in page source or
    a distributed binary leaks the key and shares one quota across all
    clients. The cost, stated honestly: public endpoints are rate-limited
    and offer no SLA — a busy or throttled endpoint degrades into the
    RPC-failure path, which the pre-encrypt gate treats as FAIL CLOSED
    (explicit typed override required, mirroring the TOFU-mismatch
    pattern), so degraded RPC service degrades availability, never
    security. Note also the residual: the client trusts the chosen RPC
    node to answer `eth_call` honestly — a malicious RPC endpoint could
    lie about registry state (light-client verification is far out of
    scope); using a well-known public provider distinct from the mailbox
    operator keeps the two trust domains separate, which is the property
    that matters for this threat model.
    (g) **Client gates wired (B3b web, B3c C++, landed).** Both clients now
    run the registry check as a second, independent defence after the TOFU
    pin, at every encrypt and decrypt call site. Identical outcome table in
    both: RPC failure/unconfigured → fail closed (explicit typed override);
    revoked key on **encrypt** → hard block with NO override; revoked on
    **decrypt** → override allowed (the file may predate the revocation and
    old mail must stay readable); not-registered → soft notice (pre-registry
    accounts have no record); server key ≠ on-chain key → override showing
    both fingerprints (recent rotation lag, or substitution). Verified
    end-to-end against a live local node driving the real UI / CLI: a
    revoked recipient is blocked before any encryption occurs, and an
    unreachable RPC aborts unless the user types the override. Receipt
    confirmation after upload is the deliberate opposite posture —
    fail-open, informational polling that never blocks (docs note: it is
    evidence display, not a control).

---

## 9. Remediation map

| Gap | Fix | When |
|---|---|---|
| §8.1 key pinning | **Done — both clients.** TOFU pin store (web: IndexedDB; C++: per-account pin file), hard block + fingerprint display on change, explicit override re-pins. Residual: first-contact trust (inherent to TOFU; blockchain registry would strengthen) | Web + C++ rework chunks (landed) |
| §8.1 / §8.11 first-contact trust | `KeyRegistry.sol` (B1). Backend register/rotate + `?onchain=1` lookup (B2). Client read primitives — from-scratch Keccak-256 + direct `eth_call` (B3a). **Pre-encrypt gate wired into both clients (B3b web, B3c C++, landed)**: independent second defence after TOFU; revoked-encrypt hard-blocks, RPC failure fails closed with typed override; verified end-to-end (revoked recipient blocked before encryption; unreachable RPC aborts). Residual: first-registration trust and the trusted-RPC assumption (§8.11(f)) | B1 → B2 → B3a → B3b/B3c (all landed) |
| §8.11 receipt evidence | `MessageReceipt.sol` deployed + unit-tested (B1). **Backend wired (B2)**: server posts a receipt in the background after every accepted upload/share; `GET /files/{id}/download` and `.../blockchain-proof` surface status (informational, fail-open). Remaining: clients poll after upload and surface confirmation/pending in the UI | B1 (landed) → B2 (landed) → B4 (UI) |
| §8.4 AAD | **Done — enforcement live at every call site in both clients** (canonical username/filename form; file ID excluded — unbindable pre-upload; no AAD-less fallback). Residual: same-pair duplication | Web + C++ rework chunks (landed) |
| §8.3 key-at-rest | **Done — both clients.** C++: Argon2id(passphrase, dedicated salt/params) → XSalsa20-Poly1305 key-wrap vault (secretbox chosen over AES-GCM so the vault opens without AES-NI). Web: PBKDF2-HMAC-SHA256 (600k, dedicated salt) → AES-256-GCM via `wrapKey`/`unwrapKey`; session key non-extractable; legacy keys replaced via upgrade flow. Residual: PBKDF2 not memory-hard (§8.3) | C++ + web key-vault chunks (landed) |
| §8.6 upload cap | Enforced max upload size + documented limit | Files-router chunk |

---

## 10. References

1. RFC 9180 — *Hybrid Public Key Encryption* (Barnes, Bhargavan, Lipp, Wood), §4.1, §5.1–5.2, §7, §9.1.1.
2. RFC 7748 — *Elliptic Curves for Security*, §5, §6.1.
3. RFC 5869 — *HKDF*, §2.2–2.3, §3.1.
4. NIST SP 800-38D — *GCM and GMAC*, §5.2.1.1–5.2.1.2, §8.3.
5. RFC 9106 — *Argon2*, §4, §9.4.
6. W3C Web Cryptography API — `CryptoKey.extractable` semantics.
7. A. Joux — *Authentication Failures in NIST version of GCM* (nonce-reuse forgery attacks).
8. Alwen, Blanchet, Hauck, Kiltz, Lipp, Riepel — *Analysing the HPKE Standard* (EUROCRYPT 2021).
9. OWASP Password Storage Cheat Sheet (Argon2id minimums).
10. NIST SP 800-56C rev. 2 — key-derivation methods (extract-then-expand rationale).
11. NIST SP 800-132 — salt length minimum.
