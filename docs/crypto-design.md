# Cryptographic Design — Secure Messenger

**Version:** 1.0  
**Last updated:** 2026-06-02

---

## 1. Threat Model

This section defines the attacker classes considered during design and states explicitly what each class can and cannot achieve against this system.

### 1a. Passive Network Attacker

The attacker can read all traffic in transit: TLS records, HTTP request/response bodies, and any unencrypted metadata (IP addresses, connection timing, packet sizes).

**Properties that hold:**
- **Message confidentiality.** All message bodies are encrypted with AES-256-GCM before leaving the sender's device. The network attacker sees only ciphertext and the ephemeral X25519 public key (`enc`), neither of which yields plaintext without the recipient's private key.
- **Password confidentiality.** Passwords are never transmitted in plaintext; registration and login send credentials over TLS. Even if TLS were stripped, the server stores only an Argon2id hash and never echoes the password back.
- **Transport integrity.** TLS provides record-level integrity; any modification to a TLS record causes the connection to abort.

**Properties that do not hold:**
- **Traffic analysis.** Message timing, frequency, and approximate size are observable from packet metadata even over TLS.
- **Participant identity.** The IP addresses of sender and recipient are visible to a network-level observer.

---

### 1b. Active Network Attacker

The attacker can intercept, modify, drop, replay, and inject traffic between any two parties.

**Properties that hold:**
- **Message integrity at rest.** Each message carries a 128-bit AES-GCM authentication tag. Any modification to the ciphertext after encryption causes decryption to raise `ValueError` before any plaintext is returned; the recipient rejects the message.
- **Replay resistance.** Replaying an old `(ciphertext, enc)` pair succeeds only if the recipient's private key has not changed. However, a replayed message has the same `(sender_id, message_id)` and the server deduplicates by message ID, so the same payload cannot be inserted twice.
- **Sender authentication.** HPKE Mode\_Auth binds the ciphertext to the sender's static private key. An active attacker who does not hold the sender's private key cannot produce a new ciphertext that the recipient will accept as coming from the claimed sender.

**Properties that do not hold:**
- **Availability.** The attacker can drop or delay messages. The server cannot detect suppression, and the recipient has no way to distinguish "no new messages" from "messages were dropped in transit."
- **First-contact TOFU.** If the attacker intercepts the very first key-registration request and substitutes their own public key, subsequent messages will be encrypted to the attacker's key. This attack requires active infrastructure access at a precise moment and cannot be performed retroactively. See §5 for the full trust model discussion.

---

### 1c. Honest-but-Curious Server

The server faithfully executes the protocol but logs all data it receives and attempts to derive as much information as possible from it.

**Properties that hold:**
- **Message confidentiality.** The server stores only ciphertext. It has no access to any private key and therefore cannot decrypt any message. This is verifiable from the source code: the backend never calls `decapsulate()` or any equivalent.
- **Password confidentiality.** The server stores only PHC-formatted Argon2id hashes. Even with full database access, recovering a password requires a brute-force search against a memory-hard function.
- **Sender authentication after TOFU.** The server cannot forge a message that a recipient will accept as coming from a legitimate sender, because it does not hold any user's static private key.

**Properties that do not hold:**
- **Metadata privacy.** The server sees, and persistently stores, all message metadata: sender identity, recipient identity, timestamps, subject lines, and message size. It knows who is communicating with whom and when.
- **Access control integrity.** The server controls who can download each message via the `message_access` table. A curious server could grant itself access to any ciphertext. It still cannot decrypt it, but it can observe access patterns and forward ciphertext to a third party.

---

### 1d. Fully Compromised Server

The attacker has root access to the server, the database, and the deployed private keys (JWT signing key, deployer wallet).

**Properties that hold:**
- **Past message confidentiality.** User private keys are never sent to the server. Compromising the server yields only ciphertext. Without the users' private keys (held exclusively on their devices), past messages cannot be decrypted.
- **Blockchain audit trail.** The `MessageDigest` smart contract on Sepolia is independent of the server. An attacker who compromises the server cannot alter or delete records already anchored on-chain. Any discrepancy between the SQLite `integrity_hash` and the on-chain record is detectable.

**Properties that do not hold:**
- **Future message confidentiality.** An attacker with full server control can intercept key-registration requests for new users and replace their public keys before they are stored. All subsequent messages sent to those users will be encrypted to the attacker's key.
- **Access control.** The attacker can serve arbitrary ciphertext to any authenticated user or deny service entirely.
- **JWT integrity.** Possession of `SECRET_KEY` allows forging access tokens for any username.

---

## 2. Cryptographic Primitives

### 2a. AES-256-GCM (AEAD)

**Specification:** NIST SP 800-38D — Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM).

AES-256-GCM is an Authenticated Encryption with Associated Data (AEAD) scheme. A single primitive simultaneously provides confidentiality (CTR-mode AES stream cipher), integrity, and authenticity (GHASH polynomial authentication over GF(2¹²⁸)), eliminating the need to compose separate encryption and MAC primitives.

**Why AEAD over Encrypt-then-MAC or MAC-then-Encrypt:**  
Composed schemes require correct instantiation of two primitives and explicit specification of what is authenticated. MAC-then-Encrypt is vulnerable to padding-oracle attacks (the decryptor may release partial plaintext before verifying the MAC). Encrypt-then-MAC is cryptographically sound but requires two separate keys, a defined MAC scope, and constant-time comparison. AEAD provides all three properties in a single, formally specified interface where the authentication tag is computed before any plaintext is released — a decryptor either returns verified plaintext or raises an exception.

**Parameters:**
- Key: 256 bits (32 bytes). Matches the 128-bit security level of other primitives.
- Nonce: 96 bits (12 bytes). The NIST-preferred length; other sizes require an extra GHASH computation to derive the counter block.
- Authentication tag: 128 bits (16 bytes). Maximum GCM tag length, appended to ciphertext by the library.

**Nonce strategy — HPKE path:**  
In the HPKE Mode\_Auth path, the nonce is not generated randomly. It is derived deterministically from the HKDF key schedule:

```
OKM = HKDF-SHA256(ikm=dh1‖dh2, salt=ek_pub, info="secure-messenger", length=44)
aes_key = OKM[0:32]
nonce   = OKM[32:44]
```

Uniqueness is guaranteed by the fresh ephemeral key `ek_priv` generated per message: a different ephemeral key produces a different `dh1`, a different `OKM`, and therefore a different `(aes_key, nonce)` pair for every message, even when the same sender and recipient communicate repeatedly.

**Nonce strategy — standalone aead.py path:**  
When `aead.encrypt()` is called directly (outside HPKE), a 96-bit nonce is drawn from `os.urandom(12)`. The OS CSPRNG provides cryptographic randomness. The birthday-bound collision probability for random 96-bit nonces reaches 2⁻³² (≈ 0.000000023%) only after 2⁴⁸ ≈ 2.8 × 10¹⁴ messages per key — negligible for any per-user or per-message key lifetime.

**Nonce reuse is catastrophic for GCM.** Reusing the same `(key, nonce)` pair produces identical keystreams. XOR-ing two ciphertexts cancels the keystream (`ct1 ⊕ ct2 = pt1 ⊕ pt2`), exposing both plaintexts. Worse, GCM nonce reuse also exposes the GHASH subkey `H = AES(key, 0)`, from which an attacker can forge authentication tags for arbitrary plaintexts. The per-message key derivation and random nonce generation eliminate this risk.

**Associated Data (AAD):**  
The canonical AAD is computed server-side and returned to the client on every download:

```
"v1:sender={sender_id}:recipient={recipient_id}:msg={message_id}"
```

AAD is authenticated but not encrypted; it is fed into the GHASH computation but does not appear in the stored ciphertext. Binding the ciphertext to concrete identifiers prevents context-confusion attacks: a ciphertext encrypted in one conversation cannot be replayed in a different conversation because the recipient reconstructs the AAD from current metadata — any mismatch causes the authentication tag to fail.

**Note:** In the HPKE path, the AAD passed to `AESGCM.encrypt()` is `None`. Context binding is instead provided by the HKDF `info` string ("secure-messenger"), which is mixed into the key derivation itself — a stronger form of binding than AAD because it ties the symmetric key, not merely the authentication tag, to the application context.

---

### 2b. HPKE Mode\_Auth — RFC 9180

**Specification:** RFC 9180 — Hybrid Public Key Encryption.  
**Instantiation:** DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + AES-256-GCM.

HPKE (Hybrid Public Key Encryption) combines an asymmetric key encapsulation mechanism (KEM) with a symmetric AEAD. The KEM establishes a shared secret between sender and recipient; HKDF derives a symmetric key and nonce; AES-256-GCM encrypts the message body. The sender transmits only the 32-byte ephemeral public key (`enc`) alongside the ciphertext — there is no large asymmetric ciphertext component.

**Why Mode\_Auth over Mode\_Base:**  
Mode\_Base is unauthenticated: any party with an X25519 key pair can produce a valid encapsulation to a given recipient. An attacker who intercepts a message in transit can replace it with their own message; the recipient has no mechanism to distinguish a legitimate sender from an impersonator.

Mode\_Auth incorporates the sender's static private key into the shared secret derivation via a second DH operation. The recipient can only decrypt a message if the ciphertext was produced by someone holding the private key corresponding to the stored `sender_pub`. Decryption is an implicit proof of sender identity — no separate signature is required.

**Two DH operations:**

```
dh1 = X25519(ek_priv,     recip_pub)   ← ephemeral × recipient
dh2 = X25519(sender_priv, recip_pub)   ← static sender × recipient (auth)
```

`dh1` alone would produce an unauthenticated scheme (any party with any ephemeral key can compute it). `dh2` is the authentication contribution: only the holder of `sender_priv` can compute `X25519(sender_priv, recip_pub)`. On the recipient side, X25519 commutativity allows recomputation without sender's private key:

```
X25519(ek_priv,     recip_pub) == X25519(recip_priv, ek_pub)     # dh1
X25519(sender_priv, recip_pub) == X25519(recip_priv, sender_pub) # dh2
```

**Key schedule:**

```
ikm     = dh1 ‖ dh2                         (64 bytes of input key material)
OKM     = HKDF-SHA256(ikm, salt=ek_pub, info=b"secure-messenger", length=44)
aes_key = OKM[0:32]                          (256-bit AES key)
nonce   = OKM[32:44]                         (96-bit GCM nonce)
```

The ephemeral public key `ek_pub` serves as the HKDF salt, tying the derived keys to this specific encapsulation. Even if the same `(sender_priv, recip_pub)` pair is reused across messages, a different `ek_priv` on every call produces a different `dh1` and therefore a completely different `(aes_key, nonce)`.

**Forward secrecy:**  
This implementation does **not** provide forward secrecy. The sender's static private key `sender_priv` is reused across all messages. If an attacker records ciphertext now and later obtains `sender_priv` (for example, by compromising the sender's device), they can recompute `dh2`, re-run the key schedule, and decrypt all past messages. Forward secrecy would require a separate ephemeral key for the sender (using a different protocol, such as Signal's Double Ratchet), which is outside the scope of this implementation.

The ephemeral key `ek_priv` is discarded after the DH computation and never stored, which means compromise of the recipient's long-term key alone is not sufficient to decrypt messages without also recovering `ek_priv` from memory at the time of encryption. This is a partial mitigation but not true forward secrecy.

---

### 2c. Argon2id Password Hashing

**Specification:** RFC 9106 — Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work Applications.

**Why Argon2id over alternatives:**

| Algorithm | Weakness |
|-----------|----------|
| PBKDF2 | Parallelisable on GPU/ASIC; no memory requirement. An attacker with GPU hardware can try billions of passwords per second. |
| bcrypt | Fixed 72-byte input truncation; no parallelism control; maximum ~4 KB memory usage, trivially met by hardware. |
| scrypt | Memory-hard but no side-channel resistance in its internal BlockMix; vulnerable to cache-timing attacks. |
| Argon2i | Memory-hard but computable with lower memory via time–memory trade-offs; suited for adversarial environments but not password hashing. |
| **Argon2id** | **Hybrid: first half uses Argon2i (side-channel resistance), second half uses Argon2d (TMTO resistance). RFC 9106 recommends this for password hashing.** |

**Parameters:**

```
memory_cost = 65 536 KiB  (64 MB)
time_cost   = 3            (iterations)
parallelism = 4            (independent lanes)
hash_len    = 32 bytes     (256-bit output, matching AES-256 key strength)
salt_len    = 16 bytes     (128-bit random salt, generated per hash)
```

**Rationale (per RFC 9106 §4 and OWASP Password Storage Cheat Sheet 2024):**

- `memory_cost = 64 MB`: The dominant defence against GPU-based offline cracking. Each Argon2id evaluation must allocate and fully traverse a 64 MB memory block. A GPU with 8 GB VRAM can sustain at most ~128 simultaneous evaluations, compared to ~10⁹ per second for raw SHA-256. Increasing this value is the most effective way to raise cracking cost.
- `time_cost = 3`: RFC 9106 specifies a minimum of 3 iterations at this memory level. Three passes ensure the memory block is written in a data-dependent order, defeating TMTO attacks.
- `parallelism = 4`: Four independent memory lanes. An attacker cannot compute the correct hash using fewer than 4 threads without producing a different value, preventing parallelism reduction as a cost-saving measure.

**Output format:**  
`argon2-cffi` returns the PHC string format, which embeds all parameters, a freshly generated random salt, and the digest in a single self-contained string:

```
$argon2id$v=19$m=65536,t=3,p=4$<base64-salt>$<base64-hash>
```

This is stored verbatim in `users.hashed_password`. No separate salt column is required.

**User enumeration defence:**  
A `DUMMY_HASH` pre-computed from the string `"dummy"` with identical parameters is used when a login request names a non-existent username. The dummy verify call takes the same ~300 ms as a real verification, collapsing the timing difference between "user not found" (< 1 ms without the dummy) and "wrong password" (~300 ms). Without this, an attacker can enumerate valid usernames by measuring response times.

---

### 2d. HKDF-SHA256 Key Derivation

**Specification:** RFC 5869 — HMAC-based Extract-and-Expand Key Derivation Function (HKDF).

HKDF transforms an arbitrary input key material (IKM) — typically a Diffie-Hellman shared secret — into one or more uniform pseudorandom keys suitable for direct use in AES or HMAC operations.

**Why raw DH output cannot be used directly as a key:**  
An X25519 shared secret is a point on Curve25519 (a Montgomery-form elliptic curve). It is not uniformly distributed over all 32-byte strings: only approximately half of all byte strings are valid curve coordinates. AES-256-GCM's security proof requires a uniformly random key. HKDF's Extract phase resolves this:

```
PRK = HMAC-SHA256(salt, IKM)
```

This maps any distribution onto a uniform 256-bit pseudorandom key, removing algebraic structure.

**Two-phase construction:**

```
Extract:  PRK = HMAC-SHA256(salt=ek_pub, IKM=dh1‖dh2)
Expand:   OKM = T(1) ‖ T(2) ‖ ... truncated to length bytes
          where T(i) = HMAC-SHA256(PRK, T(i-1) ‖ info ‖ i)
```

The Expand phase can produce up to 255 × 32 = 8 160 bytes from a single PRK. In the HPKE key schedule, 44 bytes are derived in a single call: the first 32 become the AES-256 key and the remaining 12 become the GCM nonce. Deriving both from the same PRK is safe because they occupy non-overlapping, independent positions in the output stream.

**Domain separation via info strings:**  
The `info` parameter in the Expand phase domain-separates keys derived for different purposes. Even if two derivations use the same `(IKM, salt)`, different `info` values produce outputs that are computationally indistinguishable from independently drawn random keys.

The `kdf.py` module defines named constants for each distinct derivation context:

```
INFO_MESSAGE_ENCRYPTION = "secure-messenger:v1:message-encryption"
INFO_MESSAGE_AUTH       = "secure-messenger:v1:message-auth"
INFO_SESSION_KEY        = "secure-messenger:v1:session-key"
INFO_HEADER_ENCRYPTION  = "secure-messenger:v1:header-encryption"
```

The `hpke.py` module uses the simpler `b"secure-messenger"` info string, which is the HPKE-layer context binding; the structured `INFO_*` constants from `kdf.py` apply when `derive_key()` is called outside the HPKE path. Prefixing all info strings with the application name (`secure-messenger`) and a version number (`v1`) provides cross-application domain separation and a clear upgrade path for future protocol versions.

---

## 3. Protocol Walkthrough

### 3.1 Registration and Key Publication

```
Client (Browser)                        Server
─────────────────────────────────────────────────────────────────
Generate X25519 key pair:
  (priv, pub) = crypto.subtle.generateKey(X25519, extractable=false)
Store priv in IndexedDB (non-extractable)
                                        
POST /register  ──── { username, password, public_key (base64) } ──▶
                                        hash_password(password)  → PHC string
                                        store (username, phc, public_key)
◀── 201 Created ──────────────────────────────────────────────────
```

The private key never leaves the client. The server stores the public key and Argon2id hash only.

### 3.2 Login and Token Issuance

```
Client                                  Server
──────────────────────────────────────────────────────────────────
POST /login  ──── { username, password } ──────────────────────▶
                                        load PHC from DB (or DUMMY_HASH)
                                        Argon2id.verify(password, PHC)  ~300ms
                                        if ok: issue HS256 JWT
◀── 200 { access_token, token_type } ─────────────────────────────
Client stores JWT in memory / sessionStorage
```

### 3.3 Sending a Message (Alice → Bob)

```
Alice (Browser)                         Server
──────────────────────────────────────────────────────────────────
GET /users/bob  ──────────────────────────────────────────────▶
◀── { username: "bob", public_key: "<bob_pub_b64>" } ──────────────

── HPKE Mode_Auth encrypt ──────────────────────────────────────
1. Generate ephemeral key pair:
     ek_priv, ek_pub = crypto.subtle.generateKey(X25519)
2. dh1 = X25519(ek_priv,      bob_pub)   // ephemeral × recipient
   dh2 = X25519(alice_priv,   bob_pub)   // static sender × recipient
3. ikm = dh1 ‖ dh2
   OKM = HKDF-SHA256(ikm, salt=ek_pub, info="secure-messenger", len=44)
   aes_key = OKM[0:32]
   nonce   = OKM[32:44]
4. ct = AES-256-GCM(aes_key, nonce, plaintext)  // no AAD in HPKE path
5. Discard ek_priv
──────────────────────────────────────────────────────────────────

POST /messages/send ──── {
  recipient_username: "bob",
  ciphertext:    base64(ct),
  nonce:         base64(nonce),      ← transmitted; not used for decrypt
  encrypted_key: base64(ek_pub),     ← 32-byte ephemeral X25519 public key
  subject: ...
} ─────────────────────────────────────────────────────────────▶

                                        pack: base64(nonce ‖ ct) → stored blob
                                        integrity = keccak256(stored_blob)
                                        INSERT INTO messages (ciphertext=blob, integrity_hash)
                                        INSERT INTO message_access (recipient_id=bob, encrypted_key=ek_pub)
                                        background: anchor integrity_hash on Sepolia
◀── 201 { id, sender_username, ... } ─────────────────────────────
```

### 3.4 Receiving and Decrypting

```
Bob (Browser)                           Server
──────────────────────────────────────────────────────────────────
GET /messages/inbox ─────────────────────────────────────────▶
◀── [ { id, sender_username: "alice", subject, is_read }, ... ] ──

GET /messages/{id}/download ──────────────────────────────────▶
                                        verify MessageAccess row for bob
                                        unpack blob → (nonce, ciphertext)
                                        mark is_read = true
◀── { ciphertext, nonce, encrypted_key, ... } ────────────────────

── HPKE Mode_Auth decrypt ──────────────────────────────────────
ek_pub = base64decode(encrypted_key)    // 32-byte ephemeral public key
dh1 = X25519(bob_priv, ek_pub)          // recipient × ephemeral
dh2 = X25519(bob_priv, alice_pub)       // recipient × static sender
OKM = HKDF-SHA256(dh1‖dh2, salt=ek_pub, info="secure-messenger", len=44)
aes_key = OKM[0:32]
nonce   = OKM[32:44]                    // re-derived; transmitted nonce ignored
plaintext = AES-256-GCM.decrypt(aes_key, nonce, ciphertext)
──────────────────────────────────────────────────────────────────
```

### 3.5 Forward with Re-encryption

A forward cannot simply pass the existing ciphertext to the new recipient — it was encrypted to Bob's key, not Carol's. The forwarder must re-encrypt:

```
POST /messages/{id}/forward  ──── {
  recipient_username: "carol",
  new_ciphertext:    base64(re-encrypted ct),
  new_nonce:         base64(new_nonce),
  new_encrypted_key: base64(new_ek_pub),   ← new ephemeral key for Carol
} ─────────────────────────────────────────────────────────────▶
                                        INSERT INTO messages (new ciphertext row)
                                        INSERT INTO message_access (recipient_id=carol)
◀── 200 { detail: "Message forwarded to carol." } ────────────────
```

A new `Message` row is created with the re-encrypted payload. The original message row is unchanged.

### 3.6 Revoke Access

```
POST /messages/{id}/revoke  ──── { recipient_username: "carol" } ▶
                                        DELETE FROM message_access
                                        WHERE message_id=? AND recipient_id=carol
◀── 200 { detail: "Access revoked for carol." } ──────────────────
```

The `Message` row and `BlockchainRecord` are preserved — the blockchain audit chain uses a RESTRICT foreign key that prevents hard deletion. Revocation is a server-side access control action; a recipient who already downloaded and decrypted a message retains their local plaintext.

---

## 4. Storage at Rest

### SQLite (Server)

| Table | Column | Contents |
|-------|--------|----------|
| `users` | `hashed_password` | PHC Argon2id string |
| `users` | `public_key` | Base64 X25519 public key (32 bytes) |
| `messages` | `ciphertext` | `base64(nonce ‖ ciphertext_with_tag)` — server never decrypts |
| `messages` | `integrity_hash` | Lowercase hex keccak256 of the stored blob (64 chars) |
| `message_access` | `encrypted_key` | Base64 ephemeral X25519 public key (`enc`, 32 bytes) |
| `blockchain_records` | `block_hash` | SHA-256(`previous_hash ‖ message_hash`) |

The server stores the nonce packed into the ciphertext blob (`nonce ‖ ct`) rather than as a separate column, eliminating any risk of a nonce/ciphertext row mismatch if records are ever reordered.

### Blockchain (Sepolia)

The `MessageDigest` smart contract stores `(hash, timestamp, recorder)` tuples indexed by keccak256 hash. Each hash may be recorded exactly once; the contract reverts on duplicate submissions. This provides an append-only, independently verifiable log of message integrity hashes that exists outside the server's control. The `blockchain-proof` endpoint recomputes the keccak256 of the current stored blob and compares it against the on-chain record.

### Browser — Private Key Storage

Private keys are stored in IndexedDB as non-extractable `CryptoKey` objects. The `extractable: false` flag in the Web Crypto API prevents JavaScript from calling `crypto.subtle.exportKey()` on the private key — the key material lives inside the browser's cryptographic engine and cannot be read by JavaScript, including by XSS payloads. An XSS attacker on the page can use the key to encrypt or decrypt during the active session but cannot exfiltrate the raw bytes for offline use.

An earlier version stored private keys as JWK strings in `localStorage`. A migration path (`migrateLocalStorageKey()`) moves any such keys into IndexedDB as non-extractable `CryptoKey` objects and deletes the `localStorage` entries, regardless of whether migration succeeds.

### C++ Client — Key Handling

The C++ client generates X25519 key pairs using `crypto_box_keypair` (libsodium). Private keys are held in process memory only and are not persisted to disk. The CLI prints the base64-encoded private key at generation time; the user is responsible for storing it externally. Loss of the private key is permanent — there is no server-side backup or recovery mechanism.

---

## 5. Trust Model

### TOFU (Trust On First Use)

Key distribution uses the TOFU model. The first time a user fetches a peer's public key from `/users/{username}`, the key is stored locally (IndexedDB in the browser, in-memory in the C++ client) and treated as trusted for all future messages. Subsequent key fetches compare the received key against the stored value; a mismatch triggers a warning — the "safety number changed" pattern used by Signal and WhatsApp.

### First-Contact Vulnerability

TOFU does not protect the very first key exchange. An active attacker with the ability to intercept and modify HTTP responses at the moment of first contact can substitute their own public key for the legitimate user's key. All subsequent messages from the victim will be encrypted to the attacker's key.

This attack requires:
1. Active network access (not passive eavesdropping).
2. Interception at a precise moment — the specific registration or first-contact request.
3. Sustained interception of all future key updates to avoid detection.

HPKE Mode\_Auth stops a weaker attack: once a key is trusted, an attacker who cannot produce valid ciphertexts under that key (because they do not hold the corresponding private key) cannot inject forged messages. Mode\_Auth provides authentication only after the first trusted key exchange has taken place.

### Mitigation

Out-of-band fingerprint verification eliminates the first-contact vulnerability. Users can compare public key fingerprints via a trusted channel (in person, over a verified phone call). This is the same mechanism as Signal's "verify safety number" feature. Implementation is straightforward — the 32-byte public key can be encoded as a 64-character hex string or a 10-word phrase — and is left as a future enhancement.

---

## 6. Known Limitations

**No forward secrecy.**  
Static X25519 key pairs are reused across all messages. Compromise of a user's private key (by device seizure or malware) allows decryption of all past messages stored on the server. True forward secrecy requires a ratcheting protocol (e.g., Signal's Double Ratchet or TLS 1.3's ephemeral DH), which would require per-session state on the server or client and is outside the scope of this implementation.

**TOFU first-contact attack.**  
As described in §5, an active attacker can compromise confidentiality at the first key exchange. No protection is offered against this attack without out-of-band verification.

**Server message suppression.**  
The server can drop messages silently. Recipients have no way to detect suppression. A transparency log or signed delivery receipt would be required to provide delivery guarantees; neither is implemented.

**AES-NI hardware requirement (C++ client).**  
The C++ client calls `crypto_secretstream_xchacha20poly1305` and related libsodium primitives, which emit a warning if AES-NI hardware acceleration is unavailable (e.g., on virtualised or older hardware). The warning is informational — ChaCha20-Poly1305 runs in constant time in software — but users may encounter it in VM environments.

**JWT in sessionStorage.**  
The browser client stores the JWT access token in `sessionStorage`, which is cleared on tab close but is readable by JavaScript in the same origin. An XSS attack that bypasses Content Security Policy can read and forward the token, allowing impersonation for the duration of the token's validity (`ACCESS_TOKEN_EXPIRE_MINUTES`, default 30 minutes). The non-extractable private key in IndexedDB limits the damage: the attacker can send and receive messages during the session but cannot exfiltrate the private key for offline decryption of stored ciphertext.

---

## References

| Reference | Title |
|-----------|-------|
| RFC 9180 | Hybrid Public Key Encryption |
| RFC 5869 | HMAC-based Extract-and-Expand Key Derivation Function (HKDF) |
| RFC 9106 | Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work Applications |
| NIST SP 800-38D | Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC |
| OWASP Password Storage Cheat Sheet | https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html |
