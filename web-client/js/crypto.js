/**
 * crypto.js — Web Crypto API helpers for SecureMailbox
 *
 * Key scheme: HPKE Mode_Auth (RFC 9180)
 *   KEM  — DHKEM(X25519)      raw 32-byte keys, matches backend users.public_key column
 *   KDF  — HKDF-SHA256
 *   AEAD — AES-256-GCM
 *
 * Key schedule (mirrors hpke.py _derive_key_and_nonce exactly):
 *   dh1     = X25519(ek_priv, recip_pub)           ephemeral × recipient
 *   dh2     = X25519(sender_priv, recip_pub)        static sender × recipient (auth)
 *   ikm     = dh1 ‖ dh2                             64 bytes
 *   OKM     = HKDF-SHA256(ikm, salt=ek_pub, info=b"secure-messenger", length=44)
 *   aes_key = OKM[0:32]
 *   nonce   = OKM[32:44]
 *
 * encryptedKey wire format: 32 raw bytes — the ephemeral X25519 public key.
 * (Same as Python encapsulate() `enc`; interoperable with C++ client.)
 *
 * Key storage: IndexedDB holds the private key ONLY in passphrase-wrapped
 * form — AES-256-GCM ciphertext produced by crypto.subtle.wrapKey() under a
 * key derived from a user passphrase with PBKDF2-HMAC-SHA256 (600k
 * iterations, random per-key salt).  A copied IndexedDB store is useless
 * without the passphrase.
 *
 * Lifecycle (the non-extractable/wrapping resolution):
 *   - generateKeyPair() creates the key EXTRACTABLE, but the reference is
 *     transient: it is handed straight to wrapKey() — the export+encrypt
 *     happens inside the browser crypto engine, the raw bytes never appear
 *     in JS-visible memory — and then dropped.  Only the wrapped blob is
 *     persisted.
 *   - unlockKeyPair() uses unwrapKey() to decrypt-and-import in one
 *     engine-internal step, producing a NON-extractable session CryptoKey:
 *     XSS can use it for the session but can never read or export the bytes.
 *   - There is no unwrapped storage path and no way to obtain a usable key
 *     without the passphrase.
 *
 * Residual (documented in docs/crypto-design.md §4.5): during the moment of
 * generation the key object is extractable, so script already running at
 * that exact time could export it; after wrapKey() returns, never again.
 * CSP and input sanitisation remain the primary XSS defences.
 *
 * Browser requirements: Chrome 113+, Edge 113+, Safari 17+, Firefox 130+
 * (X25519 in Web Crypto API — https://caniuse.com/mdn-api_subtlecrypto_generatekey_x25519)
 */

const X25519    = { name: 'X25519' };
const AES_GCM   = { name: 'AES-GCM', length: 256 };
const HPKE_INFO = new TextEncoder().encode('secure-messenger');
const EK_LEN    = 32; // X25519 raw public key length in bytes

// ---- Base-64 utilities -------------------------------------------------------

export function b64ToBuffer(b64) {
  const bin = atob(b64);
  const buf = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
  return buf.buffer;
}

export function bufToB64(buf) {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

// ---- Key generation & import ------------------------------------------------

/**
 * Generate an X25519 key pair.
 *
 * The private key is created EXTRACTABLE — deliberately, and only so it can
 * be handed to crypto.subtle.wrapKey() by saveWrappedKeyPair().  Callers
 * MUST pass it straight to saveWrappedKeyPair() and drop the reference; it
 * must never be persisted or held beyond that call.  The unlocked session
 * key later produced by unlockKeyPair() is non-extractable.
 *
 *   publicKeyB64 = 32 raw bytes as base64 → upload to users.public_key
 *   privateKey   = extractable CryptoKey → wrap immediately, then discard
 */
export async function generateKeyPair() {
  const kp  = await crypto.subtle.generateKey(X25519, true, ['deriveBits']);
  const raw = await crypto.subtle.exportKey('raw', kp.publicKey);
  return {
    publicKey:    kp.publicKey,
    privateKey:   kp.privateKey,
    publicKeyB64: bufToB64(raw),
  };
}

/** Import a base64-encoded raw X25519 public key (32 bytes). */
export function importPublicKey(b64) {
  return crypto.subtle.importKey('raw', b64ToBuffer(b64), X25519, true, []);
}

// ---- IndexedDB key storage --------------------------------------------------

const _DB_NAME    = 'securemsg';
const _DB_VERSION = 2;          // v2 adds the 'pins' store (TOFU)
const _STORE      = 'keyring';
const _PIN_STORE  = 'pins';

function _openDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(_DB_NAME, _DB_VERSION);
    req.onupgradeneeded = ({ target: { result: db } }) => {
      // Guarded creates so both fresh installs (no stores) and v1→v2
      // upgrades (keyring exists, pins doesn't) work.
      if (!db.objectStoreNames.contains(_STORE))     db.createObjectStore(_STORE);
      if (!db.objectStoreNames.contains(_PIN_STORE)) db.createObjectStore(_PIN_STORE);
    };
    req.onsuccess = ({ target: { result } }) => resolve(result);
    req.onerror   = () => reject(req.error);
  });
}

// ---- Passphrase-wrapped key vault ---------------------------------------------
//
// The private key is stored ONLY wrapped: AES-256-GCM over the JWK export,
// under a key derived from the user's vault passphrase (which must not be
// their login password).
//
// KDF: PBKDF2-HMAC-SHA256, 600,000 iterations (OWASP minimum for this
// construction), random 16-byte salt per key, parameters stored in the
// record so they can be raised later without breaking existing vaults.
// PBKDF2 rather than Argon2id because it is the only password KDF native to
// Web Crypto: pulling in a WASM Argon2 build would add third-party crypto
// to a CSP-locked page for a marginal gain here. Distinctness from the
// server-side login hashing (Argon2id m=64 MiB/t=3/p=4) holds by
// construction: different algorithm, different salt, different secret.
// The honest cost — PBKDF2 is not memory-hard — is recorded in
// docs/crypto-design.md §8.

const PBKDF2_ITERATIONS = 600_000;
const _KDF_LABEL        = 'PBKDF2-HMAC-SHA256';

/**
 * Derive the AES-256-GCM wrapping key from a passphrase.
 * The derived key is non-extractable and can ONLY wrap/unwrap — it cannot
 * be used to encrypt arbitrary data, so a bug elsewhere cannot repurpose it.
 */
export async function deriveWrappingKey(passphrase, salt, iterations = PBKDF2_ITERATIONS) {
  const base = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(passphrase), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations },
    base,
    AES_GCM,
    false,
    ['wrapKey', 'unwrapKey']
  );
}

/**
 * Wrap `privateKey` (the transient extractable CryptoKey from
 * generateKeyPair()) under `passphrase` and persist the wrapped record.
 *
 * wrapKey() performs export+encrypt inside the browser crypto engine — the
 * private key bytes never enter JS-visible memory here.  After this call
 * returns, the caller must drop its extractable reference; the only stored
 * form is the ciphertext.
 */
export async function saveWrappedKeyPair(username, publicKeyB64, privateKey, passphrase) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv   = crypto.getRandomValues(new Uint8Array(12));

  const wrappingKey = await deriveWrappingKey(passphrase, salt);
  const wrapped     = await crypto.subtle.wrapKey(
    'jwk', privateKey, wrappingKey, { name: 'AES-GCM', iv });

  const record = {
    v: 2,                          // 2 = wrapped format (1 = legacy raw CryptoKey)
    publicKeyB64,
    wrapped,                       // ArrayBuffer: AES-GCM(JWK) + tag
    salt, iv,
    kdf: _KDF_LABEL,
    iterations: PBKDF2_ITERATIONS,
  };

  const db = await _openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(_STORE, 'readwrite');
    tx.objectStore(_STORE).put(record, username);
    tx.oncomplete = () => resolve();
    tx.onerror    = () => reject(tx.error);
  });
}

async function _getKeyRecord(username) {
  const db = await _openDB();
  return new Promise((resolve, reject) => {
    const req = db.transaction(_STORE, 'readonly').objectStore(_STORE).get(username);
    req.onsuccess = () => resolve(req.result ?? null);
    req.onerror   = () => reject(req.error);
  });
}

/**
 * What kind of key record exists for username?
 *   'wrapped' — passphrase-wrapped vault record (current format)
 *   'legacy'  — pre-vault record holding a raw non-extractable CryptoKey.
 *               It cannot be wrapped retroactively (non-extractability is
 *               one-way) and must be REPLACED via the key-upgrade flow.
 *   'none'    — no record.
 */
export async function keyPairStatus(username) {
  const rec = await _getKeyRecord(username);
  if (!rec) return 'none';
  return rec.v === 2 && rec.wrapped ? 'wrapped' : 'legacy';
}

/**
 * Unlock the vault: derive the wrapping key from `passphrase` using the
 * record's stored salt/iterations and unwrap the private key.
 *
 * unwrapKey() decrypts and imports in one engine-internal step; the
 * resulting session key is NON-extractable (['deriveBits'] only).  A wrong
 * passphrase fails the AES-GCM tag → returns null (never a garbage key).
 *
 * @returns {{privateKey: CryptoKey, publicKeyB64: string} | null}
 */
export async function unlockKeyPair(username, passphrase) {
  const rec = await _getKeyRecord(username);
  if (!rec || rec.v !== 2 || !rec.wrapped) {
    throw new Error('No wrapped key vault for this account on this device.');
  }
  try {
    const wrappingKey = await deriveWrappingKey(passphrase, rec.salt, rec.iterations);
    const privateKey  = await crypto.subtle.unwrapKey(
      'jwk', rec.wrapped, wrappingKey,
      { name: 'AES-GCM', iv: rec.iv },
      X25519,
      false,              // session key is non-extractable
      ['deriveBits']
    );
    return { privateKey, publicKeyB64: rec.publicKeyB64 };
  } catch {
    return null;          // GCM tag failure — wrong passphrase (or corrupt record)
  }
}

/** Remove the key record (legacy-upgrade flow only — the caller must have
 *  informed the user that files encrypted to the old key become unreadable). */
export async function deleteKeyPair(username) {
  const db = await _openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(_STORE, 'readwrite');
    tx.objectStore(_STORE).delete(username);
    tx.oncomplete = () => resolve();
    tx.onerror    = () => reject(tx.error);
  });
}

/**
 * One-time migration: move a legacy JWK private key from localStorage into
 * the passphrase-wrapped vault.  Unlike the legacy-IndexedDB case, the JWK
 * IS extractable, so the SAME key can be wrapped — files encrypted to it
 * stay readable.
 *
 * Always removes the localStorage entries on exit, whether migration
 * succeeded or not, so key material never lingers in localStorage.
 *
 * Returns true if the key was migrated into the vault.
 */
export async function migrateLocalStorageKey(username, passphrase) {
  const raw = localStorage.getItem(`sm_privkey_${username}`);
  if (!raw) return false;

  try {
    const jwk = JSON.parse(raw);
    if (jwk?.crv !== 'X25519') throw new Error('not X25519');

    // Import extractable only long enough to wrap; the reference is dropped
    // on return and only the wrapped form is stored.
    const privateKey   = await crypto.subtle.importKey('jwk', jwk, X25519, true, ['deriveBits']);
    const publicKeyB64 = localStorage.getItem(`sm_pubkey_${username}`) ?? '';
    await saveWrappedKeyPair(username, publicKeyB64, privateKey, passphrase);
    return true;
  } catch {
    return false; // invalid JWK or wrong curve — caller will generate a new key
  } finally {
    localStorage.removeItem(`sm_privkey_${username}`);
    localStorage.removeItem(`sm_pubkey_${username}`);
  }
}

// ---- TOFU key pinning ---------------------------------------------------------
//
// Trust On First Use: the first public key seen for a peer is stored (pinned)
// per local account. Every later fetch is compared against the pin; a
// mismatch means either the peer rotated their key legitimately OR the
// server is substituting keys (the §3(d)1 attack in docs/crypto-design.md).
// The UI must hard-block on mismatch and only proceed after an explicit,
// informed user override — which re-pins the new key (Signal's
// "safety number changed" model).
//
// Pins live in IndexedDB keyed by `${myUsername}|${peerUsername}` so two
// accounts used from the same browser keep independent trust stores.

/**
 * Compare a freshly fetched key against the local pin for (me, peer).
 * First sighting pins automatically and returns {status:'first-use'}.
 *
 * @returns {{status:'first-use'|'match'|'mismatch',
 *            pinnedKeyB64?: string, pinnedSince?: string}}
 */
export async function checkTofuPin(myUsername, peerUsername, fetchedKeyB64) {
  const db  = await _openDB();
  const key = `${myUsername}|${peerUsername}`;

  const existing = await new Promise((resolve, reject) => {
    const req = db.transaction(_PIN_STORE, 'readonly').objectStore(_PIN_STORE).get(key);
    req.onsuccess = () => resolve(req.result ?? null);
    req.onerror   = () => reject(req.error);
  });

  if (!existing) {
    await new Promise((resolve, reject) => {
      const tx = db.transaction(_PIN_STORE, 'readwrite');
      tx.objectStore(_PIN_STORE).put(
        { publicKeyB64: fetchedKeyB64, firstSeen: new Date().toISOString() }, key);
      tx.oncomplete = () => resolve();
      tx.onerror    = () => reject(tx.error);
    });
    return { status: 'first-use' };
  }

  if (existing.publicKeyB64 === fetchedKeyB64) return { status: 'match' };

  return {
    status: 'mismatch',
    pinnedKeyB64: existing.publicKeyB64,
    pinnedSince:  existing.firstSeen,
  };
}

/**
 * Replace the pin for (me, peer) — call ONLY after the user explicitly
 * confirmed they trust the new key in the mismatch warning dialog.
 */
export async function overridePin(myUsername, peerUsername, newKeyB64) {
  const db = await _openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(_PIN_STORE, 'readwrite');
    tx.objectStore(_PIN_STORE).put(
      { publicKeyB64: newKeyB64, firstSeen: new Date().toISOString() },
      `${myUsername}|${peerUsername}`);
    tx.oncomplete = () => resolve();
    tx.onerror    = () => reject(tx.error);
  });
}

/**
 * Human-comparable fingerprint of a public key: SHA-256 of the raw key
 * bytes, hex, spaced in groups of 8 (like Signal safety numbers, users
 * compare these out-of-band).
 */
export async function keyFingerprint(keyB64) {
  const digest = await crypto.subtle.digest('SHA-256', b64ToBuffer(keyB64));
  const hex = Array.from(new Uint8Array(digest))
    .map(b => b.toString(16).padStart(2, '0')).join('');
  return hex.match(/.{8}/g).join(' ');
}

// ---- Canonical file-context AAD ----------------------------------------------

/**
 * Build the canonical associated-data bytes for a file transfer.
 * Must byte-match backend.crypto.build_file_aad and the C++ build_file_aad:
 *
 *   smx:v1:sender={sender}:recipient={recipient}:filename={filename}
 *
 * Binding this into the AEAD means the server cannot relabel a stored
 * ciphertext (e.g. swap the filename) without decryption failing.
 * Usernames cannot contain ':' (validated server-side as [a-zA-Z0-9_.-]),
 * and filename is the last field, so the encoding is unambiguous.
 * A null/undefined filename canonicalises to the empty string.
 *
 * @returns {Uint8Array} UTF-8 bytes to pass as the aad parameter.
 */
export function buildFileAad(senderUsername, recipientUsername, filename) {
  return new TextEncoder().encode(
    `smx:v1:sender=${senderUsername}:recipient=${recipientUsername}:filename=${filename ?? ''}`
  );
}

// ---- HPKE Mode_Auth key schedule --------------------------------------------

/**
 * Derive (aesKey: CryptoKey, nonce: Uint8Array<12>) from two DH outputs.
 *
 * Mirrors hpke.py _derive_key_and_nonce():
 *   HKDF-SHA256(ikm=dh1‖dh2, salt=ek_pub_raw, info="secure-messenger", length=44)
 */
async function _hpkeKeySchedule(dh1, dh2, ekPubRaw) {
  const ikm = new Uint8Array(64);
  ikm.set(new Uint8Array(dh1), 0);
  ikm.set(new Uint8Array(dh2), 32);

  const hkdfKey = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  const okm = await crypto.subtle.deriveBits(
    {
      name: 'HKDF', hash: 'SHA-256',
      salt: ekPubRaw,
      info: HPKE_INFO,
    },
    hkdfKey,
    44 * 8  // 352 bits → 44 bytes
  );

  const okm8   = new Uint8Array(okm);
  const aesKey = await crypto.subtle.importKey('raw', okm8.slice(0, 32), AES_GCM, false, ['encrypt', 'decrypt']);
  const nonce  = okm8.slice(32, 44);
  return { aesKey, nonce };
}

// ---- Public: encrypt / decrypt ----------------------------------------------

/**
 * Encrypt raw bytes (a file) using HPKE Mode_Auth.
 * Produces output compatible with Python encapsulate() and the C++ client.
 *
 * @param {Uint8Array|ArrayBuffer} plaintextBytes  File bytes to encrypt.
 * @param {string}    recipientPublicKeyB64 Recipient's 32-byte X25519 public key (base64).
 * @param {CryptoKey} senderPrivateKey      Sender's non-extractable X25519 private key
 *                                          (from unlockKeyPair()).
 * @param {Uint8Array|null} aad             Optional associated data authenticated by the
 *                                          AEAD (use buildFileAad()). The recipient must
 *                                          supply the identical bytes or decryption fails.
 * @returns {{ ciphertext: string, nonce: string, encryptedKey: string }}
 *   All base64. encryptedKey = 32-byte ephemeral X25519 public key.
 */
export async function encryptFile(plaintextBytes, recipientPublicKeyB64, senderPrivateKey, aad = null) {
  const recipPub = await importPublicKey(recipientPublicKeyB64);

  // Fresh ephemeral key pair — private half used once then discarded
  const eph      = await crypto.subtle.generateKey(X25519, true, ['deriveBits']);
  const ekPubRaw = new Uint8Array(await crypto.subtle.exportKey('raw', eph.publicKey));

  const dh1 = await crypto.subtle.deriveBits({ name: 'X25519', public: recipPub }, eph.privateKey,    256);
  const dh2 = await crypto.subtle.deriveBits({ name: 'X25519', public: recipPub }, senderPrivateKey, 256);

  const { aesKey, nonce } = await _hpkeKeySchedule(dh1, dh2, ekPubRaw);

  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce, ...(aad ? { additionalData: aad } : {}) },
    aesKey,
    plaintextBytes instanceof Uint8Array ? plaintextBytes : new Uint8Array(plaintextBytes)
  );

  return {
    ciphertext:   bufToB64(ct),
    nonce:        bufToB64(nonce),
    encryptedKey: bufToB64(ekPubRaw),
  };
}

/** String convenience wrapper around encryptFile() (UTF-8 encodes first). */
export async function encryptMessage(plaintext, recipientPublicKeyB64, senderPrivateKey, aad = null) {
  return encryptFile(new TextEncoder().encode(plaintext),
                     recipientPublicKeyB64, senderPrivateKey, aad);
}

/**
 * Decrypt file bytes using HPKE Mode_Auth.
 * Matches Python decapsulate(recip_priv, sender_pub, ciphertext, enc, info, aad).
 *
 * @param {string}    ciphertextB64      AES-256-GCM ciphertext_with_tag only
 *                                       (slice base64decode(storedBlob)[12:]).
 * @param {string}    encryptedKeyB64    32-byte ephemeral X25519 public key (base64).
 * @param {CryptoKey} recipientPrivKey   Recipient's non-extractable X25519 private key.
 * @param {string}    senderPublicKeyB64 Sender's 32-byte X25519 public key (base64).
 * @param {Uint8Array|null} aad          Must be identical to the aad passed at encrypt
 *                                       time (null if none). Rebuild it locally with
 *                                       buildFileAad() — do not trust a server-supplied
 *                                       string verbatim; the tag check is the verifier.
 * @returns {Uint8Array} Decrypted file bytes, verified authentic.
 */
export async function decryptFile(
  ciphertextB64, encryptedKeyB64, recipientPrivKey, senderPublicKeyB64, aad = null
) {
  const ekPubRaw = new Uint8Array(b64ToBuffer(encryptedKeyB64));
  if (ekPubRaw.length !== EK_LEN) {
    throw new Error(`Encapsulated key must be ${EK_LEN} bytes; got ${ekPubRaw.length}.`);
  }

  const ekPub     = await crypto.subtle.importKey('raw', ekPubRaw.buffer, X25519, false, []);
  const senderPub = await importPublicKey(senderPublicKeyB64);

  // X25519 commutativity: recipient recomputes the same DH values as the sender
  const dh1 = await crypto.subtle.deriveBits({ name: 'X25519', public: ekPub },     recipientPrivKey, 256);
  const dh2 = await crypto.subtle.deriveBits({ name: 'X25519', public: senderPub }, recipientPrivKey, 256);

  const { aesKey, nonce } = await _hpkeKeySchedule(dh1, dh2, ekPubRaw);

  const plain = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: nonce, ...(aad ? { additionalData: aad } : {}) },
    aesKey,
    b64ToBuffer(ciphertextB64)
  );
  return new Uint8Array(plain);
}

/**
 * String convenience wrapper around decryptFile() (UTF-8 decodes the result).
 * The legacy _nonceB64 parameter is unused — the nonce is re-derived from the
 * HPKE key schedule; kept for signature stability.
 */
export async function decryptMessage(
  ciphertextB64, _nonceB64, encryptedKeyB64, recipientPrivKey, senderPublicKeyB64, aad = null
) {
  const bytes = await decryptFile(
    ciphertextB64, encryptedKeyB64, recipientPrivKey, senderPublicKeyB64, aad);
  return new TextDecoder().decode(bytes);
}

// ---- Hashing ----------------------------------------------------------------

/** SHA-256 of a UTF-8 string, returned as lowercase hex. */
export async function sha256Hex(str) {
  const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  return Array.from(new Uint8Array(hash))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}
