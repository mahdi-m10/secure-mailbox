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
 * Key storage: IndexedDB, private key stored as a non-extractable CryptoKey.
 * The key material lives inside the browser's crypto engine — JavaScript can
 * pass the CryptoKey to crypto.subtle but can never read or export the raw bytes.
 * An XSS attacker on the page can use the key during the session but cannot
 * exfiltrate it for offline use.  CSP and input sanitisation remain the
 * primary XSS defences; this is a defence-in-depth measure.
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
 * Generate an X25519 key pair with a non-extractable private key.
 *
 * Per W3C WebCrypto spec §26.4, the extractable parameter applies only to
 * the private key for asymmetric algorithms; the public key is always
 * extractable regardless.
 *
 *   publicKeyB64 = 32 raw bytes as base64 → upload to users.public_key
 *   privateKey   = non-extractable CryptoKey → persist via saveKeyPair()
 */
export async function generateKeyPair() {
  const kp  = await crypto.subtle.generateKey(X25519, false, ['deriveBits']);
  const raw = await crypto.subtle.exportKey('raw', kp.publicKey);
  return {
    publicKey:    kp.publicKey,
    privateKey:   kp.privateKey,  // non-extractable — bytes inaccessible to JS
    publicKeyB64: bufToB64(raw),
    // privateKeyJwk intentionally absent
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

/**
 * Persist a key pair to IndexedDB under the given username.
 * privateKey should be a non-extractable CryptoKey from generateKeyPair()
 * or from the migrateLocalStorageKey() path.
 */
export async function saveKeyPair(username, publicKeyB64, privateKey) {
  const db = await _openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(_STORE, 'readwrite');
    tx.objectStore(_STORE).put({ publicKeyB64, privateKey }, username);
    tx.oncomplete = () => resolve();
    tx.onerror    = () => reject(tx.error);
  });
}

/**
 * Retrieve the private key for username from IndexedDB.
 * Returns the non-extractable CryptoKey, or null if no key is stored.
 */
export async function loadPrivateKey(username) {
  const db = await _openDB();
  return new Promise((resolve, reject) => {
    const tx  = db.transaction(_STORE, 'readonly');
    const req = tx.objectStore(_STORE).get(username);
    req.onsuccess = () => resolve(req.result?.privateKey ?? null);
    req.onerror   = () => reject(req.error);
  });
}

/**
 * Return true if IndexedDB holds a key pair for username.
 */
export async function hasKeyPair(username) {
  const db = await _openDB();
  return new Promise((resolve, reject) => {
    const tx  = db.transaction(_STORE, 'readonly');
    const req = tx.objectStore(_STORE).getKey(username);
    req.onsuccess = () => resolve(req.result !== undefined);
    req.onerror   = () => reject(req.error);
  });
}

/**
 * One-time migration: move a legacy JWK private key from localStorage into
 * IndexedDB as a non-extractable CryptoKey.
 *
 * Covers two previous storage formats:
 *   - X25519 JWK written by the IndexedDB-less build  (crv === 'X25519')
 *   - P-256 JWK written by the original P-256 build   (crv === 'P-256', skipped)
 *
 * Always removes the localStorage entries on exit, whether migration succeeded
 * or not, to avoid leaving key material in localStorage.
 *
 * Returns true if the key was successfully migrated.
 */
export async function migrateLocalStorageKey(username) {
  const raw = localStorage.getItem(`sm_privkey_${username}`);
  if (!raw) return false;

  try {
    const jwk = JSON.parse(raw);
    if (jwk?.crv !== 'X25519') throw new Error('not X25519');

    // Re-import as non-extractable so the migrated key has the same security
    // properties as one generated fresh by generateKeyPair().
    const privateKey   = await crypto.subtle.importKey('jwk', jwk, X25519, false, ['deriveBits']);
    const publicKeyB64 = localStorage.getItem(`sm_pubkey_${username}`) ?? '';
    await saveKeyPair(username, publicKeyB64, privateKey);
    return true;
  } catch {
    return false; // invalid JWK or wrong curve — caller will generate a new key
  } finally {
    // Erase regardless of outcome — localStorage is no longer the canonical store
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
 *                                          (from loadPrivateKey()).
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
