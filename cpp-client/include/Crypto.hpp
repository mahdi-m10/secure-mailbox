#pragma once
#include <cstddef>
#include <optional>
#include <string>
#include <vector>

// crypto — HPKE Mode_Auth (RFC 9180) file encryption, matching
// backend/crypto/hpke.py and web-client/js/crypto.js byte-for-byte.
//
//   Key generation
//       crypto_box_keypair() → 32-byte Curve25519/X25519 (Montgomery form).
//       Wire-compatible with Python's X25519PrivateKey / X25519PublicKey.
//
//   Encapsulation (hpke_encapsulate)
//       1. Fresh ephemeral X25519 keypair (ek_priv discarded after use).
//       2. dh1 = X25519(ek_priv,     recip_pub)   — standard DH
//          dh2 = X25519(sender_priv, recip_pub)   — Mode_Auth authentication
//       3. HKDF-SHA256(ikm=dh1‖dh2, salt=ek_pub, info, length=44)
//          → aes_key (bytes 0–31) + nonce (bytes 32–43)
//       4. AES-256-GCM(aes_key, nonce, plaintext, aad) — requires AES-NI
//       5. encrypted_key field = ek_pub (32 bytes), NOT a wrapped key.
//
//   Decapsulation (hpke_decapsulate)
//       Re-runs the DH + HKDF key schedule from (recip_priv, sender_pub,
//       ek_pub), re-derives the nonce, decrypts.  Decryption succeeds iff the
//       ciphertext was produced by whoever holds sender_priv AND the caller
//       supplies the identical AAD — the GCM tag provides implicit sender
//       authentication and context binding in one check.
//
//   HKDF-SHA256 (RFC 5869) is built from libsodium's crypto_auth_hmacsha256
//   because libsodium 1.0.18 does not ship crypto_kdf_hkdf_sha256_*.
//
//   AES-256-GCM requires hardware acceleration.  Call sodium_init() first,
//   then check crypto_aead_aes256gcm_is_available() before encapsulating.

namespace crypto {

using Bytes = std::vector<unsigned char>;

// ── Base64 (standard variant, matches Python's base64.b64encode) ──────────────
std::string to_base64(const unsigned char* data, std::size_t len);
std::string to_base64(const Bytes& v);
Bytes       from_base64(const std::string& b64);   // throws std::runtime_error

// ── Keypair ───────────────────────────────────────────────────────────────────
struct Keypair {
    Bytes pub;   // 32-byte X25519 u-coordinate — share freely
    Bytes priv;  // 32-byte scalar — NEVER transmit; wipe() before discarding
};

Keypair generate_keypair();

// SHA-256 fingerprint of a base64-encoded public key, formatted as lowercase
// hex in space-separated 8-character groups — identical to the web client's
// keyFingerprint() so users can compare across devices.
std::string key_fingerprint(const std::string& key_b64);

// ── Canonical file-context AAD ────────────────────────────────────────────────
// Must byte-match backend.crypto.build_file_aad and the web client's
// buildFileAad:
//
//   smx:v1:sender={sender}:recipient={recipient}:filename={filename}
//
// Binding this into the AEAD means the server cannot relabel a stored
// ciphertext (e.g. swap the filename) without decryption failing.  Usernames
// cannot contain ':' (server-validated charset) and filename is the final
// field, so the encoding is unambiguous.  Empty filename is valid.
std::string build_file_aad(const std::string& sender_username,
                           const std::string& recipient_username,
                           const std::string& filename);

// ── HPKE Mode_Auth ────────────────────────────────────────────────────────────

// Default application context — must equal the backend's b"secure-messenger".
inline const Bytes HPKE_INFO = {
    's','e','c','u','r','e','-','m','e','s','s','e','n','g','e','r'
};

struct EncryptedFile {
    std::string ciphertext_b64;    // base64(AES-256-GCM ciphertext + 16-byte tag)
    std::string nonce_b64;         // base64(12-byte HKDF-derived nonce) — needed by API
    std::string encrypted_key_b64; // base64(32-byte ephemeral public key ek_pub)
};

// Encrypt `plaintext` (raw file bytes) for `recipient_pub` in HPKE Mode_Auth.
// `aad` — associated data authenticated (not encrypted) by the AEAD; build
// with build_file_aad().  Empty string means no AAD (matches Python
// associated_data=None; libsodium treats ad=nullptr/adlen=0 identically).
// Throws std::runtime_error on invalid key sizes or DH failure.
EncryptedFile hpke_encapsulate(const Bytes& plaintext,
                               const Bytes& recipient_pub,
                               const Bytes& sender_priv,
                               const std::string& aad = "",
                               const Bytes& info = HPKE_INFO);

// Decrypt a blob produced by hpke_encapsulate() (or Python / web client).
// `ciphertext_blob_b64` is the packed server blob:
//   base64(nonce_12_bytes ‖ aes_gcm_ciphertext_with_tag)
// The stored nonce prefix is stripped and IGNORED — the nonce is re-derived
// from the key schedule.
// `aad` must be identical to the encrypt-time value ("" if none).  Rebuild it
// locally with build_file_aad() from download metadata — never trust the
// server-supplied associated_data string.
// Returns std::nullopt on any failure (tampering, wrong sender key, wrong AAD).
std::optional<Bytes> hpke_decapsulate(const std::string& ciphertext_blob_b64,
                                      const std::string& enc_key_b64,
                                      const Bytes& recipient_priv,
                                      const Bytes& sender_pub,
                                      const std::string& aad = "",
                                      const Bytes& info = HPKE_INFO);

} // namespace crypto
