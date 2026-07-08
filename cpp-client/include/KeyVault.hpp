#pragma once
#include <filesystem>
#include <optional>
#include <string>
#include "Crypto.hpp"

// KeyVault — passphrase-encrypted private key at rest.
//
// The X25519 private key is never written to disk in the clear and never
// printed.  It is wrapped with XSalsa20-Poly1305 (crypto_secretbox) under a
// key derived from the user's passphrase with Argon2id (libsodium
// crypto_pwhash, alg ARGON2ID13):
//
//   salt      — 16 random bytes, stored in the vault file
//   opslimit  — crypto_pwhash_OPSLIMIT_MODERATE (3)
//   memlimit  — crypto_pwhash_MEMLIMIT_MODERATE (256 MiB)
//
// These parameters are deliberately DISTINCT from the server's login hashing
// (Argon2id m=64 MiB, t=3, p=4): the two derivations protect different
// assets in different threat models, and sharing parameters/salts across
// contexts invites cross-protocol confusion.
//
// The wrap cipher is XSalsa20-Poly1305 rather than AES-256-GCM — a deliberate
// exception to the AES-GCM-everywhere pattern: libsodium's AES-256-GCM
// requires AES-NI hardware, so a GCM-wrapped vault could not be opened on a
// CPU without it, locking the user out of their own key.  XSalsa20-Poly1305
// is a pure-software AEAD available unconditionally, and its 24-byte random
// nonce is safe to generate randomly (no counter management).
//
// Vault file layout (JSON, mode 0600):
//   {
//     "version": 1,
//     "kdf": "argon2id13",
//     "opslimit": 3,
//     "memlimit_bytes": 268435456,
//     "salt": "<b64, 16 bytes>",
//     "nonce": "<b64, 24 bytes>",
//     "public_key": "<b64, 32 bytes>",           — stored in clear (public)
//     "encrypted_private_key": "<b64, 32+16 bytes>"
//   }
//
// A wrong passphrase fails the Poly1305 MAC — unlock() returns nullopt, it
// cannot return garbage key bytes.
class KeyVault {
public:
    explicit KeyVault(std::filesystem::path path) : path_(std::move(path)) {}

    bool exists() const { return std::filesystem::exists(path_); }
    const std::filesystem::path& path() const noexcept { return path_; }

    // Wrap `kp.priv` under `passphrase` and write the vault file (0600).
    // Refuses to overwrite an existing vault. Returns false on any failure.
    bool create(const crypto::Keypair& kp, const std::string& passphrase) const;

    // Derive the KDF key from `passphrase` using the stored salt/params and
    // open the secretbox.  nullopt on wrong passphrase or corrupt file.
    std::optional<crypto::Keypair> unlock(const std::string& passphrase) const;

    // Public key stored in the vault (readable without the passphrase),
    // e.g. to cross-check against the key the server has on record.
    std::optional<std::string> public_key_b64() const;

private:
    std::filesystem::path path_;
};
