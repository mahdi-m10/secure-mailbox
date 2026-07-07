# Secure Mailbox — C++ Client

Command-line client for the Secure Mailbox backend (`/files` API).
Connects over HTTP(S) with libcurl; encrypts files end-to-end with libsodium
using the same HPKE Mode_Auth construction as the Python backend and the web
client — ciphertexts are fully interoperable across all three.

## Install dependencies (Ubuntu)

```sh
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    cmake \
    pkg-config \
    libcurl4-openssl-dev \
    libsodium-dev \
    nlohmann-json3-dev
```

## Build

```sh
cd cpp-client
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
```

The binary is `build/secure_mailbox`.

## Run

```sh
# Connect to the default server
./secure_mailbox

# Custom server URL (e.g. local dev backend)
./secure_mailbox http://localhost:8000
```

To run against a local backend, start it first:

```sh
cd ..   # back to the repo root
uvicorn backend.main:app --reload
```

Note: file encryption/decryption requires hardware AES (AES-NI) — libsodium's
AES-256-GCM has no software fallback. On a CPU without it the client still
runs (login, listings, key-vault unlock) but disables upload/download.

## Cryptography

The full construction is specified in `docs/crypto-design.md`; parameters
match `backend/crypto/hpke.py` and `web-client/js/crypto.js` byte-for-byte.

| Operation | Primitive | Library |
|-----------|-----------|---------|
| Key generation | `crypto_box_keypair` (Curve25519/X25519) | libsodium |
| Key encapsulation | HPKE Mode_Auth: ephemeral X25519 + static-static DH, HKDF-SHA256 key schedule | libsodium (`crypto_scalarmult_curve25519`, HKDF built from `crypto_auth_hmacsha256`) |
| File encryption | AES-256-GCM, 12-byte nonce derived from the key schedule (never random, never reused) | libsodium (`crypto_aead_aes256gcm_*`, requires AES-NI) |
| Context binding | Canonical AAD `smx:v1:sender=…:recipient=…:filename=…` authenticated by the GCM tag | — |
| Private key at rest | Argon2id (`crypto_pwhash`, ARGON2ID13) → XSalsa20-Poly1305 key wrap | libsodium (`crypto_secretbox`) |
| Base64 encode/decode | `sodium_bin2base64` / `sodium_base642bin` | libsodium |

**Key vault.** Your X25519 private key is generated (or imported) once and
immediately persisted to `~/.securemailbox/<username>/vault.json`, encrypted
with a key derived from your passphrase via Argon2id (random salt; parameters
distinct from the server's login hashing). The key is never printed and never
written to disk unencrypted; each session unlocks the vault with the
passphrase. The vault uses XSalsa20-Poly1305 rather than AES-GCM so it can be
opened even on CPUs without AES-NI. There is no way to use a key without a
vault.

**TOFU key pinning.** Peer public keys are pinned on first use to
`~/.securemailbox/<username>/pins.json` and checked on every subsequent fetch
— before encrypting to a recipient and before decrypting from a sender. If
the server returns a different key than the pinned one, the operation is
blocked and both SHA-256 fingerprints are shown; proceeding requires an
explicit typed confirmation, which re-pins.

**AAD enforcement.** Every upload binds the canonical associated-data string
(sender, recipient, filename) into the AEAD; every download rebuilds it
locally from the response metadata rather than trusting the server's copy.
A file whose metadata was relabelled server-side fails the GCM tag check.
There is no fallback to AAD-less decryption.

The server stores all ciphertext opaquely and never has key material to
decrypt it.

## Class overview

| Class | File | Responsibility |
|-------|------|----------------|
| `crypto` (namespace) | `include/Crypto.hpp` | HPKE Mode_Auth encapsulate/decapsulate, canonical AAD builder, base64, key fingerprints |
| `KeyVault` | `include/KeyVault.hpp` | Passphrase-encrypted private key at rest (Argon2id + secretbox) |
| `PinStore` | `include/PinStore.hpp` | TOFU pin file: first-use pinning, match/mismatch checks |
| `User` | `include/User.hpp` | Immutable value: remote user's id, username, public key |
| `File` | `include/File.hpp` | Value type: listing fields + download-only encrypted payload fields |
| `FileStore` | `include/FileStore.hpp` | In-memory cache: `std::vector` + `std::map` index; STL filtering |
| `Client` | `include/Client.hpp` | libcurl HTTP client — auth, `/files` endpoints, key discovery |

## Interoperability

Ciphertexts are cross-compatible in every direction: a file uploaded by this
client decrypts in the web client and via the Python reference
implementation, and vice versa, provided the same canonical AAD is used.
Verified by cross-stack tests (C++ ↔ Python ↔ Web Crypto, both directions,
including rejection of relabelled filenames).
