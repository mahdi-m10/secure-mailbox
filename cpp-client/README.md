# Secure Messenger — C++ Client

Command-line client for the Secure Messenger backend API.
Connects over HTTP(S) with libcurl, encrypts messages end-to-end with libsodium.

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

The binary is `build/secure_messenger`.

## Run

```sh
# Connect to the local dev server (default: http://localhost:8000)
./secure_messenger

# Custom server URL
./secure_messenger http://192.168.1.10:8000
```

Start the backend first:

```sh
cd ..   # back to the repo root
uvicorn backend.main:app --reload
```

## Cryptography

| Operation | Primitive | Library |
|-----------|-----------|---------|
| Key generation | `crypto_box_keypair` (Curve25519/X25519) | libsodium |
| Message encryption | ChaCha20-Poly1305-IETF (12-byte nonce) | libsodium |
| Key encapsulation | `crypto_box_seal` (anonymous box) | libsodium |
| Base64 encode/decode | `sodium_bin2base64` / `sodium_base642bin` | libsodium |

**Private keys are held in memory only.** The CLI prints your base64-encoded
private key when you generate a keypair — save it externally if you need to
decrypt messages after restarting.

The server stores all ciphertext opaquely and never attempts to decrypt it.

## Class overview

| Class | File | Responsibility |
|-------|------|----------------|
| `User` | `include/User.hpp` | Immutable value: remote user's id, username, public key |
| `Message` | `include/Message.hpp` | Value type: summary fields from inbox + download fields |
| `Client` | `include/Client.hpp` | libcurl HTTP client — auth, messages, key-discovery |
| `MessageStore` | `include/MessageStore.hpp` | In-memory cache: `std::vector` + `std::map` index; STL filtering |

## Interoperability note

Messages encrypted by this C++ client can only be decrypted by another C++
client that knows the same private key.  The Python backend uses HPKE Mode\_Auth
for its own E2E scheme, which uses a different key-encapsulation format.
The server stores both formats opaquely — the two schemes can coexist on the
same server as long as clients know which scheme they used.
