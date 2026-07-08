# Secure Mailbox

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.136-009688?logo=fastapi&logoColor=white)
![Ethereum](https://img.shields.io/badge/Ethereum-Sepolia-764ABC?logo=ethereum&logoColor=white)

A full-stack, end-to-end encrypted **asynchronous file mailbox**. Users upload
encrypted files for named recipients, who list, download, re-share, and delete
them on their own schedule. The Python/FastAPI backend stores only ciphertext —
all encryption and decryption happen on the client using HPKE Mode\_Auth
(RFC 9180 construction) over X25519, with the file's context (sender,
recipient, filename) bound into the AEAD so the server cannot relabel stored
files undetected. Each file's keccak256 integrity hash is anchored on the
Ethereum Sepolia testnet via a Solidity smart contract, providing a
tamper-evident audit trail. A C++17 CLI client built with libsodium is
included alongside the browser-based web client; ciphertexts are fully
interoperable across the Python reference implementation, the web client, and
the C++ client.

```
┌─────────────────────┐     HTTPS      ┌─────────────────────────┐
│  Web Client         │ ─────────────► │  TLS Gateway            │
│  (Web Crypto API)   │                │  theburkenator.com      │
└─────────────────────┘                └────────────┬────────────┘
                                                    │ HTTP :80
┌─────────────────────┐     HTTPS      ┌────────────▼────────────┐
│  C++ CLI Client     │ ─────────────► │  FastAPI Backend        │
│  (libcurl/libsodium)│                │  Ubuntu VM              │
└─────────────────────┘                │  ├── SQLite DB          │
                                       │  └── Web Client /app    │
                                       └────────────┬────────────┘
                                                    │ HTTPS
                                       ┌────────────▼────────────┐
                                       │  Ethereum Sepolia       │
                                       │  MessageDigest Contract │
                                       └─────────────────────────┘
```

---

## Features

**Authentication** — Register, login, logout, and password change. Short-lived
HS256 JWTs for API access; long-lived refresh tokens stored server-side
(SHA-256 digests only) and invalidated on logout. Login is rate-limited to
5 requests per minute per IP.

**File mailbox** — Encrypt-and-upload a file for a recipient (~8 MiB cap,
enforced twice: schema validator + request-size middleware), list files
shared with you and files you uploaded, download-and-decrypt, share with
further recipients (client-side re-encryption — the server cannot re-target a
ciphertext), revoke access (targeted or all recipients), and soft-delete.
Access-control failures return 404, not 403, to prevent IDOR probing.

**Cryptography** — HPKE Mode\_Auth construction: DHKEM(X25519), HKDF-SHA256,
AES-256-GCM. The sender's static private key is bound into key derivation,
authenticating the ciphertext to a specific sender. A canonical
associated-data string (`smx:v1:sender=…:recipient=…:filename=…`) is
authenticated by the GCM tag at every client call site — recipients rebuild
it locally, so a relabelled file fails decryption. Passwords are hashed with
Argon2id (64 MB, 3 iterations, 4 lanes).

**Key protection** — Peer public keys are TOFU-pinned in both clients (pin on
first use, hard-block with SHA-256 fingerprints on change, explicit override
re-pins). Private keys are passphrase-encrypted at rest in both clients: the
web client wraps its key with AES-256-GCM under a PBKDF2-HMAC-SHA256 key
(600k iterations) via `wrapKey`/`unwrapKey`, keeping the unlocked session key
non-extractable; the C++ client uses an Argon2id → XSalsa20-Poly1305 vault
file. Neither client has a path that operates with an unprotected key.

**Blockchain** — Every file's keccak256 digest is recorded via the
`MessageDigest` Solidity contract on Sepolia. A local SHA-256 block chain in
SQLite provides secondary tamper evidence. The web client includes a
dedicated verification page for on-chain proof.

---

## Live Deployment

| Resource | URL |
|----------|-----|
| Web application | <https://team10.theburkenator.com/app/> |
| API docs (Swagger) | <https://team10.theburkenator.com/docs> |
| Smart contract (Sepolia) | [`0xc8ABe2E8fB438F9120ED63c22ed9074F586586f6`](https://sepolia.etherscan.io/address/0xc8ABe2E8fB438F9120ED63c22ed9074F586586f6) |

---

## Repository Structure

```
secure-mailbox/
├── backend/
│   ├── main.py               # FastAPI app, CORS, security headers, body-size cap
│   ├── models.py             # SQLAlchemy ORM models (files, file_access, …)
│   ├── schemas.py            # Pydantic request/response schemas
│   ├── database.py           # Engine and session factory
│   ├── dependencies.py       # JWT auth dependency
│   ├── routers/
│   │   ├── auth.py           # /auth/* endpoints
│   │   ├── files.py          # /files/* upload, listings, share, revoke, proof
│   │   └── users.py          # /users/* public key lookup
│   ├── crypto/
│   │   ├── hpke.py           # HPKE Mode_Auth (X25519) + canonical AAD builder
│   │   └── password.py       # Argon2id
│   └── blockchain/
│       └── contract.py       # Web3.py interface to MessageDigest
├── blockchain/
│   ├── contracts/MessageDigest.sol
│   ├── scripts/deploy.js
│   └── test/MessageDigest.test.js
├── cpp-client/               # C++17 CLI (libcurl, libsodium, CMake)
│   ├── include/              # Crypto, KeyVault, PinStore, File(Store), Client
│   └── src/
├── web-client/               # Static frontend served at /app
│   ├── index.html            # Login / registration (incl. vault passphrase)
│   ├── files.html            # File mailbox (upload, share, TOFU, vault unlock)
│   └── verify.html           # Blockchain proof verification
├── docs/
│   ├── crypto-design.md      # Cryptographic design document
│   └── ai-log.md             # AI-assisted development log
├── tests/                    # Python pytest suite (51 tests)
└── .env.example
```

---

## Installation

### Backend

```bash
git clone <repo-url> && cd secure-mailbox
python -m venv venv && source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env          # set SECRET_KEY at minimum
```

### Web Client

No build step required. Static HTML/JS is served by FastAPI at `/app`. Start
the backend and open `http://localhost:8000/app`.

### C++ Client (Ubuntu)

```bash
sudo apt-get install -y build-essential cmake pkg-config \
    libcurl4-openssl-dev libsodium-dev nlohmann-json3-dev
cd cpp-client && mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release && make -j$(nproc)
```

See [cpp-client/README.md](cpp-client/README.md) for full usage notes.

### Blockchain

```bash
cd blockchain && npm install && npx hardhat compile
# Deploy (requires SEPOLIA_RPC_URL and DEPLOYER_PRIVATE_KEY in .env):
npx hardhat run scripts/deploy.js --network sepolia
# Copy the printed address into .env as CONTRACT_ADDRESS
```

---

## Environment Variables

Copy `.env.example` to `.env`. **Never commit `.env`.**

| Variable | Description |
|----------|-------------|
| `SECRET_KEY` | JWT signing key — `python -c "import secrets; print(secrets.token_hex(32))"` |
| `ALGORITHM` | JWT algorithm — `HS256` |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | JWT lifetime in minutes |
| `DATABASE_URL` | SQLAlchemy URL — `sqlite:///./secure_messenger.db` |
| `APP_ENV` | `development` or `production` |
| `DEBUG` | `true` / `false` |
| `SEPOLIA_RPC_URL` | Sepolia HTTPS RPC endpoint |
| `DEPLOYER_PRIVATE_KEY` | Deployer wallet private key (no `0x` prefix) |
| `CONTRACT_ADDRESS` | Deployed `MessageDigest` contract address |

---

## Running the Application

**Local development**
```bash
source venv/bin/activate      # Windows: venv\Scripts\activate
uvicorn backend.main:app --reload
# Web client: http://localhost:8000/app
# API docs:   http://localhost:8000/docs
```

**Production**
```bash
uvicorn backend.main:app --host 0.0.0.0 --port 80
```

**C++ client**
```bash
./cpp-client/build/secure_mailbox http://localhost:8000
./cpp-client/build/secure_mailbox           # default configured server
```

---

## Testing

**Python — 51 tests** (auth, username validation, file access control, AAD
canonicalisation and enforcement, /files endpoint behaviour, end-to-end
crypto with compromised-server simulations)
```bash
source venv/bin/activate
pytest tests/ -v
```

**Smart contract — 5 tests** (deploy, record, getDigest, duplicate rejection, owner-only)
```bash
cd blockchain && npx hardhat test
```

---

## Security Documentation

- [`docs/crypto-design.md`](docs/crypto-design.md) — threat model (four
  attacker classes), construction walkthrough, parameter-level primitive
  justifications with RFC citations, known limitations, remediation map
- [`docs/ai-log.md`](docs/ai-log.md) — AI-assisted development log
- Network Architecture Document and Penetration Testing Report are included
  in the project submission

---

## Design Decisions

- **HPKE Mode\_Auth (RFC 9180 construction)** provides both confidentiality
  and implicit sender authentication — the recipient can only decrypt if the
  ciphertext was produced by the holder of the sender's static private key.
- **Canonical AAD binding** — sender, recipient, and filename are
  authenticated by the GCM tag; the recipient rebuilds the string locally, so
  a server that relabels a stored file breaks decryption. There is no
  AAD-less fallback (it would enable a downgrade attack).
- **TOFU key pinning** in both clients defends sender authenticity against a
  compromised server for every already-established pair; first contact is
  verified out-of-band via displayed fingerprints.
- **Passphrase-wrapped keys at rest** in both clients, with KDF parameters
  deliberately distinct from the server's login hashing (web:
  PBKDF2-HMAC-SHA256 600k — the only password KDF native to Web Crypto;
  C++: Argon2id via libsodium, with an XSalsa20-Poly1305 wrap so the vault
  opens on CPUs without AES-NI).
- **Argon2id** with 64 MB memory cost protects stored password hashes against
  GPU-accelerated brute force.
- **Blockchain anchoring** provides tamper evidence that survives a fully
  compromised server — the keccak256 hash is recorded before the HTTP
  response is returned.
- **Sharing is client-side re-encryption** — the content key is derived from
  the recipient's key pair, so the server cannot re-target a ciphertext;
  a sharer decrypts locally and re-encrypts for the new recipient.

---

## Smart Contract

`MessageDigest` — append-only on-chain hash registry deployed on Ethereum Sepolia:  
[`0xc8ABe2E8fB438F9120ED63c22ed9074F586586f6`](https://sepolia.etherscan.io/address/0xc8ABe2E8fB438F9120ED63c22ed9074F586586f6)

---

## Author

**Mahdi Mirzay** — Team10
