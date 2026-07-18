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
files undetected. Three Solidity contracts on the Ethereum Sepolia testnet
anchor each file's keccak256 integrity hash, maintain a public-key
transparency log that both clients check before encrypting, and record
server-signed upload receipts. A C++17 CLI client built with libsodium is
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
                                       │  MessageDigest /        │
                                       │  KeyRegistry /          │
                                       │  MessageReceipt         │
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

**Blockchain** — Three Solidity contracts live on Sepolia. `MessageDigest`
records every file's keccak256 digest (tamper-evident audit trail; a local
SHA-256 block chain in SQLite provides secondary evidence). `KeyRegistry` is
a public transparency log of user public keys, keyed by
`keccak256(username)`: the server registers/rotates keys on-chain, and both
clients read the registry **directly** over a public RPC (from-scratch
Keccak-256 in JS and C++) as a fail-closed pre-encrypt gate — a compromised
server cannot answer its own integrity check. `MessageReceipt` anchors a
server-signed receipt for every accepted upload. The web client includes a
file-proof verification page and a key verification page that cross-checks
chain, server, and local TOFU pin.

---

## Live Deployment

| Resource | URL |
|----------|-----|
| Web application | <https://team10.theburkenator.com/app/> |
| API docs (Swagger) | <https://team10.theburkenator.com/docs> |
| `MessageDigest` (Sepolia) | [`0xc8ABe2E8fB438F9120ED63c22ed9074F586586f6`](https://sepolia.etherscan.io/address/0xc8ABe2E8fB438F9120ED63c22ed9074F586586f6) |
| `KeyRegistry` (Sepolia) | [`0x230c56Ab59535625c8eAeF18f8394b7D222a889D`](https://sepolia.etherscan.io/address/0x230c56Ab59535625c8eAeF18f8394b7D222a889D) |
| `MessageReceipt` (Sepolia) | [`0x355557d9E5bd1188372986f3ad73b60D992Ef9e5`](https://sepolia.etherscan.io/address/0x355557d9E5bd1188372986f3ad73b60D992Ef9e5) |

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
│       ├── contract.py       # Web3.py interface to MessageDigest
│       ├── registry.py       # KeyRegistry: register/rotate/revoke + reads
│       ├── receipts.py       # MessageReceipt: post + read receipts
│       └── _send_lock.py     # Shared-wallet nonce serialisation lock
├── blockchain/
│   ├── contracts/            # MessageDigest.sol, KeyRegistry.sol, MessageReceipt.sol
│   ├── scripts/              # deploy.js, deploy-registry.js, lifecycle helpers
│   ├── test/                 # Hardhat unit tests for all three contracts
│   └── artifacts/…/*.json    # Tracked ABIs (rest of the build tree gitignored)
├── cpp-client/               # C++17 CLI (libcurl, libsodium, CMake)
│   ├── include/              # Crypto, KeyVault, PinStore, File(Store), Chain, Client
│   └── src/                  # incl. from-scratch Keccak-256 + eth_call reads
├── web-client/               # Static frontend served at /app
│   ├── index.html            # Login / registration (incl. vault passphrase)
│   ├── files.html            # File mailbox (upload, share, TOFU, vault unlock)
│   ├── verify.html           # Blockchain proof verification
│   └── verify-key.html       # Key verification (chain vs server vs TOFU pin)
├── docs/
│   ├── crypto-design.md      # Cryptographic design document
│   ├── network-architecture.md # Topology, TLS, trust boundaries, external services
│   ├── pentest-report.md     # Vulnerability & penetration testing report
│   ├── deployment.md         # Live Sepolia addresses, ABIs, deployment txs
│   ├── test-plan.md          # Blockchain test plan + on-chain verification
│   └── ai-log.md             # AI-assisted development log
├── tests/                    # Python pytest suite (72 tests)
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
npx hardhat run scripts/deploy.js --network sepolia            # MessageDigest
npx hardhat run scripts/deploy-registry.js --network sepolia   # KeyRegistry + MessageReceipt
# Copy the printed addresses into .env (CONTRACT_ADDRESS,
# KEY_REGISTRY_ADDRESS, MESSAGE_RECEIPT_ADDRESS).
```

The contracts are already deployed live on Sepolia; addresses, tx hashes, and
Etherscan links are recorded in [docs/deployment.md](docs/deployment.md), and
the on-chain lifecycle verification in [docs/test-plan.md](docs/test-plan.md).

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
| `DEPLOYER_PRIVATE_KEY` | Deployer wallet private key (no `0x` prefix); the registrar/server wallet |
| `CONTRACT_ADDRESS` | Deployed `MessageDigest` contract address |
| `KEY_REGISTRY_ADDRESS` | Deployed `KeyRegistry` contract address (see docs/deployment.md) |
| `MESSAGE_RECEIPT_ADDRESS` | Deployed `MessageReceipt` contract address (see docs/deployment.md) |

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

**Python — 72 tests** (auth incl. rate limiting, username validation, file
access control, AAD canonicalisation and enforcement, /files endpoint
behaviour, end-to-end crypto with compromised-server simulations, and
backend blockchain integration)
```bash
source venv/bin/activate
pytest tests/ -v
```

**Smart contracts — 31 tests** across `KeyRegistry` (17), `MessageReceipt`
(9), and `MessageDigest` (5): lifecycle, access control, duplicate
rejection, and event assertions
```bash
cd blockchain && npx hardhat test
```

---

## Security Documentation

- [`docs/crypto-design.md`](docs/crypto-design.md) — threat model (four
  attacker classes), construction walkthrough, parameter-level primitive
  justifications with RFC citations, known limitations, remediation map
- [`docs/network-architecture.md`](docs/network-architecture.md) — network
  topology, TLS termination, trust boundaries, external service connections,
  and ports
- [`docs/pentest-report.md`](docs/pentest-report.md) — vulnerability and
  penetration testing report: OWASP-category controls, the tests exercising
  them, and findings
- [`docs/deployment.md`](docs/deployment.md) — live Sepolia contract
  addresses, ABIs, and deployment transactions
- [`docs/test-plan.md`](docs/test-plan.md) — blockchain test plan and
  on-chain verification results
- [`docs/ai-log.md`](docs/ai-log.md) — AI-assisted development log

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

## Smart Contracts

All three deployed live on Ethereum Sepolia (details, deployment txs, and
tracked ABIs in [docs/deployment.md](docs/deployment.md)):

| Contract | Purpose | Address |
|---|---|---|
| `MessageDigest` | Append-only file-hash registry (tamper evidence) | [`0xc8ABe2E8…6586f6`](https://sepolia.etherscan.io/address/0xc8ABe2E8fB438F9120ED63c22ed9074F586586f6) |
| `KeyRegistry` | Public-key transparency log (register/rotate/revoke, versioned) | [`0x230c56Ab…2a889D`](https://sepolia.etherscan.io/address/0x230c56Ab59535625c8eAeF18f8394b7D222a889D) |
| `MessageReceipt` | Server-signed receipts for accepted uploads | [`0x355557d9…2Ef9e5`](https://sepolia.etherscan.io/address/0x355557d9E5bd1188372986f3ad73b60D992Ef9e5) |

---

## Author

**Mahdi Mirzay** — Team10
