# Secure Messenger

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.136-009688?logo=fastapi&logoColor=white)
![Ethereum](https://img.shields.io/badge/Ethereum-Sepolia-764ABC?logo=ethereum&logoColor=white)

A full-stack, end-to-end encrypted messaging application. The Python/FastAPI backend stores only ciphertext — all encryption and decryption happen on the client using HPKE Mode\_Auth (RFC 9180) over X25519. Each message's keccak256 integrity hash is permanently anchored on the Ethereum Sepolia testnet via a Solidity smart contract, providing a tamper-evident audit trail. A C++ CLI client built with libsodium is included alongside the browser-based web client.

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

**Authentication** — Register, login, logout, and password change. Short-lived HS256 JWTs for API access; long-lived refresh tokens stored server-side and invalidated on logout. Login is rate-limited to 5 requests per minute per IP.

**Messaging** — Send, receive, forward (with re-encryption to a new recipient), revoke, soft-delete, and download encrypted payloads. Delete and revoke are separate operations — deleting removes a message from the sender's view only; revoking removes a recipient's access to previously shared ciphertext.

**Cryptography** — HPKE Mode\_Auth (RFC 9180): DHKEM(X25519), HKDF-SHA256, AES-256-GCM. The sender's static private key is bound into key derivation, authenticating the ciphertext to a specific sender. Passwords are hashed with Argon2id (64 MB, 3 iterations, 4 lanes).

**Blockchain** — Every message's keccak256 digest is recorded via the `MessageDigest` Solidity contract on Sepolia. A local SHA-256 block chain in SQLite provides secondary tamper evidence. The web client includes a dedicated verification page for on-chain proof.

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
secure-messenger/
├── backend/
│   ├── main.py               # FastAPI app, CORS, security headers
│   ├── models.py             # SQLAlchemy ORM models
│   ├── schemas.py            # Pydantic request/response schemas
│   ├── database.py           # Engine and session factory
│   ├── dependencies.py       # JWT auth dependency
│   ├── routers/
│   │   ├── auth.py           # /auth/* endpoints
│   │   ├── messages.py       # /messages/* endpoints
│   │   └── users.py          # /users/* public key lookup
│   ├── crypto/
│   │   ├── hpke.py           # HPKE Mode_Auth (X25519)
│   │   ├── aead.py           # AES-256-GCM
│   │   ├── kdf.py            # HKDF-SHA256
│   │   └── password.py       # Argon2id
│   └── blockchain/
│       └── contract.py       # Web3.py interface to MessageDigest
├── blockchain/
│   ├── contracts/MessageDigest.sol
│   ├── scripts/deploy.js
│   └── test/MessageDigest.test.js
├── cpp-client/               # C++17 CLI (libcurl, libsodium, CMake)
├── web-client/               # Static frontend served at /app
│   ├── index.html            # Login / registration
│   ├── chat.html             # Messaging interface
│   └── verify.html           # Blockchain proof verification
├── tests/                    # Python pytest suite
└── .env.example
```

---

## Installation

### Backend

```bash
git clone <repo-url> && cd secure-messenger
python -m venv venv && source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env          # set SECRET_KEY at minimum
```

### Web Client

No build step required. Static HTML/JS is served by FastAPI at `/app`. Start the backend and open `http://localhost:8000/app`.

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
./cpp-client/build/secure_messenger                                    # localhost:8000
./cpp-client/build/secure_messenger https://team10.theburkenator.com
```

---

## Testing

**Python — 12 tests** (auth, username validation, message access control)
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

Full security documentation is included in the project submission:
- Cryptographic Design Document
- Network Architecture Document
- Penetration Testing Report
- AI Tool Usage Reflection

---

## Design Decisions

- **HPKE Mode\_Auth (RFC 9180)** provides both confidentiality and implicit sender authentication — the recipient can only decrypt if the ciphertext was produced by the holder of the sender's static private key.
- **AES-256-GCM** provides authenticated encryption; ciphertext tampering is detected and rejected before decryption.
- **Argon2id** with 64 MB memory cost protects stored password hashes against GPU-accelerated brute force.
- **Blockchain anchoring** provides tamper evidence that survives a fully compromised server — the keccak256 hash is recorded before the HTTP response is returned.
- **Web Crypto API** with non-extractable IndexedDB keys ensures the private key never leaves the browser in exportable form.

---

## Smart Contract

`MessageDigest` — append-only on-chain hash registry deployed on Ethereum Sepolia:  
[`0xc8ABe2E8fB438F9120ED63c22ed9074F586586f6`](https://sepolia.etherscan.io/address/0xc8ABe2E8fB438F9120ED63c22ed9074F586586f6)

---

## Author

**Mahdi Mirzay** — Team10
