# Secure Messenger

A full-stack, end-to-end encrypted messaging application with a Python REST API, a browser client, a C++ CLI client, and a Solidity smart contract for tamper-evident message auditing on the Ethereum Sepolia testnet.

---

## Project Overview

Users exchange messages that are encrypted on the client before transmission. The server stores only ciphertext and never has access to plaintext.

**Key security properties:**

- **End-to-end encryption** — HPKE Mode\_Auth (RFC 9180) over X25519; encryption and decryption happen entirely on the client.
- **Sender authentication** — the sender's static private key is bound into the key derivation, so only the genuine sender can produce a ciphertext the recipient accepts.
- **Password security** — Argon2id; no plaintext or reversible hash is stored.
- **Immutable audit trail** — each message's keccak256 integrity hash is anchored on Sepolia via the `MessageDigest` smart contract.
- **Forward / revoke** — the sender can grant new recipients access (with re-encryption) or revoke access at any time.

---

## Tech Stack

| Layer | Technology |
|-------|------------|
| **Backend** | Python 3.11+, FastAPI, SQLAlchemy, SQLite |
| **Web client** | Vanilla HTML/CSS/JavaScript, Web Crypto API |
| **C++ client** | C++17, libcurl, libsodium, nlohmann/json, CMake |
| **Blockchain** | Solidity 0.8.20, Hardhat, Ethers.js, Sepolia testnet |
| **KEM** | DHKEM(X25519) — Curve25519 Diffie-Hellman |
| **KDF** | HKDF-SHA256 |
| **AEAD** | AES-256-GCM |
| **Password hashing** | Argon2id |

---

## Live Deployment

| Resource | URL |
|----------|-----|
| Web application | <https://team10.theburkenator.com/app/> |
| API docs | <https://team10.theburkenator.com/docs> |
| Smart contract (Sepolia) | [`0xc8ABe2E8fB438F9120ED63c22ed9074F586586f6`](https://sepolia.etherscan.io/address/0xc8ABe2E8fB438F9120ED63c22ed9074F586586f6) |

---

## Repository Structure

```
secure-messenger/
├── backend/
│   ├── main.py               # App entry point, CORS, static file mount
│   ├── models.py             # SQLAlchemy ORM models
│   ├── schemas.py            # Pydantic schemas
│   ├── database.py           # Engine and session factory
│   ├── dependencies.py       # JWT auth dependency
│   ├── routers/
│   │   ├── auth.py           # /register, /login, /me, /change-password
│   │   ├── messages.py       # /messages/* endpoints
│   │   └── users.py          # /users/{username} public key lookup
│   ├── crypto/
│   │   ├── hpke.py           # HPKE Mode_Auth implementation
│   │   ├── aead.py           # AES-256-GCM helpers
│   │   ├── kdf.py            # HKDF-SHA256 helpers
│   │   └── password.py       # Argon2id hashing
│   └── blockchain/
│       └── contract.py       # Web3.py interface to MessageDigest contract
│
├── blockchain/
│   ├── contracts/
│   │   └── MessageDigest.sol # Append-only on-chain hash registry
│   └── scripts/
│       └── deploy.js         # Hardhat deployment script
│
├── cpp-client/
│   ├── include/              # Client.hpp, User.hpp, Message.hpp, MessageStore.hpp
│   ├── src/
│   ├── CMakeLists.txt
│   └── README.md             # C++ client build and usage details
│
├── web-client/               # Static frontend served by FastAPI at /app
│   ├── index.html            # Login / registration
│   ├── chat.html             # Messaging interface
│   ├── verify.html           # Blockchain proof verification
│   ├── css/
│   └── js/
│
├── .env.example
└── README.md
```

---

## Setup and Installation

### Prerequisites

- Python 3.11+
- Node.js 18+ and npm
- A Sepolia RPC URL (free from [Alchemy](https://www.alchemy.com/) or [Infura](https://infura.io/))

---

### Backend

```bash
git clone <repo-url>
cd secure-messenger

python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

pip install -r requirements.txt

cp .env.example .env
# Edit .env — set SECRET_KEY at minimum
```

---

### Web Client

No build step required. The web client is static HTML/JS served by FastAPI at `/app`. Start the backend and open `http://localhost:8000/app`.

---

### C++ Client (Ubuntu)

```bash
sudo apt-get update
sudo apt-get install -y \
    build-essential cmake pkg-config \
    libcurl4-openssl-dev libsodium-dev nlohmann-json3-dev

cd cpp-client
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
# Binary: cpp-client/build/secure_messenger
```

See [cpp-client/README.md](cpp-client/README.md) for full usage notes.

---

### Blockchain

```bash
cd blockchain
npm install

npx hardhat compile

# Deploy (requires SEPOLIA_RPC_URL and DEPLOYER_PRIVATE_KEY in .env)
npx hardhat run scripts/deploy.js --network sepolia

# Paste the printed address into .env as CONTRACT_ADDRESS
```

---

## Environment Variables

Copy `.env.example` to `.env`. **Never commit `.env`.**

| Variable | Description |
|----------|-------------|
| `SECRET_KEY` | Random hex string for JWT signing. Generate: `python -c "import secrets; print(secrets.token_hex(32))"` |
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

### Local Development

```bash
source venv/bin/activate        # Windows: venv\Scripts\activate
uvicorn backend.main:app --reload

# Web client: http://localhost:8000/app
# API docs:   http://localhost:8000/docs
```

### Production (Ubuntu VM)

```bash
source venv/bin/activate
uvicorn backend.main:app --host 0.0.0.0 --port 80
```

### C++ Client

```bash
./cpp-client/build/secure_messenger                          # default: http://localhost:8000
./cpp-client/build/secure_messenger https://team10.theburkenator.com
```

---

## Security Features

| Concern | Mechanism |
|---------|-----------|
| Key agreement | X25519 Diffie-Hellman |
| E2E encryption | HPKE Mode\_Auth (RFC 9180) — fresh ephemeral key per message, sender identity bound to ciphertext |
| Symmetric encryption | AES-256-GCM, 96-bit nonce derived from HKDF key schedule |
| Key derivation | HKDF-SHA256 over two DH outputs (ephemeral + static-auth) |
| Password storage | Argon2id |
| Access tokens | HS256-signed JWTs |
| Integrity audit | keccak256 hash anchored on Sepolia; local SHA-256 block chain in SQLite |

**Trust model:** TOFU (Trust On First Use). A peer's public key is trusted on first download; any subsequent key change triggers a warning, matching the pattern used by Signal.

**Note on the C++ client:** the C++ client uses libsodium (Curve25519 / ChaCha20-Poly1305) rather than HPKE. The two schemes coexist on the same server because the backend stores ciphertext opaquely — see [cpp-client/README.md](cpp-client/README.md) for details.

---

## Testing

### Web Client (End-to-End)

1. Open the app and register two accounts — **alice** and **bob**.
2. Log in as **alice**, send a message to **bob**.
3. Log in as **bob** — the message appears in the inbox and decrypts in the browser.
4. Open the **Verify** page, enter the message ID, and confirm `hash_match: true` and `on_chain_match: true`.

### C++ Client

```bash
# Terminal 1
uvicorn backend.main:app --reload

# Terminal 2 — alice sends
./cpp-client/build/secure_messenger http://localhost:8000
# register alice <password> → login → send bob "hello"

# Terminal 3 — bob receives
./cpp-client/build/secure_messenger http://localhost:8000
# login bob <password> → inbox → read <id>
```

### API

The Swagger UI at `/docs` exposes every endpoint with try-it-out support.
