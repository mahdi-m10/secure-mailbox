# Network Architecture — Secure Messenger

---

## 1. System Architecture Diagram

```
  ┌─────────────────────┐
  │   Web Browser       │──── HTTPS (443) ────┐
  │   Web Crypto API    │                     │
  └─────────────────────┘                     ▼
                                  ┌───────────────────────────┐
  ┌─────────────────────┐         │       TLS Gateway          │
  │   C++ CLI Client    │──HTTPS──│  theburkenator.com         │
  │   libcurl + OpenSSL │  (443)  │  Let's Encrypt certificate │
  └─────────────────────┘         │  TLS 1.2 / 1.3             │
                                  └────────────┬──────────────┘
                                               │  HTTP port 80
                                               │  (internal / private network)
                                               ▼
                                  ┌───────────────────────────┐
                                  │        Ubuntu VM           │
                                  │                            │
                                  │  FastAPI (uvicorn :80)     │
                                  │  ├─ POST /auth/register    │
                                  │  ├─ POST /auth/login       │
                                  │  ├─ POST /auth/logout      │
                                  │  ├─ PUT  /auth/password    │
                                  │  ├─ GET/POST /messages/*   │
                                  │  ├─ GET  /users/{username} │
                                  │  └─ GET  /app/*  (static)  │
                                  │                            │
                                  │  SQLite                    │
                                  │  secure_messenger.db       │
                                  └────────────┬──────────────┘
                                               │  HTTPS (443)
                                               │  background thread,
                                               │  per-message send
                                               ▼
                                  ┌───────────────────────────┐
                                  │  Alchemy / Infura RPC      │
                                  │  Sepolia HTTPS endpoint    │
                                  └────────────┬──────────────┘
                                               │  JSON-RPC over HTTPS
                                               ▼
                                  ┌───────────────────────────┐
                                  │  Ethereum Sepolia Testnet  │
                                  │  MessageDigest contract    │
                                  │  0xc8ABe2E8fB438F9120...   │
                                  └───────────────────────────┘
```

---

## 2. Component Descriptions

### Web Browser Client

A static HTML/CSS/JavaScript application served by FastAPI at `/app`. All cryptographic operations (key generation, HPKE encryption/decryption) execute entirely inside the browser using the **Web Crypto API** — plaintext never leaves the browser. The private key is stored as a non-extractable `CryptoKey` in IndexedDB. The JWT access token is stored in `localStorage`.

Minimum browser requirements for X25519 support: Chrome 113+, Edge 113+, Safari 17+, Firefox 130+.

### C++ CLI Client

A command-line application (`cpp-client/build/secure_messenger`) built with CMake. Uses **libcurl** for HTTPS transport (with TLS verification enabled by default) and **libsodium** for cryptography (Curve25519 key generation, ChaCha20-Poly1305-IETF encryption). Keys are held in process memory only; the CLI prints the base64-encoded private key at generation time for external backup.

### FastAPI Backend

A Python 3.11+ ASGI application served by **uvicorn** on port 80. Handles authentication, message routing, access control, and blockchain anchoring. Request/response bodies are validated by **Pydantic** schemas. All endpoints that handle messages enforce JWT authentication via the `get_current_user` dependency, which verifies the token signature, expiry, and type claim, then reloads the user from the database on every request.

The blockchain anchoring call (`record_message_digest`) runs in a **daemon thread** after the HTTP response is returned, so Sepolia's ~15–30 s block confirmation time does not delay the client.

### SQLite Database

A single-file database (`secure_messenger.db`) co-located on the VM. Managed via **SQLAlchemy 2.0** ORM. All queries use parameterised statements, preventing SQL injection. The database stores users, messages (ciphertext only), message access records, and a local blockchain audit chain. The file path is hardcoded in `backend/database.py`.

### Sepolia Smart Contract (`MessageDigest`)

A Solidity 0.8.20 contract deployed at `0xc8ABe2E8fB438F9120ED63c22ed9074F586586f6` on the Ethereum Sepolia testnet. Provides an append-only, permissioned hash registry: only the deployer wallet can call `recordHash`; reads are public. Once a keccak256 hash is recorded, it cannot be altered or deleted — independent tamper evidence for the SQLite message log.

### TLS Gateway

A reverse proxy at `theburkenator.com` that terminates TLS connections from the public internet and forwards requests to the VM over HTTP on port 80 via the private network. Issues a **Let's Encrypt** certificate renewed automatically. The VM is not directly exposed to the public internet on port 80; all external traffic passes through the gateway.

---

## 3. Network Connections

| # | Source | Destination | Protocol | Port | Encrypted | Notes |
|---|--------|-------------|----------|------|-----------|-------|
| 1 | Browser / C++ client | TLS gateway | HTTPS | 443 | Yes — TLS 1.2+ | All client traffic |
| 2 | TLS gateway | Ubuntu VM | HTTP | 80 | No — private network | SSL terminated at gateway |
| 3 | FastAPI (VM) | Alchemy / Infura RPC | HTTPS | 443 | Yes — TLS | Sepolia RPC calls |
| 4 | Alchemy / Infura | Ethereum Sepolia nodes | JSON-RPC / P2P | 443 / varied | Yes | Managed by RPC provider |

---

## 4. SSL/TLS Configuration

**Certificate authority:** Let's Encrypt, issued to `theburkenator.com`. Renewed automatically by the gateway.

**Protocol versions:** TLS 1.2 and TLS 1.3. Older versions (TLS 1.0, 1.1) are disabled at the gateway.

**SSL termination:** Termination occurs at the TLS gateway. The connection between the gateway and the VM is unencrypted HTTP on port 80 over a private network. This is the standard reverse-proxy deployment model; the plaintext segment is not exposed to the public internet.

**Client certificate verification (C++ client):** libcurl verifies the server's certificate against the system CA bundle by default (`CURLOPT_SSL_VERIFYPEER = 1`, `CURLOPT_SSL_VERIFYHOST = 2`). Certificate verification was explicitly re-enabled in a prior fix after it was found to be disabled.

**HTTPS for RPC:** All outbound calls from FastAPI to the Alchemy/Infura endpoint use `Web3.HTTPProvider` with a standard `https://` URL, relying on Python's `urllib3` and the system CA bundle for certificate validation.

---

## 5. External Service Connections

### Alchemy / Infura (Sepolia RPC)

- **URL:** configured via the `SEPOLIA_RPC_URL` environment variable (e.g. `https://eth-sepolia.g.alchemy.com/v2/<api-key>`)
- **Used for:** submitting `recordHash` transactions and querying `getIndexByHash` / `getDigest`
- **Call frequency:** one HTTPS call per message sent (in a background thread); one call per blockchain-proof lookup
- **Failure behaviour:** if the RPC endpoint is unreachable or the transaction reverts, the error is logged and the HTTP response to the client is unaffected — the SQLite integrity hash is still recorded

### Ethereum Sepolia Testnet

- **Network:** Ethereum Sepolia (chain ID 11155111)
- **Contract address:** `0xc8ABe2E8fB438F9120ED63c22ed9074F586586f6`
- **Deployer wallet:** address controlled by `DEPLOYER_PRIVATE_KEY`; the only account authorised to call `recordHash`
- **Transaction cost:** paid in Sepolia ETH (test ether, no real value)
- **Block confirmation time:** approximately 15–30 seconds

---

## 6. Security Controls per Layer

### Input Validation

All API request bodies are defined as **Pydantic** models in `backend/schemas.py`. Pydantic enforces field types, length constraints, and custom validators (e.g. base64 format checks, nonce length) before any handler code runs. Invalid requests are rejected with HTTP 422 before reaching the database.

### Authentication

| Mechanism | Detail |
|-----------|--------|
| Token type | HS256-signed JWT |
| Claims | `sub` (user ID), `username`, `iat`, `exp`, `type: "access"` |
| Lifetime | Configurable via `ACCESS_TOKEN_EXPIRE_MINUTES` (default: 30 min) |
| Refresh tokens | Opaque random strings; only the SHA-256 hash is stored in the DB — a database leak cannot be replayed directly |
| Token-type guard | `_decode_access_token` rejects any token whose `type` claim is not `"access"`, preventing refresh tokens from being used on protected endpoints |
| Session invalidation | Password change deletes all active sessions for that user, forcing re-login on all devices |
| Timing attack mitigation | `DUMMY_HASH` used when a username is not found, keeping both failure paths at the same ~300 ms — prevents username enumeration via response timing |

### CORS

CORS is currently configured with a wildcard:

```python
allow_origins=["*"]
allow_methods=["*"]
allow_headers=["*"]
```

This is marked with a `# TODO: restrict to frontend origin in production` comment in `backend/main.py`. As a known limitation, this allows any origin to make credentialed API requests. The practical risk is limited because all sensitive operations require a valid JWT, which an attacker-controlled origin cannot obtain without the user's credentials.

### Rate Limiting

**None implemented.** There is no rate limiting on any endpoint, including `/auth/login` and `/auth/register`. A brute-force or credential-stuffing attack against the login endpoint is not prevented at the application layer. The Argon2id hash (~300 ms per attempt) provides a natural throttle at the cost of server CPU, but this is not a substitute for request-rate controls. This is a known limitation.

### SQL Injection

All database queries use **SQLAlchemy ORM** parameterised statements. Raw SQL is not used anywhere in the codebase. SQLAlchemy's query builder passes all user-supplied values as bound parameters, not interpolated strings.

### IDOR Prevention

The messages router returns **HTTP 404** (not 403) when a user requests a message they do not have access to. Returning 403 would confirm the message exists to an unauthorised requester; 404 leaks nothing. The same pattern applies to the message download and blockchain-proof endpoints.
