# Network Architecture

Network topology, transport security, external-service connections, and trust
boundaries for the Secure Mailbox. This document expands the summary diagram
in the project README.

## 1. Topology

```
 CLIENT DEVICES (trusted)     EDGE                   SERVER (untrusted)
 ┌──────────────────────┐   ┌──────────────────┐   ┌──────────────────────────┐
 │ Web client           │   │  TLS Gateway /   │   │  Ubuntu VM               │
 │ (Web Crypto API,     │──>│  reverse proxy   │──>│  FastAPI (uvicorn)       │
 │  served from /app)   │   │                  │   │   - /auth /users /files  │
 ├──────────────────────┤   │  team10...       │   │   - /app (web client)    │
 │ C++ CLI client       │──>│                  │   │   - SQLite DB (file)     │
 │ (libcurl + libsodium)│   │  HTTPS/TLS       │   │                          │
 └──────────┬───────────┘   └──────────────────┘   └────────────┬─────────────┘
            │                                                   │ HTTPS writes:
            │ HTTPS (eth_call reads, direct to chain)           │ keys, receipts, digests
            │                                                   v
            │               ┌─────────────────────────────────────────────────┐
            └──────────────>│  Ethereum Sepolia testnet                       │
                            │  MessageDigest / KeyRegistry /                  │
                            │  MessageReceipt contracts                       │
                            └─────────────────────────────────────────────────┘
```

## 2. Transport security (TLS)

- **Client ⇄ edge.** Both clients connect over HTTPS to the public virtual
  host `team10.theburkenator.com`.
  - Web client: the browser enforces TLS and certificate validity natively.
  - C++ client: libcurl with `CURLOPT_SSL_VERIFYPEER` and
    `CURLOPT_SSL_VERIFYHOST` **on by default**
    (`cpp-client/include/Client.hpp` — `verify_ssl{true}`;
    `cpp-client/src/Client.cpp` only disables them when `verify_ssl` is
    explicitly false, which is never set in normal operation). A forged or
    invalid certificate aborts the connection.
- **TLS termination.** TLS is terminated at the gateway / reverse proxy; the
  gateway forwards plain HTTP on port 80 to the FastAPI process on the same
  VM (loopback / private network segment). No untrusted network segment
  carries plaintext application traffic — the only cleartext hop is
  gateway→app inside the host boundary.
- **Application-layer E2EE is independent of TLS.** File contents are
  encrypted end-to-end (HPKE Mode_Auth, see `crypto-design.md`) before they
  ever reach TLS, so confidentiality does **not** depend on trusting the
  gateway or the server — TLS protects metadata and session tokens in
  transit, not file contents.

## 3. HTTP security controls (backend edge)

Set in `backend/main.py`:

| Control | Value | Purpose |
|---|---|---|
| CORS `allow_origins` | `https://team10.theburkenator.com` only | Blocks cross-origin browser calls from other sites |
| CORS `allow_credentials` | `false` | Tokens travel in the `Authorization` header, not cookies — no ambient credential replay |
| CORS `allow_methods` | `GET, POST, PUT, DELETE` | Least-privilege method set |
| Content-Security-Policy | `default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self' <gateway> https://ethereum-sepolia-rpc.publicnode.com` | Confines fetch/XHR/WebSocket targets to the app origin plus the declared Sepolia RPC — the `connect-src` entry is what permits the client-side on-chain key lookup. Note `'unsafe-inline'` on `script-src`: inline scripts are permitted, so this policy is **not** an XSS control (XSS is handled by output escaping — see `pentest-report.md` §4) |
| `X-Frame-Options` | `DENY` | Clickjacking |
| `X-Content-Type-Options` | `nosniff` | MIME sniffing |
| `Referrer-Policy` | `no-referrer` | Referrer leakage |
| Request-body cap | 16 MiB (`MAX_REQUEST_BODY_BYTES`) | Rejects oversize bodies before parsing (DoS) |

## 4. External service connections

| From | To | Transport | Purpose | Credential |
|---|---|---|---|---|
| Backend | Ethereum Sepolia RPC (`SEPOLIA_RPC_URL`) | HTTPS | **Writes**: register/rotate keys, post receipts, anchor digests | `DEPLOYER_PRIVATE_KEY` (registrar/server wallet) — env only, never committed |
| Web client | Sepolia public RPC (`ethereum-sepolia-rpc.publicnode.com`) | HTTPS | **Reads**: `eth_call` to `KeyRegistry.getKey` before encrypting | none (keyless public node) |
| C++ client | Sepolia public RPC (same) | HTTPS | Same read-path key lookup | none |
| Backend | SQLite database file (`secure_messenger.db` — the deployed file predates the naming cleanup; new deployments following `.env.example` create `secure_mailbox.db`) | local file I/O | Ciphertext + metadata store | filesystem perms |

Design note on the two RPC paths: the clients read the chain **directly**
over a keyless public node rather than proxying through the backend. This is
deliberate — if the on-chain key check were relayed by the server, a
compromised server could answer its own integrity check, defeating the point
of the transparency log (`crypto-design.md` §8.11). The backend's own
(write-side) RPC uses a keyed provider whose URL and private key live only in
the server's environment.

## 5. Trust boundaries

1. **Client device** — trusted. Holds the user's long-term X25519 private key
   (passphrase-encrypted at rest) and plaintext. The security of the whole
   system rests here.
2. **TLS gateway** — trusted for availability and TLS termination only; it
   sees ciphertext + metadata, never plaintext or private keys.
3. **Backend VM + database** — **untrusted** (the design's `(d)` threat class,
   `crypto-design.md` §3). Assumed potentially fully compromised: it stores
   only opaque AEAD blobs and public keys and cannot read plaintext or tamper
   undetectably. Sender forgery specifically is TOFU-pinned, not
   cryptographically excluded outright: for any pair that has already
   communicated, the server cannot substitute a sender's key undetectably
   (`crypto-design.md` §3(d)1); a server that substitutes a key before the
   pair's first contact is not caught by this mechanism. Access control
   (JWT + ownership checks) is a defence-in-depth layer on top of E2EE, not
   the primary confidentiality control.
4. **Ethereum Sepolia** — public, append-only ledger. Contains no secrets:
   only public keys, `keccak256(username)` identity hashes, and ciphertext
   digests. Serves as a transparency log the clients cross-check against.

## 6. Ports and hosts (summary)

| Endpoint | Host | Port | Protocol |
|---|---|---|---|
| Public application | `team10.theburkenator.com` | 443 | HTTPS |
| Gateway → app (internal) | loopback / private | 80 | HTTP |
| Web UI | `…/app` | 443 | HTTPS |
| API docs | `…/docs` | 443 | HTTPS |
| Sepolia RPC (public read) | `ethereum-sepolia-rpc.publicnode.com` | 443 | HTTPS |
