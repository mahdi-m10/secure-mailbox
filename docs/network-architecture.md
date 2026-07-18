# Network Architecture

Network topology, transport security, external-service connections, and trust
boundaries for the Secure Mailbox. This document expands the summary diagram
in the project README.

## 1. Topology

```
   CLIENT DEVICES (trusted)                EDGE                 SERVER (untrusted)
 ┌──────────────────────┐                                   ┌────────────────────────┐
 │ Web client           │                                   │  Ubuntu VM             │
 │ (Web Crypto API,     │──── HTTPS/TLS ─┐   ┌── HTTP :80 ──▶│  FastAPI (uvicorn)     │
 │  served from /app)   │                │   │               │  ├─ /auth /users /files│
 └──────────────────────┘         ┌──────▼───┴─────────┐     │  ├─ /app (web client)  │
 ┌──────────────────────┐         │  TLS Gateway /      │     │  └─ SQLite DB (file)   │
 │ C++ CLI client       │──── HTTPS/TLS ─▶ reverse proxy│     └───────────┬────────────┘
 │ (libcurl + libsodium)│         │  team10.theburken…  │                 │ HTTPS
 └──────────┬───────────┘         └─────────────────────┘                 │ (write: register/
            │ HTTPS (read: eth_call)                                      │  rotate/receipt/
            │                                                             │  digest)
            └───────────────┐                            ┌────────────────▼────────────┐
                            └──── HTTPS (read: eth_call) ▶│  Ethereum Sepolia testnet    │
                                                          │  MessageDigest / KeyRegistry │
   Web client also reads the chain directly ────────────▶│  / MessageReceipt contracts  │
   (connect-src allows the public RPC)                   └──────────────────────────────┘
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
  transit, not message contents.

## 3. HTTP security controls (backend edge)

Set in `backend/main.py`:

| Control | Value | Purpose |
|---|---|---|
| CORS `allow_origins` | `https://team10.theburkenator.com` only | Blocks cross-origin browser calls from other sites |
| CORS `allow_credentials` | `false` | Tokens travel in the `Authorization` header, not cookies — no ambient credential replay |
| CORS `allow_methods` | `GET, POST, PUT, DELETE` | Least-privilege method set |
| Content-Security-Policy | `default-src 'self'`; `connect-src 'self' <gateway> https://ethereum-sepolia-rpc.publicnode.com` | Restricts script/style/connect origins; the explicit Sepolia RPC entry is what permits the client-side on-chain key lookup |
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
| Backend | SQLite database file (`secure_messenger.db`) | local file I/O | Ciphertext + metadata store | filesystem perms |

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
   only opaque AEAD blobs and public keys, and cannot read plaintext, forge a
   sender, or tamper undetectably. Access control (JWT + ownership checks) is
   a defence-in-depth layer on top of E2EE, not the primary confidentiality
   control.
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
