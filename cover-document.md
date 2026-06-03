# Project Submission — Cover Document

---

## Group Information

| Field | Details |
|-------|---------|
| **Group name** | Team10 |
| **Project URL** | <https://team10.theburkenator.com/app/> |
| **GitHub repository** | <https://github.com/mahdi-m10/secure-messenger> |

---

## Team Members

| Full Name | Student ID | Contribution |
|-----------|------------|--------------|
| Mahdi Mirzay | 24401927 | 100% |

> **Note:** This project was completed individually by Mahdi Mirzay.

---

## Contribution Breakdown

All design, implementation, testing, and deployment was carried out solely by Mahdi Mirzay.

| Component | Description |
|-----------|-------------|
| **Backend** | FastAPI application — authentication (JWT, Argon2id), message routing, access control (send, inbox, download, forward, revoke), SQLAlchemy models, SQLite database |
| **Cryptography** | Manual HPKE Mode\_Auth implementation (RFC 9180) over X25519 + HKDF-SHA256 + AES-256-GCM; standalone AES-256-GCM helpers; Argon2id password hashing |
| **Web frontend** | Browser client (HTML/CSS/JavaScript) using the Web Crypto API — login/registration, encrypted messaging UI, blockchain proof verification page |
| **C++ CLI client** | Command-line client built with CMake; libcurl for HTTP transport; libsodium for Curve25519 key generation and ChaCha20-Poly1305 message encryption |
| **Blockchain** | `MessageDigest` Solidity contract (Sepolia testnet) — append-only keccak256 hash registry; Hardhat deployment pipeline; Web3.py backend integration for anchoring and verifying message digests |
| **VM deployment** | Production deployment on Ubuntu VM — uvicorn serving the API and static web client over port 80 at `team10.theburkenator.com` |

---

## Smart Contract

| Field | Value |
|-------|-------|
| **Network** | Ethereum Sepolia testnet |
| **Contract address** | `0xc8ABe2E8fB438F9120ED63c22ed9074F586586f6` |
| **Etherscan** | <https://sepolia.etherscan.io/address/0xc8ABe2E8fB438F9120ED63c22ed9074F586586f6> |
