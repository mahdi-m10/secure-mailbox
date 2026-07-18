# Blockchain Deployment (Sepolia)

Live deployment record for the two blockchain-brief contracts, `KeyRegistry`
and `MessageReceipt`. The pre-existing `MessageDigest` contract is deployed
separately (via `scripts/deploy.js`) and is untouched by this deployment.

- **Network:** Ethereum **Sepolia** testnet (chainId **11155111**)
- **Toolchain:** Hardhat, Solidity 0.8.20 (optimizer on, 200 runs), ethers v6
- **Deploy script:** `blockchain/scripts/deploy-registry.js`
- **Explorer:** https://sepolia.etherscan.io

## Deployed contracts

| Contract | Address | Etherscan |
|---|---|---|
| `KeyRegistry` | `0x230c56Ab59535625c8eAeF18f8394b7D222a889D` | [address](https://sepolia.etherscan.io/address/0x230c56Ab59535625c8eAeF18f8394b7D222a889D) |
| `MessageReceipt` | `0x355557d9E5bd1188372986f3ad73b60D992Ef9e5` | [address](https://sepolia.etherscan.io/address/0x355557d9E5bd1188372986f3ad73b60D992Ef9e5) |
| `MessageDigest` | `0xc8ABe2E8fB438F9120ED63c22ed9074F586586f6` | [address](https://sepolia.etherscan.io/address/0xc8ABe2E8fB438F9120ED63c22ed9074F586586f6) |

### Deployment transactions

| Contract | Deployment tx |
|---|---|
| `KeyRegistry` | [`0x7bebd4cd…db9478ae`](https://sepolia.etherscan.io/tx/0x7bebd4cd6842daa61ce453f8c0539401da4896ef01e6a596dcf92875db9478ae) |
| `MessageReceipt` | [`0x256d66aa…f76fffab`](https://sepolia.etherscan.io/tx/0x256d66aaf0adf30ff76c08883625d9994378ca7711d9375759d03c2df76fffab) |

### ABIs

The compiled ABI for each contract is tracked in the repo (the rest of
`blockchain/artifacts/` is a gitignored build output):

- [`KeyRegistry.json`](../blockchain/artifacts/contracts/KeyRegistry.sol/KeyRegistry.json)
- [`MessageReceipt.json`](../blockchain/artifacts/contracts/MessageReceipt.sol/MessageReceipt.json)
- [`MessageDigest.json`](../blockchain/artifacts/contracts/MessageDigest.sol/MessageDigest.json)

## Roles

Both contracts set their privileged role to the **deployer wallet** in the
constructor:

- `KeyRegistry.registrar` — the only account that may `registerKey` /
  `rotateKey` / `revokeKey`.
- `MessageReceipt.server` — the only account that may `postReceipt`.

This is the server-custodial model from `crypto-design.md` §3(d)1: application
users hold no Ethereum wallets, so the mailbox server's wallet
(`DEPLOYER_PRIVATE_KEY`) acts on their behalf. The deployer address is the
`From` of the deployment transactions above and can be read back on-chain from
the `registrar()` / `server()` getters. It is intentionally **not** committed
to the repo.

## How each component is configured to use these addresses

| Component | Where | Value |
|---|---|---|
| Web client | `web-client/js/config.js` → `CHAIN.keyRegistryAddress` | KeyRegistry address is the built-in default; `localStorage['sm_chain_registry']` overrides it for local testing |
| C++ client | `cpp-client/include/Chain.hpp` → `ChainConfig::key_registry_address` | KeyRegistry address is the built-in default; `SECUREMAILBOX_KEY_REGISTRY` env var overrides it |
| Backend | `.env` (`KEY_REGISTRY_ADDRESS`, `MESSAGE_RECEIPT_ADDRESS`) | read by `backend/blockchain/registry.py` and `receipts.py`; see `.env.example` |

The clients read `KeyRegistry` **directly** over JSON-RPC (never through the
mailbox server), so a compromised server cannot answer its own integrity check
— see `crypto-design.md` §8.11. The RPC endpoint defaults to the public,
keyless node `https://ethereum-sepolia-rpc.publicnode.com`.

## Reproducing / redeploying

From `blockchain/`, with `SEPOLIA_RPC_URL` and `DEPLOYER_PRIVATE_KEY` set in
the repo-root `.env` (loaded by `hardhat.config.js` from `../.env`):

```bash
npx hardhat run scripts/preflight.js --network sepolia        # no-gas checks
npx hardhat run scripts/deploy-registry.js --network sepolia  # deploy both
```

`deploy-registry.js` prints the two addresses; copy them into `.env` as
`KEY_REGISTRY_ADDRESS` / `MESSAGE_RECEIPT_ADDRESS`, then update the client
defaults (this file's addresses). Redeploying mints **new** addresses; the old
ones remain on-chain forever (the registry is an append-only transparency log).

The on-chain lifecycle verification performed against this deployment is
recorded in [test-plan.md](test-plan.md).
