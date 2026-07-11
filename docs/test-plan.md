# Blockchain Test Plan & On-Chain Verification

Test plan for the `KeyRegistry` and `MessageReceipt` contracts and their
deployment, plus the **actual results** of exercising the full lifecycle on
Sepolia. Deployment addresses and Etherscan links are in
[deployment.md](deployment.md).

## What is being verified

The contracts encode a small set of invariants that the clients depend on
(`crypto-design.md` §8.11). Each is checked by driving the live contract and
reading the resulting on-chain state back:

1. **Register** a new identity → record at `version = 1`, `revoked = false`.
2. **Rotate** an existing identity → `version` bumps to 2, key replaced,
   `revoked = false`; history is re-emitted, never deleted.
3. **Revoke** → record **preserved** (key + version intact) with
   `revoked = true`, so clients distinguish "revoked" from "never registered".
4. **Post receipt** for a ciphertext hash → `getReceipt` reads back
   `exists = true` with the stored sender/recipient hashes.
5. Access control: only the registrar/server wallet can mutate state
   (enforced by `onlyRegistrar` / `onlyServer`; covered by the Hardhat unit
   tests in `blockchain/test/`).

## Test layers

| Layer | Where | Purpose |
|---|---|---|
| Unit tests | `blockchain/test/` (`npx hardhat test`) | Contract logic incl. revert paths (access control, double-register, revoke-unregistered, receipt replay) |
| Local smoke test | `scripts/{deploy-registry,register-key,rotate-key,revoke-key,post-receipt}.js` against a throwaway `npx hardhat node` | Prove the interaction scripts drive the contracts correctly with **zero gas** before touching Sepolia |
| Live verification | Same scripts, `--network sepolia` | Exercise the real deployment end-to-end on the public testnet |

### Pre-flight (no gas)

`scripts/preflight.js --network sepolia` confirms the RPC is reachable, the
deployer key is loaded, the network is Sepolia (chainId 11155111), and the
wallet is funded — so a misconfiguration fails before any transaction is sent.

### Local smoke test (pre-Sepolia)

Before the live run, the full sequence was executed against a local Hardhat
node. All five steps behaved to spec — register → v1, rotate → v2, revoke →
v2 + `revoked=true`, receipt → `exists=true` — confirming the scripts and
decode logic were correct independent of the network.

## Live Sepolia results

Contracts under test (see [deployment.md](deployment.md)):

- `KeyRegistry` — `0x230c56Ab59535625c8eAeF18f8394b7D222a889D`
- `MessageReceipt` — `0x355557d9E5bd1188372986f3ad73b60D992Ef9e5`

Identities are `keccak256(username)`:

| Username | Identity hash |
|---|---|
| `alice` | `0x9c0257114eb9399a2985f8e75dad7600c5d89fe3824ffa99ec1c3eb8bf3b0501` |
| `bob` | `0x38e47a7b719dce63662aeaf43440326f551b8a7ee198cee35cb5d517f2d296a2` |
| `charlie` | `0x87a213ce1ee769e28decedefb98f6fe48890a74ba84957ebf877fb591e37e0de` |

### Key lifecycle — identity `alice`

| Step | Expected | Observed | Block | Transaction |
|---|---|---|---|---|
| Register | `version=1`, `revoked=false` | `version=1` ✓ | 11250901 | [`0x890293…94ae5c6`](https://sepolia.etherscan.io/tx/0x8902939b7facfc2ccf634dd90eb550ae13866d9106b2daec5e85dfbb994ae5c6) |
| Rotate | `version=2`, new key, `revoked=false` | `version=2` ✓ | 11250904 | [`0x0fe55c…599be2a2`](https://sepolia.etherscan.io/tx/0x0fe55cd2abea6f27c719be109d20bc13a0e59a1aa0aa5cf1d222c57c599be2a2) |
| Revoke | record preserved, `revoked=true` | `revoked=true`, `version` still 2 ✓ | 11250906 | [`0xcb09f5…4b3f2897e`](https://sepolia.etherscan.io/tx/0xcb09f56a764f808a9528b52b66fe7a08b2436af0c0ec0215be955e74b3f2897e) |

### Receipt — sender `bob` → recipient `charlie`

| Step | Expected | Observed | Block | Transaction |
|---|---|---|---|---|
| Post receipt | `getReceipt.exists=true` | `exists=true` ✓ | 11250908 | [`0xc93ca1…4a61a9165f`](https://sepolia.etherscan.io/tx/0xc93ca15ef162dd7820043b430eae9ce49b177a2c8f73ef20976a5e4a61a9165f) |

### Outcome

All four live transactions confirmed (`status = 1`) and every read-back
matched the expected on-chain state. The register→rotate→revoke progression on
a single identity demonstrates the transparency-log invariants the client-side
pre-encrypt gate relies on: a rotation is a publicly visible version bump, and
a revocation stays readable so a sender is blocked from encrypting to a revoked
key (`crypto-design.md` §8.11(g)).

## Reproducing

From `blockchain/`, addresses set in the repo-root `.env` (see
[deployment.md](deployment.md)):

```bash
npx hardhat run scripts/register-key.js  --network sepolia
npx hardhat run scripts/rotate-key.js    --network sepolia
npx hardhat run scripts/revoke-key.js    --network sepolia
npx hardhat run scripts/post-receipt.js  --network sepolia
```

Identities/usernames are overridable via `REGISTRY_USERNAME`,
`RECEIPT_SENDER`, and `RECEIPT_RECIPIENT`. Each script prints the tx hash,
mined block, and the post-transaction `getKey` / `getReceipt` read-back. Note
that `registerKey` reverts on an already-registered identity, so re-running the
lifecycle against the same deployment requires a fresh username.
