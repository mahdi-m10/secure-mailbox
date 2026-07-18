"""Web3 interface for the KeyRegistry smart contract on Sepolia.

Server-custodial registrar model: application users hold no Ethereum
wallets, so the mailbox server's own wallet (DEPLOYER_PRIVATE_KEY, the same
key used for MessageDigest/MessageReceipt) posts registrations on their
behalf. Identities are keccak256(username); keys are raw 32-byte X25519
public keys.

Trust-model reminder (see docs/crypto-design.md §3(d)1, §8.1, §8.11): this
makes the registry a PUBLIC TRANSPARENCY LOG, not a trustless PKI. A
compromised server can still post whatever it wants, but it cannot do so
invisibly — every registration and rotation is a permanent, publicly
readable event.
"""

import logging
import os

from dotenv import load_dotenv
from web3 import Web3
from web3.exceptions import ContractLogicError

from backend.blockchain._send_lock import SEND_LOCK, advance_nonce, allocate_nonce

load_dotenv()

logger = logging.getLogger(__name__)

_RPC_URL: str = os.getenv("SEPOLIA_RPC_URL", "")
_PRIVATE_KEY: str = os.getenv("DEPLOYER_PRIVATE_KEY", "")
_CONTRACT_ADDRESS: str = os.getenv("KEY_REGISTRY_ADDRESS", "")

# Minimal ABI — only the functions and events actually used here.
_ABI = [
    {
        "inputs": [
            {"internalType": "bytes32", "name": "identity", "type": "bytes32"},
            {"internalType": "bytes32", "name": "x25519Key", "type": "bytes32"},
        ],
        "name": "registerKey",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [
            {"internalType": "bytes32", "name": "identity", "type": "bytes32"},
            {"internalType": "bytes32", "name": "newX25519Key", "type": "bytes32"},
        ],
        "name": "rotateKey",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [{"internalType": "bytes32", "name": "identity", "type": "bytes32"}],
        "name": "revokeKey",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [{"internalType": "bytes32", "name": "identity", "type": "bytes32"}],
        "name": "getKey",
        "outputs": [
            {"internalType": "bytes32", "name": "x25519Key", "type": "bytes32"},
            {"internalType": "uint32", "name": "version", "type": "uint32"},
            {"internalType": "uint64", "name": "updatedAt", "type": "uint64"},
            {"internalType": "bool", "name": "revoked", "type": "bool"},
        ],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "internalType": "bytes32", "name": "identity", "type": "bytes32"},
            {"indexed": False, "internalType": "bytes32", "name": "x25519Key", "type": "bytes32"},
            {"indexed": False, "internalType": "uint32", "name": "version", "type": "uint32"},
            {"indexed": False, "internalType": "uint256", "name": "timestamp", "type": "uint256"},
        ],
        "name": "KeyRegistered",
        "type": "event",
    },
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "internalType": "bytes32", "name": "identity", "type": "bytes32"},
            {"indexed": False, "internalType": "uint32", "name": "version", "type": "uint32"},
            {"indexed": False, "internalType": "uint256", "name": "timestamp", "type": "uint256"},
        ],
        "name": "KeyRevoked",
        "type": "event",
    },
]


def _connect() -> tuple[Web3, object]:
    """Return a connected (Web3, contract) pair, raising on misconfiguration."""
    if not _RPC_URL:
        raise EnvironmentError("SEPOLIA_RPC_URL is not set")
    if not _CONTRACT_ADDRESS:
        raise EnvironmentError("KEY_REGISTRY_ADDRESS is not set")

    w3 = Web3(Web3.HTTPProvider(_RPC_URL))
    if not w3.is_connected():
        raise ConnectionError(f"Cannot reach RPC endpoint: {_RPC_URL}")

    checksum = Web3.to_checksum_address(_CONTRACT_ADDRESS)
    contract = w3.eth.contract(address=checksum, abi=_ABI)
    return w3, contract


def identity_hash(username: str) -> bytes:
    """The one place the identity scheme lives: keccak256(username)."""
    return Web3.keccak(text=username)


def _key_to_bytes32(x25519_key_b64: str) -> bytes:
    import base64

    raw = base64.b64decode(x25519_key_b64)
    if len(raw) != 32:
        raise ValueError(f"X25519 public key must be 32 bytes; got {len(raw)}")
    return raw


def _send(contract_fn) -> str:
    """Sign, send, and wait for a state-changing call; return the tx hash."""
    w3, _ = _connect()
    account = w3.eth.account.from_key(_PRIVATE_KEY)

    # Nonce allocation + broadcast must be atomic across all three
    # contracts' senders sharing this wallet, and immune to stale
    # pending-count reads from a load-balanced RPC — see _send_lock.py.
    with SEND_LOCK:
        nonce = allocate_nonce(w3, account.address)
        tx = contract_fn.build_transaction(
            {
                "from": account.address,
                "nonce": nonce,
                "gas": 200_000,
                "gasPrice": w3.eth.gas_price,
            }
        )
        signed = w3.eth.account.sign_transaction(tx, _PRIVATE_KEY)
        tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
        advance_nonce(account.address, nonce)

    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)

    if receipt["status"] != 1:
        raise RuntimeError("Transaction reverted — check contract state")

    return "0x" + tx_hash.hex()


def register_or_rotate_key(username: str, x25519_key_b64: str) -> str:
    """Register a new identity, or rotate an existing one's key.

    The contract has two distinct calls with mutually exclusive
    preconditions (registerKey requires the identity be new; rotateKey
    requires it already exist), so this function reads the current
    on-chain state first and picks the right one — the same
    "upload or replace" shape POST /users/keys already presents to callers.

    Raises:
        EnvironmentError: Missing env vars.
        ValueError: Bad key format, or the contract rejected the call
            (e.g. rotating to an identical key).
        RuntimeError: Transaction reverted or network error.
    """
    if not _PRIVATE_KEY:
        raise EnvironmentError("DEPLOYER_PRIVATE_KEY is not set")

    key_bytes = _key_to_bytes32(x25519_key_b64)
    identity = identity_hash(username)

    try:
        _, contract = _connect()
        _, version, _, _ = contract.functions.getKey(identity).call()

        if version == 0:
            fn = contract.functions.registerKey(identity, key_bytes)
        else:
            fn = contract.functions.rotateKey(identity, key_bytes)

        return _send(fn)

    except ContractLogicError as exc:
        raise ValueError(f"Contract rejected the key registration: {exc}") from exc
    except (EnvironmentError, ValueError):
        raise
    except Exception as exc:
        raise RuntimeError(f"Failed to register/rotate key on-chain: {exc}") from exc


def revoke_key(username: str) -> str:
    """Mark *username*'s current on-chain key as revoked.

    Not wired to any endpoint yet — no "delete my key" flow exists in the
    application. Included so the contract's full surface is exercised from
    Python and available when that flow is added.
    """
    if not _PRIVATE_KEY:
        raise EnvironmentError("DEPLOYER_PRIVATE_KEY is not set")

    identity = identity_hash(username)
    try:
        _, contract = _connect()
        return _send(contract.functions.revokeKey(identity))
    except ContractLogicError as exc:
        raise ValueError(f"Contract rejected the revocation: {exc}") from exc
    except (EnvironmentError, ValueError):
        raise
    except Exception as exc:
        raise RuntimeError(f"Failed to revoke key on-chain: {exc}") from exc


def get_onchain_key(username: str) -> dict:
    """Look up *username*'s on-chain key record.

    Returns:
        Dict with keys:
            registered — True if version > 0
            version    — int, 0 if never registered
            key_b64    — base64 of the 32-byte X25519 key, or None
            updated_at — Unix timestamp (int), or None
            revoked    — bool

    Raises:
        EnvironmentError: Missing env vars.
        RuntimeError: Network or call failure.
    """
    import base64

    identity = identity_hash(username)
    try:
        _, contract = _connect()
        key_bytes, version, updated_at, revoked = contract.functions.getKey(identity).call()

        if version == 0:
            return {
                "registered": False, "version": 0,
                "key_b64": None, "updated_at": None, "revoked": False,
            }
        return {
            "registered": True,
            "version": version,
            "key_b64": base64.b64encode(key_bytes).decode(),
            "updated_at": updated_at,
            "revoked": revoked,
        }
    except EnvironmentError:
        raise
    except Exception as exc:
        raise RuntimeError(f"Failed to read key registry: {exc}") from exc


def submit_key_registration_background(user_id: int, username: str, public_key_b64: str) -> None:
    """Register or rotate *username*'s on-chain key. Intended to be run in a
    daemon thread (by both POST /auth/register and POST /users/keys) so
    neither request is delayed by an RPC round trip.

    Never raises — logs and returns on any failure, mirroring
    routers/files.py's _submit_to_chain.
    """
    from backend.database import SessionLocal

    try:
        tx_hash = register_or_rotate_key(username, public_key_b64)
        logger.info("user %s: key registered/rotated on-chain: %s", username, tx_hash)
    except EnvironmentError as exc:
        logger.error("user %s: blockchain env vars not configured: %r", username, exc)
        return
    except (ValueError, RuntimeError) as exc:
        logger.error("user %s: failed to register/rotate key on-chain: %r", username, exc)
        return
    except Exception as exc:
        logger.error("user %s: unexpected error registering key on-chain: %r", username, exc)
        return

    try:
        with SessionLocal() as db:
            from backend import models

            user = db.get(models.User, user_id)
            if user:
                user.eth_key_tx = tx_hash
                db.commit()
    except Exception as exc:
        logger.error("user %s: failed to persist eth_key_tx=%r: %r", username, tx_hash, exc)
