"""Web3 interface for the MessageDigest smart contract on Sepolia."""

import os

from dotenv import load_dotenv
from web3 import Web3
from web3.exceptions import ContractLogicError

load_dotenv()

_RPC_URL: str = os.getenv("SEPOLIA_RPC_URL", "")
_PRIVATE_KEY: str = os.getenv("DEPLOYER_PRIVATE_KEY", "")
_CONTRACT_ADDRESS: str = os.getenv("CONTRACT_ADDRESS", "")

# Minimal ABI — only the functions and events actually used here.
_ABI = [
    {
        "inputs": [{"internalType": "bytes32", "name": "hash", "type": "bytes32"}],
        "name": "recordHash",
        "outputs": [{"internalType": "uint256", "name": "index", "type": "uint256"}],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [{"internalType": "uint256", "name": "index", "type": "uint256"}],
        "name": "getDigest",
        "outputs": [
            {"internalType": "bytes32", "name": "hash", "type": "bytes32"},
            {"internalType": "uint256", "name": "timestamp", "type": "uint256"},
            {"internalType": "address", "name": "recorder", "type": "address"},
        ],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [{"internalType": "bytes32", "name": "hash", "type": "bytes32"}],
        "name": "getIndexByHash",
        "outputs": [
            {"internalType": "uint256", "name": "index", "type": "uint256"},
            {"internalType": "bool", "name": "exists", "type": "bool"},
        ],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "internalType": "uint256", "name": "index", "type": "uint256"},
            {"indexed": True, "internalType": "bytes32", "name": "hash", "type": "bytes32"},
            {"indexed": True, "internalType": "address", "name": "recorder", "type": "address"},
            {"indexed": False, "internalType": "uint256", "name": "timestamp", "type": "uint256"},
        ],
        "name": "HashRecorded",
        "type": "event",
    },
]


def _connect() -> tuple[Web3, object]:
    """Return a connected (Web3, contract) pair, raising on misconfiguration."""
    if not _RPC_URL:
        raise EnvironmentError("SEPOLIA_RPC_URL is not set")
    if not _CONTRACT_ADDRESS:
        raise EnvironmentError("CONTRACT_ADDRESS is not set")

    w3 = Web3(Web3.HTTPProvider(_RPC_URL))
    if not w3.is_connected():
        raise ConnectionError(f"Cannot reach RPC endpoint: {_RPC_URL}")

    checksum = Web3.to_checksum_address(_CONTRACT_ADDRESS)
    contract = w3.eth.contract(address=checksum, abi=_ABI)
    return w3, contract


def _normalise_hash(message_hash: str) -> bytes:
    """Convert a 0x-prefixed or bare 64-char hex string to 32 bytes."""
    h = message_hash if message_hash.startswith("0x") else f"0x{message_hash}"
    hex_part = h[2:]
    if len(hex_part) != 64:
        raise ValueError(
            f"Expected 64 hex chars (32 bytes); got {len(hex_part)}: {hex_part!r}"
        )
    return bytes.fromhex(hex_part)


def record_message_digest(message_hash: str) -> str:
    """
    Anchor a keccak256 message digest on the Sepolia chain.

    Args:
        message_hash: Hex string (with or without 0x prefix) of the 32-byte hash.

    Returns:
        Transaction hash as a 0x-prefixed hex string.

    Raises:
        EnvironmentError: Missing env vars.
        ValueError: Bad hash format or hash already recorded.
        RuntimeError: Transaction reverted or network error.
    """
    if not _PRIVATE_KEY:
        raise EnvironmentError("DEPLOYER_PRIVATE_KEY is not set")

    hash_bytes = _normalise_hash(message_hash)

    try:
        w3, contract = _connect()
        account = w3.eth.account.from_key(_PRIVATE_KEY)
        nonce = w3.eth.get_transaction_count(account.address, "pending")

        tx = contract.functions.recordHash(hash_bytes).build_transaction(
            {
                "from": account.address,
                "nonce": nonce,
                "gas": 300_000,
                "gasPrice": w3.eth.gas_price,
            }
        )
        signed = w3.eth.account.sign_transaction(tx, _PRIVATE_KEY)
        tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)

        if receipt["status"] != 1:
            raise RuntimeError("Transaction reverted — check contract state")

        return "0x" + tx_hash.hex()

    except ContractLogicError as exc:
        raise ValueError(f"Contract rejected the hash: {exc}") from exc
    except (EnvironmentError, ValueError):
        raise
    except Exception as exc:
        raise RuntimeError(f"Failed to record digest: {exc}") from exc


def verify_hash_on_chain(message_hash: str) -> dict:
    """
    Check whether a keccak256 hash is recorded on Sepolia and return its details.

    Args:
        message_hash: Hex string (with or without 0x prefix) of the 32-byte hash.

    Returns:
        Dict with keys:
            exists    — True if the hash is found in the contract
            index     — contract array index (int), or None
            hash      — 0x-prefixed hex of the stored bytes32, or None
            timestamp — Unix timestamp (int), or None
            recorder  — Ethereum address (str), or None

    Raises:
        EnvironmentError: Missing env vars.
        RuntimeError: Network or call failure.
    """
    hash_bytes = _normalise_hash(message_hash)
    try:
        _, contract = _connect()
        index, exists = contract.functions.getIndexByHash(hash_bytes).call()
        if not exists:
            return {"exists": False, "index": None, "hash": None, "timestamp": None, "recorder": None}
        stored_hash, timestamp, recorder = contract.functions.getDigest(index).call()
        return {
            "exists": True,
            "index": index,
            "hash": "0x" + stored_hash.hex(),
            "timestamp": timestamp,
            "recorder": recorder,
        }
    except ContractLogicError as exc:
        raise ValueError(f"Contract call failed: {exc}") from exc
    except EnvironmentError:
        raise
    except Exception as exc:
        raise RuntimeError(f"Failed to verify hash on chain: {exc}") from exc


def get_transaction_hash(index: int) -> dict:
    """
    Retrieve a stored digest entry by its zero-based index.

    Args:
        index: Zero-based position of the digest in the contract's array.

    Returns:
        Dict with keys:
            hash      — 0x-prefixed hex string of the stored bytes32
            timestamp — Unix timestamp (int) of the block that recorded it
            recorder  — Ethereum address that called recordHash

    Raises:
        EnvironmentError: Missing env vars.
        IndexError: Index is out of bounds.
        RuntimeError: Network or call failure.
    """
    try:
        _, contract = _connect()
        stored_hash, timestamp, recorder = contract.functions.getDigest(index).call()
        return {
            "hash": "0x" + stored_hash.hex(),
            "timestamp": timestamp,
            "recorder": recorder,
        }
    except ContractLogicError as exc:
        raise IndexError(f"Index {index} is out of bounds: {exc}") from exc
    except EnvironmentError:
        raise
    except Exception as exc:
        raise RuntimeError(f"Failed to retrieve digest at index {index}: {exc}") from exc
