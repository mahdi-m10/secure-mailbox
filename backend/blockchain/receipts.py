"""Web3 interface for the MessageReceipt smart contract on Sepolia.

After the server accepts an encrypted file, it posts a signed receipt keyed
by the ciphertext's keccak256 hash (the same integrity_hash computed for
MessageDigest). See docs/crypto-design.md §8.11 for exactly what a receipt
does and does not prove: it is non-repudiable evidence the server accepted
this ciphertext at this time; it is not a guarantee the server will keep
serving it.
"""

import os

from dotenv import load_dotenv
from web3 import Web3
from web3.exceptions import ContractLogicError

from backend.blockchain._send_lock import SEND_LOCK, advance_nonce, allocate_nonce
from backend.blockchain.registry import identity_hash

load_dotenv()

_RPC_URL: str = os.getenv("SEPOLIA_RPC_URL", "")
_PRIVATE_KEY: str = os.getenv("DEPLOYER_PRIVATE_KEY", "")
_CONTRACT_ADDRESS: str = os.getenv("MESSAGE_RECEIPT_ADDRESS", "")

_ABI = [
    {
        "inputs": [
            {"internalType": "bytes32", "name": "ciphertextHash", "type": "bytes32"},
            {"internalType": "bytes32", "name": "senderHash", "type": "bytes32"},
            {"internalType": "bytes32", "name": "recipientHash", "type": "bytes32"},
        ],
        "name": "postReceipt",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [{"internalType": "bytes32", "name": "ciphertextHash", "type": "bytes32"}],
        "name": "getReceipt",
        "outputs": [
            {"internalType": "bool", "name": "exists", "type": "bool"},
            {"internalType": "bytes32", "name": "senderHash", "type": "bytes32"},
            {"internalType": "bytes32", "name": "recipientHash", "type": "bytes32"},
            {"internalType": "uint64", "name": "timestamp", "type": "uint64"},
            {"internalType": "uint64", "name": "blockNumber", "type": "uint64"},
        ],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "internalType": "bytes32", "name": "ciphertextHash", "type": "bytes32"},
            {"indexed": True, "internalType": "bytes32", "name": "senderHash", "type": "bytes32"},
            {"indexed": True, "internalType": "bytes32", "name": "recipientHash", "type": "bytes32"},
            {"indexed": False, "internalType": "uint256", "name": "timestamp", "type": "uint256"},
        ],
        "name": "ReceiptPosted",
        "type": "event",
    },
]


def _connect() -> tuple[Web3, object]:
    if not _RPC_URL:
        raise EnvironmentError("SEPOLIA_RPC_URL is not set")
    if not _CONTRACT_ADDRESS:
        raise EnvironmentError("MESSAGE_RECEIPT_ADDRESS is not set")

    w3 = Web3(Web3.HTTPProvider(_RPC_URL))
    if not w3.is_connected():
        raise ConnectionError(f"Cannot reach RPC endpoint: {_RPC_URL}")

    checksum = Web3.to_checksum_address(_CONTRACT_ADDRESS)
    contract = w3.eth.contract(address=checksum, abi=_ABI)
    return w3, contract


def _normalise_hash(hex_hash: str) -> bytes:
    """Convert a 0x-prefixed or bare 64-char hex string to 32 bytes."""
    h = hex_hash if hex_hash.startswith("0x") else f"0x{hex_hash}"
    hex_part = h[2:]
    if len(hex_part) != 64:
        raise ValueError(f"Expected 64 hex chars (32 bytes); got {len(hex_part)}: {hex_part!r}")
    return bytes.fromhex(hex_part)


def post_receipt(ciphertext_hash_hex: str, sender_username: str, recipient_username: str) -> str:
    """Post the inclusion receipt for an accepted ciphertext.

    Raises:
        EnvironmentError: Missing env vars.
        ValueError: Bad hash format, or a receipt already exists for this hash.
        RuntimeError: Transaction reverted or network error.
    """
    if not _PRIVATE_KEY:
        raise EnvironmentError("DEPLOYER_PRIVATE_KEY is not set")

    ct_hash = _normalise_hash(ciphertext_hash_hex)
    sender_hash = identity_hash(sender_username)
    recipient_hash = identity_hash(recipient_username)

    try:
        w3, contract = _connect()
        account = w3.eth.account.from_key(_PRIVATE_KEY)

        # Nonce allocation + broadcast must be atomic across all three
        # contracts' senders sharing this wallet, and immune to stale
        # pending-count reads from a load-balanced RPC — see _send_lock.py.
        with SEND_LOCK:
            nonce = allocate_nonce(w3, account.address)
            tx = contract.functions.postReceipt(
                ct_hash, sender_hash, recipient_hash
            ).build_transaction(
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

    except ContractLogicError as exc:
        raise ValueError(f"Contract rejected the receipt: {exc}") from exc
    except (EnvironmentError, ValueError):
        raise
    except Exception as exc:
        raise RuntimeError(f"Failed to post receipt: {exc}") from exc


def get_receipt(ciphertext_hash_hex: str) -> dict:
    """Look up the on-chain receipt for a ciphertext hash.

    Returns:
        Dict with keys:
            exists         — bool
            sender_hash    — "0x..." hex, or None
            recipient_hash — "0x..." hex, or None
            timestamp      — Unix timestamp (int), or None
            block_number   — int, or None

    Raises:
        EnvironmentError: Missing env vars.
        RuntimeError: Network or call failure.
    """
    ct_hash = _normalise_hash(ciphertext_hash_hex)
    try:
        _, contract = _connect()
        exists, sender_hash, recipient_hash, timestamp, block_number = (
            contract.functions.getReceipt(ct_hash).call()
        )
        if not exists:
            return {
                "exists": False, "sender_hash": None, "recipient_hash": None,
                "timestamp": None, "block_number": None,
            }
        return {
            "exists": True,
            "sender_hash": "0x" + sender_hash.hex(),
            "recipient_hash": "0x" + recipient_hash.hex(),
            "timestamp": timestamp,
            "block_number": block_number,
        }
    except EnvironmentError:
        raise
    except Exception as exc:
        raise RuntimeError(f"Failed to read receipt: {exc}") from exc
