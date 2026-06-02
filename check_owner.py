"""
check_owner.py — Diagnose onlyOwner revert on the blockchain contract.

Prints:
  • The Ethereum address derived from DEPLOYER_PRIVATE_KEY
  • The address returned by contract.owner()
  • Whether they match (and what to do if they don't)

Run from the project root:
    python check_owner.py
"""

import os
import sys

from dotenv import load_dotenv
from web3 import Web3

load_dotenv()

RPC_URL          = os.getenv("SEPOLIA_RPC_URL", "")
PRIVATE_KEY      = os.getenv("DEPLOYER_PRIVATE_KEY", "")
CONTRACT_ADDRESS = os.getenv("CONTRACT_ADDRESS", "")

# owner() is not in the minimal ABI used by contract.py, so we add it here.
OWNER_ABI = [
    {
        "inputs": [],
        "name": "owner",
        "outputs": [{"internalType": "address", "name": "", "type": "address"}],
        "stateMutability": "view",
        "type": "function",
    },
]

# ── Validation ────────────────────────────────────────────────────────────────

missing = [k for k, v in [
    ("SEPOLIA_RPC_URL",      RPC_URL),
    ("DEPLOYER_PRIVATE_KEY", PRIVATE_KEY),
    ("CONTRACT_ADDRESS",     CONTRACT_ADDRESS),
] if not v]

if missing:
    print("ERROR: missing env vars:", ", ".join(missing))
    sys.exit(1)

# ── Connect ───────────────────────────────────────────────────────────────────

w3 = Web3(Web3.HTTPProvider(RPC_URL))
if not w3.is_connected():
    print(f"ERROR: cannot reach RPC endpoint: {RPC_URL}")
    sys.exit(1)

print(f"Connected : True  ({RPC_URL})")

# ── Derive signer address ─────────────────────────────────────────────────────

try:
    signer = w3.eth.account.from_key(PRIVATE_KEY)
    signer_address = signer.address
except Exception as exc:
    print(f"ERROR: could not derive address from DEPLOYER_PRIVATE_KEY: {exc}")
    sys.exit(1)

balance_wei = w3.eth.get_balance(signer_address)
balance_eth = w3.from_wei(balance_wei, "ether")
print(f"Signer    : {signer_address}  (balance: {balance_eth:.4f} ETH)")

# ── Query contract owner ──────────────────────────────────────────────────────

try:
    checksum = Web3.to_checksum_address(CONTRACT_ADDRESS)
    contract = w3.eth.contract(address=checksum, abi=OWNER_ABI)
    owner_address = contract.functions.owner().call()
except Exception as exc:
    print(f"ERROR: could not call owner() on {CONTRACT_ADDRESS}: {exc}")
    print("       (Is the contract address correct? Does it implement Ownable?)")
    sys.exit(1)

print(f"Owner     : {owner_address}  (from contract.owner())")

# ── Verdict ───────────────────────────────────────────────────────────────────

print()
if signer_address.lower() == owner_address.lower():
    print("MATCH  -- signer IS the contract owner.")
    print("The onlyOwner revert has a different cause.")
    print("Check: gas limit, contract paused state, or hash format.")
else:
    print("MISMATCH -- signer is NOT the contract owner.")
    print()
    print("Fix options:")
    print()
    print("  Option A -- update DEPLOYER_PRIVATE_KEY in the VM .env")
    print("    Use the private key that corresponds to:")
    print(f"      {owner_address}")
    print()
    print("  Option B -- transfer contract ownership to the VM's signer")
    print("    From the original deployer wallet, call:")
    print(f"      contract.transferOwnership('{signer_address}')")
    print("    (requires the original deployer's private key to sign the tx)")
