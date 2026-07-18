"""Process-wide nonce serialization for the registrar/deployer wallet shared
by MessageDigest, KeyRegistry, and MessageReceipt.

Every write to any of the three contracts is signed by the same server
wallet. Two distinct races both manifest as a rejected broadcast:

1. **In-process thread race** ("nonce too low"). Multiple background
   threads fire in close succession — a single upload starts a
   MessageDigest anchor thread and a MessageReceipt thread — and each
   reads ``get_transaction_count(..., "pending")`` before broadcasting.
   The read and the broadcast are not atomic, so two sends built from the
   same nonce race. Observed during B2 integration testing against a
   local Hardhat node. Fixed by SEND_LOCK: hold it across
   nonce-read → build → sign → broadcast, and release it before the
   ~15-30 s confirmation wait so unrelated sends are not serialized.

2. **Stale-read race on a load-balanced RPC** ("replacement transaction
   underpriced"). Public RPC endpoints are clusters; two requests through
   one URL can hit backends with inconsistent mempool views. A send can
   therefore read a pending count that does not yet include a transaction
   this same process broadcast moments earlier, reuse its nonce, and be
   rejected as an underpriced replacement. Observed in production against
   Sepolia with a single process and a single wallet. SEND_LOCK cannot
   fix this — the stale value comes from outside the process — so
   ``allocate_nonce`` additionally keeps a per-address cache of the next
   nonce this process expects to use and takes
   ``max(chain_pending, cached)``.

Cache-staleness guard: the cache's only job is to bridge the propagation
window (seconds) between our broadcast and every backend seeing it. If a
broadcast transaction is later dropped from the mempool without mining,
a cached value above the real chain nonce would wedge every future send
behind a nonce gap — so entries expire after CACHE_TTL_SECONDS and the
allocator falls back to the chain's answer. A 120 s TTL is orders of
magnitude above any propagation window while bounding a wedge to two
minutes.

Usage (all three send sites follow this shape)::

    with SEND_LOCK:
        nonce = allocate_nonce(w3, account.address)
        ...build, sign...
        tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
        advance_nonce(account.address, nonce)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)

``advance_nonce`` runs only after a successful broadcast — if the node
rejects the send, the nonce was not consumed and the cache must not move.
Both helpers must be called while holding SEND_LOCK; the cache itself is
guarded by nothing else.
"""

import threading
import time

SEND_LOCK = threading.Lock()

CACHE_TTL_SECONDS = 120.0

# address -> (next expected nonce, monotonic timestamp of last broadcast)
_next_nonce: dict[str, tuple[int, float]] = {}


def allocate_nonce(w3, address: str) -> int:
    """Return the nonce for the next send from *address*.

    Takes the max of the chain's pending count and this process's cached
    next-nonce, so a stale backend that has not yet seen our previous
    broadcast cannot hand back an already-used nonce. Call only while
    holding SEND_LOCK.
    """
    chain = w3.eth.get_transaction_count(address, "pending")
    entry = _next_nonce.get(address)
    if entry is None:
        return chain
    cached, stamp = entry
    if time.monotonic() - stamp > CACHE_TTL_SECONDS:
        # Too old to trust: if our last tx was dropped without mining, the
        # cache would wedge us behind a nonce gap forever. The chain is
        # authoritative again by now.
        del _next_nonce[address]
        return chain
    return max(chain, cached)


def advance_nonce(address: str, used: int) -> None:
    """Record that *used* was consumed by a successful broadcast.

    Call only while holding SEND_LOCK, and only after
    ``send_raw_transaction`` returned without raising.
    """
    _next_nonce[address] = (used + 1, time.monotonic())
