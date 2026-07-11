"""Process-wide lock serializing nonce allocation for the registrar/deployer
wallet shared by MessageDigest, KeyRegistry, and MessageReceipt.

Every write to any of the three contracts is signed by the same server
wallet. Multiple background threads can fire in close succession from a
single upload (a MessageDigest anchor thread and a MessageReceipt thread)
or from concurrent requests (key registration/rotation), all reading
``get_transaction_count(..., "pending")`` before broadcasting. That read
and the broadcast are not atomic, so two sends built from the same nonce
race — the second is rejected by the node ("nonce too low"). Observed in
practice during B2 integration testing against a local Hardhat node.

Hold this lock only across nonce-read → build → sign → broadcast; release
it before waiting for the transaction receipt, so the ~15-30 s Sepolia
confirmation wait does not serialize unrelated sends.
"""

import threading

SEND_LOCK = threading.Lock()
