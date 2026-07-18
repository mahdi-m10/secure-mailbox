"""Unit tests for the per-process nonce allocator in _send_lock.py.

Motivated by a production failure: with a single process and a single
wallet, a receipt-posting send was rejected with "replacement transaction
underpriced" because the load-balanced public RPC returned a pending count
that did not yet include a transaction this same process had broadcast
moments earlier. The allocator's max(chain_pending, cached) must cover
exactly that case.
"""

import time

import pytest

from backend.blockchain import _send_lock
from backend.blockchain._send_lock import advance_nonce, allocate_nonce


class _FakeW3:
    """Stands in for Web3: returns a scripted pending count."""

    def __init__(self, pending: int):
        self.pending = pending
        self.eth = self

    def get_transaction_count(self, address, block_identifier):
        assert block_identifier == "pending"
        return self.pending


ADDR = "0xAbC0000000000000000000000000000000000001"


@pytest.fixture(autouse=True)
def _clean_cache():
    _send_lock._next_nonce.clear()
    yield
    _send_lock._next_nonce.clear()


def test_first_allocation_uses_chain_value():
    assert allocate_nonce(_FakeW3(7), ADDR) == 7


def test_stale_backend_cannot_reissue_used_nonce():
    # The production scenario: broadcast consumed nonce 7, but the next
    # pending-count read hits a backend that hasn't seen that tx yet and
    # still says 7. The cache must win.
    assert allocate_nonce(_FakeW3(7), ADDR) == 7
    advance_nonce(ADDR, 7)
    assert allocate_nonce(_FakeW3(7), ADDR) == 8      # stale chain view
    advance_nonce(ADDR, 8)
    assert allocate_nonce(_FakeW3(7), ADDR) == 9      # still stale — cache keeps counting


def test_chain_ahead_of_cache_wins():
    # Another party (or an expired era of this process) used nonces we
    # never saw: the chain's higher value must be taken.
    advance_nonce(ADDR, 3)                            # cache says next = 4
    assert allocate_nonce(_FakeW3(10), ADDR) == 10


def test_failed_broadcast_does_not_advance():
    # advance_nonce is only called after send_raw_transaction succeeds;
    # a rejected send leaves the cache untouched so the nonce is retried.
    assert allocate_nonce(_FakeW3(5), ADDR) == 5
    # (no advance — the broadcast raised)
    assert allocate_nonce(_FakeW3(5), ADDR) == 5


def test_cache_is_per_address():
    other = "0xAbC0000000000000000000000000000000000002"
    advance_nonce(ADDR, 7)
    assert allocate_nonce(_FakeW3(0), ADDR) == 8
    assert allocate_nonce(_FakeW3(0), other) == 0


def test_expired_cache_falls_back_to_chain(monkeypatch):
    # If our last broadcast tx was dropped without mining, a cached value
    # above the chain would wedge sends behind a nonce gap forever. After
    # the TTL the chain becomes authoritative again.
    advance_nonce(ADDR, 7)                            # cache: next = 8
    real_monotonic = time.monotonic

    monkeypatch.setattr(
        _send_lock.time, "monotonic",
        lambda: real_monotonic() + _send_lock.CACHE_TTL_SECONDS + 1,
    )
    assert allocate_nonce(_FakeW3(5), ADDR) == 5      # dropped-tx state: chain wins
    assert ADDR not in _send_lock._next_nonce         # entry evicted
