"""Backend integration with KeyRegistry / MessageReceipt (blockchain B2).

The chain layer itself (backend/blockchain/registry.py, receipts.py) talks
to a real Web3 provider and is exercised against a live local Hardhat node
during development (see docs/deployment.md) — not in this suite, which must
run without any blockchain infrastructure. These tests mock the chain calls
at the module boundary and verify:
  - POST /users/keys and POST /auth/register (with a public_key) trigger a
    background on-chain registration/rotation and persist users.eth_key_tx
  - POST /files/upload and POST /files/{id}/share trigger a background
    receipt post and persist files.receipt_tx_hash
  - GET /users/{username}?onchain=1 surfaces the on-chain record, defaults
    to omitted, and fails open (onchain=null + onchain_error) on RPC failure
  - GET /files/{id}/download and .../blockchain-proof surface receipt status

Background submissions normally run in a daemon thread so the HTTP response
isn't held for an RPC round trip. The `sync_threads` fixture makes
threading.Thread run its target synchronously and in-process for the
duration of a test, so these tests can assert on post-conditions
immediately rather than polling/sleeping.
"""

import threading
from unittest.mock import patch

import pytest


_BACKGROUND_TARGET_NAMES = {
    "submit_key_registration_background",
    "_submit_receipt",
    "_submit_to_chain",
}


@pytest.fixture
def sync_threads(monkeypatch):
    """Run this project's blockchain background-submission threads
    synchronously and in-process, so tests can assert on their effects
    immediately instead of polling/sleeping.

    Must NOT patch threading.Thread.start unconditionally: Starlette's
    TestClient and Python's own concurrent.futures.ThreadPoolExecutor (used
    by run_in_threadpool for sync endpoints) also create worker threads via
    threading.Thread(...).start() — forcing those to run synchronously turns
    a worker's blocking work-loop into a call that never returns, deadlocking
    the test client. This selectively intercepts only threads whose target
    is one of our known background functions and falls through to the real
    Thread.start for everything else.
    """
    original_start = threading.Thread.start

    def selective_start(self):
        target = getattr(self, "_target", None)
        if getattr(target, "__name__", None) in _BACKGROUND_TARGET_NAMES:
            if target is not None:
                target(*self._args, **(self._kwargs or {}))
        else:
            original_start(self)

    monkeypatch.setattr(threading.Thread, "start", selective_start)

    # The background functions do `from backend.database import
    # SessionLocal` at call time, resolving to the production DB by
    # default. Point that at the same test database the rest of the suite
    # uses, so persisted tx-hash columns are visible to this test's own
    # db_session fixture rather than landing in a different physical file.
    import backend.database
    from tests.conftest import _TestingSession

    monkeypatch.setattr(backend.database, "SessionLocal", _TestingSession)


# ---------------------------------------------------------------------------
# Key registration / rotation
# ---------------------------------------------------------------------------

def test_upload_key_registers_onchain_and_persists_tx(
    client, register_user, auth_headers, db_session, sync_threads
):
    register_user("alice", "alice@example.com")
    headers = auth_headers("alice")

    with patch(
        "backend.blockchain.registry.register_or_rotate_key",
        return_value="0xaaaa000000000000000000000000000000000000000000000000000000000001",
    ) as mock_register:
        res = client.post(
            "/users/keys", json={"public_key": "A" * 43 + "="}, headers=headers
        )
    assert res.status_code == 200, res.text
    mock_register.assert_called_once()
    assert mock_register.call_args.args[0] == "alice"

    from backend import models
    user = db_session.query(models.User).filter_by(username="alice").one()
    assert user.eth_key_tx == "0xaaaa000000000000000000000000000000000000000000000000000000000001"


def test_registration_with_public_key_registers_onchain(client, sync_threads):
    with patch(
        "backend.blockchain.registry.register_or_rotate_key",
        return_value="0xbbbb000000000000000000000000000000000000000000000000000000000002",
    ) as mock_register:
        res = client.post("/auth/register", json={
            "username": "bob", "email": "bob@example.com",
            "password": "TestPass1!", "public_key": "B" * 43 + "=",
        })
    assert res.status_code == 201, res.text
    mock_register.assert_called_once()
    assert mock_register.call_args.args[0] == "bob"


def test_registration_without_public_key_does_not_touch_chain(client, sync_threads):
    with patch("backend.blockchain.registry.register_or_rotate_key") as mock_register:
        res = client.post("/auth/register", json={
            "username": "carol", "email": "carol@example.com",
            "password": "TestPass1!",
        })
    assert res.status_code == 201
    mock_register.assert_not_called()


def test_chain_registration_failure_does_not_fail_the_request(
    client, register_user, auth_headers, db_session, sync_threads
):
    """A background chain failure must never surface as an HTTP error —
    the whole point of running it in a thread is that key upload succeeds
    independent of blockchain availability."""
    register_user("dana", "dana@example.com")
    headers = auth_headers("dana")

    with patch(
        "backend.blockchain.registry.register_or_rotate_key",
        side_effect=RuntimeError("RPC unreachable"),
    ):
        res = client.post(
            "/users/keys", json={"public_key": "C" * 43 + "="}, headers=headers
        )
    assert res.status_code == 200

    from backend import models
    user = db_session.query(models.User).filter_by(username="dana").one()
    assert user.eth_key_tx is None


# ---------------------------------------------------------------------------
# GET /users/{username}?onchain=1
# ---------------------------------------------------------------------------

def test_onchain_lookup_omitted_by_default(client, register_user):
    register_user("erin", "erin@example.com")
    with patch("backend.blockchain.registry.get_onchain_key") as mock_get:
        res = client.get("/users/erin")
    assert res.status_code == 200
    assert res.json()["onchain"] is None
    mock_get.assert_not_called()


def test_onchain_lookup_returned_when_requested(client, register_user):
    register_user("frank", "frank@example.com")
    with patch(
        "backend.blockchain.registry.get_onchain_key",
        return_value={
            "registered": True, "version": 1,
            "key_b64": "ZmFrZWtleWZha2VrZXlmYWtla2V5ZmFrZWtleWZha2VrZXk9",
            "updated_at": 1234567890, "revoked": False,
        },
    ):
        res = client.get("/users/frank?onchain=1")
    assert res.status_code == 200
    body = res.json()
    assert body["onchain"]["registered"] is True
    assert body["onchain"]["version"] == 1
    assert body["onchain_error"] is None


def test_onchain_lookup_fails_open_on_rpc_error(client, register_user):
    """The pre-encrypt gate is a client-side concern; this endpoint must
    never fail the whole response over an RPC problem."""
    register_user("grace", "grace@example.com")
    with patch(
        "backend.blockchain.registry.get_onchain_key",
        side_effect=ConnectionError("Cannot reach RPC endpoint"),
    ):
        res = client.get("/users/grace?onchain=1")
    assert res.status_code == 200
    body = res.json()
    assert body["onchain"] is None
    assert "Cannot reach RPC" in body["onchain_error"]


def test_bulk_users_listing_has_no_onchain_param(client, register_user):
    """GET /users never does per-user chain reads — that would mean one RPC
    call per user for a 500-item page."""
    register_user("henry", "henry@example.com")
    with patch("backend.blockchain.registry.get_onchain_key") as mock_get:
        res = client.get("/users")
    assert res.status_code == 200
    mock_get.assert_not_called()


# ---------------------------------------------------------------------------
# Receipt posting (upload + share)
# ---------------------------------------------------------------------------

@pytest.fixture
def two_users(register_user, auth_headers):
    register_user("alice", "alice@example.com")
    register_user("bob", "bob@example.com")
    return {"alice": auth_headers("alice"), "bob": auth_headers("bob")}


def test_upload_posts_receipt_and_persists_tx(
    client, two_users, make_file_payload, db_session, sync_threads
):
    with patch(
        "backend.blockchain.receipts.post_receipt",
        return_value="0xcccc000000000000000000000000000000000000000000000000000000000003",
    ) as mock_post, patch("backend.blockchain.contract.record_message_digest",
                          side_effect=EnvironmentError("not configured")):
        res = client.post("/files/upload", json=make_file_payload("bob"),
                          headers=two_users["alice"])
    assert res.status_code == 201, res.text
    file_id = res.json()["id"]

    mock_post.assert_called_once()
    assert mock_post.call_args.args[1:] == ("alice", "bob")

    from backend import models
    file_obj = db_session.get(models.FileObject, file_id)
    assert file_obj.receipt_tx_hash == "0xcccc000000000000000000000000000000000000000000000000000000000003"


def test_receipt_failure_does_not_fail_the_upload(
    client, two_users, make_file_payload, db_session, sync_threads
):
    with patch(
        "backend.blockchain.receipts.post_receipt",
        side_effect=ValueError("receipt exists"),
    ), patch("backend.blockchain.contract.record_message_digest",
             side_effect=EnvironmentError("not configured")):
        res = client.post("/files/upload", json=make_file_payload("bob"),
                          headers=two_users["alice"])
    assert res.status_code == 201

    from backend import models
    file_obj = db_session.get(models.FileObject, res.json()["id"])
    assert file_obj.receipt_tx_hash is None


def test_download_surfaces_receipt_status(client, two_users, make_file_payload, db_session):
    res = client.post("/files/upload", json=make_file_payload("bob"), headers=two_users["alice"])
    file_id = res.json()["id"]

    from backend import models
    file_obj = db_session.get(models.FileObject, file_id)
    file_obj.receipt_tx_hash = "0xdddd000000000000000000000000000000000000000000000000000000000004"
    db_session.commit()

    dl = client.get(f"/files/{file_id}/download", headers=two_users["bob"])
    assert dl.status_code == 200
    assert dl.json()["receipt"] == {
        "posted": True,
        "tx_hash": "0xdddd000000000000000000000000000000000000000000000000000000000004",
    }


def test_download_receipt_null_when_not_posted(client, two_users, make_file_payload):
    res = client.post("/files/upload", json=make_file_payload("bob"), headers=two_users["alice"])
    file_id = res.json()["id"]

    dl = client.get(f"/files/{file_id}/download", headers=two_users["bob"])
    assert dl.json()["receipt"] == {"posted": False, "tx_hash": None}


def test_blockchain_proof_includes_live_receipt_lookup(
    client, two_users, make_file_payload, db_session
):
    res = client.post("/files/upload", json=make_file_payload("bob"), headers=two_users["alice"])
    file_id = res.json()["id"]

    with patch(
        "backend.blockchain.receipts.get_receipt",
        return_value={
            "exists": True,
            "sender_hash": "0x" + "11" * 32,
            "recipient_hash": "0x" + "22" * 32,
            "timestamp": 1111111111,
            "block_number": 42,
        },
    ):
        proof = client.get(f"/files/{file_id}/blockchain-proof", headers=two_users["bob"])
    assert proof.status_code == 200
    body = proof.json()
    assert body["receipt"]["exists"] is True
    assert body["receipt"]["block_number"] == 42


def test_blockchain_proof_receipt_fails_open(client, two_users, make_file_payload):
    res = client.post("/files/upload", json=make_file_payload("bob"), headers=two_users["alice"])
    file_id = res.json()["id"]

    with patch(
        "backend.blockchain.receipts.get_receipt",
        side_effect=RuntimeError("RPC down"),
    ):
        proof = client.get(f"/files/{file_id}/blockchain-proof", headers=two_users["bob"])
    assert proof.status_code == 200
    assert proof.json()["receipt"] is None


def test_share_posts_receipt_naming_sharer_as_sender(
    client, register_user, auth_headers, two_users, make_file_payload, db_session, sync_threads
):
    register_user("carol", "carol@example.com")
    carol_headers = auth_headers("carol")

    upload = client.post("/files/upload", json=make_file_payload("bob"), headers=two_users["alice"])
    file_id = upload.json()["id"]

    import base64
    import os

    share_body = {
        "recipient_username": "carol",
        "new_ciphertext": base64.b64encode(os.urandom(48)).decode(),
        "new_nonce": base64.b64encode(os.urandom(12)).decode(),
        "new_encrypted_key": base64.b64encode(os.urandom(32)).decode(),
    }

    with patch(
        "backend.blockchain.receipts.post_receipt",
        return_value="0xeeee000000000000000000000000000000000000000000000000000000000005",
    ) as mock_post, patch("backend.blockchain.contract.record_message_digest",
                          side_effect=EnvironmentError("not configured")):
        res = client.post(f"/files/{file_id}/share", json=share_body, headers=two_users["bob"])
    assert res.status_code == 200, res.text

    # The sharer (bob) is the sender of the re-encrypted copy, not alice.
    mock_post.assert_called_once()
    assert mock_post.call_args.args[1:] == ("bob", "carol")
