"""End-to-end cryptography through the real API.

Unlike test_crypto_aad.py (which tests the HPKE layer directly) these tests
run the full client workflow with real keys against the FastAPI app:
encapsulate → upload → download → rebuild the AAD from response metadata →
decapsulate.  They also simulate a compromised server editing the database
directly, proving which attacks the AAD binding stops (relabelling,
cross-recipient replay, re-attribution) and documenting the one it cannot
(same-pair duplication — the file ID does not exist at encrypt time).
"""

import base64

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from backend import models
from backend.crypto import build_file_aad
from backend.crypto.hpke import decapsulate, encapsulate


def _keypair():
    priv = X25519PrivateKey.generate()
    return priv.private_bytes_raw(), priv.public_key().public_bytes_raw()


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


@pytest.fixture
def users(register_user, auth_headers):
    register_user("alice", "alice@example.com")
    register_user("bob", "bob@example.com")
    register_user("carol", "carol@example.com")
    headers = {u: auth_headers(u) for u in ("alice", "bob", "carol")}
    keys = {u: _keypair() for u in ("alice", "bob", "carol")}
    return {"headers": headers, "keys": keys}


FILE_BYTES = bytes(range(256)) * 300          # 76.8 kB, all byte values


def _upload(client, users, sender, recipient, filename, payload=FILE_BYTES):
    """Encrypt with real HPKE + canonical AAD and upload; returns file id."""
    sender_priv, _ = users["keys"][sender]
    _, recipient_pub = users["keys"][recipient]
    aad = build_file_aad(sender, recipient, filename)

    ct, ek, nonce = encapsulate(recipient_pub, sender_priv, payload,
                                associated_data=aad)
    res = client.post("/files/upload", json={
        "recipient_username": recipient,
        "ciphertext": _b64(ct),
        "nonce": _b64(nonce),
        "encrypted_key": _b64(ek),
        "associated_data": aad.decode(),
        "filename": filename,
        "size_bytes": len(payload),
    }, headers=users["headers"][sender])
    assert res.status_code == 201, res.text
    return res.json()["id"]


def _download_and_decrypt(client, users, me, file_id):
    """The honest-client recipe: rebuild the AAD locally from the response
    metadata + own username; never trust the server's associated_data."""
    dl = client.get(f"/files/{file_id}/download",
                    headers=users["headers"][me])
    assert dl.status_code == 200, dl.text
    body = dl.json()

    blob = base64.b64decode(body["ciphertext"])
    ct = blob[12:]                                   # strip stored nonce prefix
    aad = build_file_aad(body["owner_username"], me, body["filename"])

    my_priv, _ = users["keys"][me]
    _, sender_pub = users["keys"][body["owner_username"]]
    return decapsulate(my_priv, sender_pub, ct,
                       base64.b64decode(body["encrypted_key"]),
                       associated_data=aad)


def test_full_upload_download_roundtrip(client, users):
    fid = _upload(client, users, "alice", "bob", "report.pdf")
    assert _download_and_decrypt(client, users, "bob", fid) == FILE_BYTES


def test_server_relabelled_filename_fails_decryption(client, users, db_session):
    """Compromised-server simulation: edit the filename in SQLite directly.
    The recipient rebuilds the AAD from the (tampered) metadata, so the GCM
    tag check fails — the relabelling is DETECTED, which is the entire point
    of binding the filename."""
    fid = _upload(client, users, "alice", "bob", "invoice_draft.pdf")

    row = db_session.get(models.FileObject, fid)
    row.filename = "invoice_FINAL_approved.pdf"
    db_session.commit()

    with pytest.raises(Exception):
        _download_and_decrypt(client, users, "bob", fid)


def test_replayed_payload_under_new_file_id_still_decrypts(client, users, db_session):
    """DOCUMENTED LIMITATION (design doc §7): the server-assigned file ID
    cannot be in the AAD (it does not exist at encrypt time), so a malicious
    server CAN duplicate an identical record under a new ID and it decrypts
    as a duplicate.  This test pins that boundary so a future fix (or an
    accidental regression that starts rejecting valid files) is noticed."""
    fid = _upload(client, users, "alice", "bob", "notes.txt")
    original = db_session.get(models.FileObject, fid)

    dup = models.FileObject(
        owner_id=original.owner_id,
        ciphertext=original.ciphertext,
        filename=original.filename,
        integrity_hash=original.integrity_hash,
    )
    db_session.add(dup)
    db_session.flush()
    access = db_session.query(models.FileAccess).filter_by(file_id=fid).one()
    db_session.add(models.FileAccess(
        file_id=dup.id,
        recipient_id=access.recipient_id,
        encrypted_key=access.encrypted_key,
    ))
    db_session.commit()

    assert _download_and_decrypt(client, users, "bob", dup.id) == FILE_BYTES


def test_cross_recipient_replay_fails(client, users, db_session):
    """Serving an alice→bob ciphertext to carol fails: the content key is
    bound to bob's key pair (dh1/dh2), independent of the AAD."""
    fid = _upload(client, users, "alice", "bob", "secret.bin")
    original = db_session.get(models.FileObject, fid)
    access = db_session.query(models.FileAccess).filter_by(file_id=fid).one()

    carol = db_session.query(models.User).filter_by(username="carol").one()
    db_session.add(models.FileAccess(
        file_id=original.id,
        recipient_id=carol.id,
        encrypted_key=access.encrypted_key,
    ))
    db_session.commit()

    with pytest.raises(Exception):
        _download_and_decrypt(client, users, "carol", fid)


def test_reattribution_fails(client, users, db_session):
    """Attributing alice's upload to carol fails: dh2 binds the SENDER's
    static key, so decrypting against carol's public key breaks the tag.
    This is Mode_Auth's implicit sender authentication."""
    fid = _upload(client, users, "alice", "bob", "statement.pdf")

    row = db_session.get(models.FileObject, fid)
    carol = db_session.query(models.User).filter_by(username="carol").one()
    row.owner_id = carol.id
    db_session.commit()

    # bob follows the honest recipe — which now uses carol's public key and
    # an AAD naming carol as sender; both independently break decryption.
    with pytest.raises(Exception):
        _download_and_decrypt(client, users, "bob", fid)


def test_reencrypt_share_end_to_end(client, users):
    """bob receives from alice, decrypts, re-encrypts for carol via the
    share endpoint; carol decrypts the share copy byte-exactly using an AAD
    naming bob as the sender."""
    fid = _upload(client, users, "alice", "bob", "dataset.csv")
    plaintext = _download_and_decrypt(client, users, "bob", fid)

    bob_priv, _ = users["keys"]["bob"]
    _, carol_pub = users["keys"]["carol"]
    aad = build_file_aad("bob", "carol", "dataset.csv")
    ct, ek, nonce = encapsulate(carol_pub, bob_priv, plaintext,
                                associated_data=aad)

    res = client.post(f"/files/{fid}/share", json={
        "recipient_username": "carol",
        "new_ciphertext": _b64(ct),
        "new_nonce": _b64(nonce),
        "new_encrypted_key": _b64(ek),
    }, headers=users["headers"]["bob"])
    assert res.status_code == 200, res.text

    copy_id = client.get("/files/shared",
                         headers=users["headers"]["carol"]).json()[0]["id"]
    assert _download_and_decrypt(client, users, "carol", copy_id) == FILE_BYTES


def test_blockchain_proof_reports_local_hash_match(client, users, db_session):
    """Without Sepolia configured the proof endpoint still verifies the
    stored keccak256 against a fresh recomputation — and detects ciphertext
    tampering when the two diverge."""
    fid = _upload(client, users, "alice", "bob", "anchored.bin")

    proof = client.get(f"/files/{fid}/blockchain-proof",
                       headers=users["headers"]["bob"]).json()
    assert proof["hash_match"] is True
    assert proof["stored_hash"] == proof["computed_hash"]

    row = db_session.get(models.FileObject, fid)
    row.ciphertext = row.ciphertext[:-4] + "AAA="       # tamper
    db_session.commit()

    proof = client.get(f"/files/{fid}/blockchain-proof",
                       headers=users["headers"]["bob"]).json()
    assert proof["hash_match"] is False
