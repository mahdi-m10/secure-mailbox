"""
Tests for AEAD associated-data binding in the HPKE layer and the /files API.

The canonical AAD (backend.crypto.build_file_aad) binds
{sender username, recipient username, filename} into the GCM tag so a
malicious server cannot relabel a stored ciphertext without the recipient's
decryption failing.
"""

import pytest

from backend.crypto import build_file_aad, decapsulate, encapsulate, generate_keypair


# ---------------------------------------------------------------------------
# build_file_aad format
# ---------------------------------------------------------------------------


def test_build_file_aad_canonical_format():
    aad = build_file_aad("alice", "bob", "report.pdf")
    assert aad == b"smx:v1:sender=alice:recipient=bob:filename=report.pdf"


def test_build_file_aad_null_filename_canonicalises_to_empty():
    assert build_file_aad("alice", "bob", None) == build_file_aad("alice", "bob", "")


# ---------------------------------------------------------------------------
# HPKE round-trips with AAD
# ---------------------------------------------------------------------------


def _keypairs():
    sender_priv, sender_pub = generate_keypair()
    recip_priv, recip_pub = generate_keypair()
    return sender_priv, sender_pub, recip_priv, recip_pub


def test_hpke_roundtrip_with_aad():
    sender_priv, sender_pub, recip_priv, recip_pub = _keypairs()
    aad = build_file_aad("alice", "bob", "report.pdf")

    ct, enc, _nonce = encapsulate(recip_pub, sender_priv, b"file bytes", associated_data=aad)
    pt = decapsulate(recip_priv, sender_pub, ct, enc, associated_data=aad)
    assert pt == b"file bytes"


def test_hpke_wrong_aad_fails():
    """A relabelled filename (different AAD at decrypt) must fail the tag check."""
    sender_priv, sender_pub, recip_priv, recip_pub = _keypairs()
    good = build_file_aad("alice", "bob", "report.pdf")
    evil = build_file_aad("alice", "bob", "invoice.pdf")   # server swapped filename

    ct, enc, _nonce = encapsulate(recip_pub, sender_priv, b"file bytes", associated_data=good)
    with pytest.raises(ValueError):
        decapsulate(recip_priv, sender_pub, ct, enc, associated_data=evil)


def test_hpke_missing_aad_fails():
    """Encrypted with AAD, decrypted without (or vice versa) must fail."""
    sender_priv, sender_pub, recip_priv, recip_pub = _keypairs()
    aad = build_file_aad("alice", "bob", "report.pdf")

    ct, enc, _nonce = encapsulate(recip_pub, sender_priv, b"file bytes", associated_data=aad)
    with pytest.raises(ValueError):
        decapsulate(recip_priv, sender_pub, ct, enc, associated_data=None)

    ct2, enc2, _n2 = encapsulate(recip_pub, sender_priv, b"file bytes", associated_data=None)
    with pytest.raises(ValueError):
        decapsulate(recip_priv, sender_pub, ct2, enc2, associated_data=aad)


def test_hpke_no_aad_backward_compatible():
    """Omitting associated_data behaves exactly as before the parameter existed."""
    sender_priv, sender_pub, recip_priv, recip_pub = _keypairs()
    ct, enc, _nonce = encapsulate(recip_pub, sender_priv, b"legacy")
    assert decapsulate(recip_priv, sender_pub, ct, enc) == b"legacy"


# ---------------------------------------------------------------------------
# /files API — server-side canonical AAD
# ---------------------------------------------------------------------------


def test_upload_rejects_mismatched_associated_data(
    client, register_user, auth_headers, make_file_payload
):
    register_user("alice", "alice@example.com")
    register_user("bob", "bob@example.com")

    payload = make_file_payload("bob")
    payload["associated_data"] = "smx:v1:sender=alice:recipient=bob:filename=WRONG.pdf"

    resp = client.post("/files/upload", json=payload, headers=auth_headers("alice"))
    assert resp.status_code == 400
    assert "canonical" in resp.json()["detail"]


def test_upload_accepts_canonical_associated_data_and_download_echoes_it(
    client, register_user, auth_headers, make_file_payload
):
    register_user("alice", "alice@example.com")
    register_user("bob", "bob@example.com")

    payload = make_file_payload("bob")   # filename is "test.txt" in the fixture
    canonical = f"smx:v1:sender=alice:recipient=bob:filename={payload['filename']}"
    payload["associated_data"] = canonical

    resp = client.post("/files/upload", json=payload, headers=auth_headers("alice"))
    assert resp.status_code == 201, resp.text
    file_id = resp.json()["id"]

    # The recipient's download must return the same canonical string.
    resp = client.get(f"/files/{file_id}/download", headers=auth_headers("bob"))
    assert resp.status_code == 200
    assert resp.json()["associated_data"] == canonical


def test_upload_without_associated_data_still_accepted(
    client, register_user, auth_headers, make_file_payload
):
    """associated_data is optional at the API layer (clients adopt it with the
    client rework); the canonical check only runs when the field is present."""
    register_user("alice", "alice@example.com")
    register_user("bob", "bob@example.com")

    payload = make_file_payload("bob")
    payload.pop("associated_data", None)

    resp = client.post("/files/upload", json=payload, headers=auth_headers("alice"))
    assert resp.status_code == 201
