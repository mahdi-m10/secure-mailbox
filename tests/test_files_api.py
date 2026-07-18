"""Endpoint-behaviour tests for the /files API.

Covers the upload / listing / delete / share / revoke surface that the
access-control and AAD suites don't: error codes, ownership rules, the
share paths (re-encrypt vs legacy), and revocation semantics.
"""

import pytest


@pytest.fixture
def two_users(register_user, auth_headers):
    """alice and bob, registered, with auth headers for each."""
    register_user("alice", "alice@example.com")
    register_user("bob", "bob@example.com")
    return {"alice": auth_headers("alice"), "bob": auth_headers("bob")}


@pytest.fixture
def three_users(two_users, register_user, auth_headers):
    register_user("carol", "carol@example.com")
    return {**two_users, "carol": auth_headers("carol")}


@pytest.fixture
def uploaded_file(client, two_users, make_file_payload):
    """A file uploaded by alice for bob; returns its id."""
    res = client.post("/files/upload", json=make_file_payload("bob"),
                      headers=two_users["alice"])
    assert res.status_code == 201, res.text
    return res.json()["id"]


# ---------------------------------------------------------------------------
# Upload
# ---------------------------------------------------------------------------

def test_upload_requires_auth(client, make_file_payload):
    res = client.post("/files/upload", json=make_file_payload("bob"))
    assert res.status_code == 401


def test_upload_to_self_returns_400(client, two_users, make_file_payload):
    res = client.post("/files/upload", json=make_file_payload("alice"),
                      headers=two_users["alice"])
    assert res.status_code == 400


def test_upload_to_unknown_recipient_returns_404(client, two_users, make_file_payload):
    res = client.post("/files/upload", json=make_file_payload("nobody"),
                      headers=two_users["alice"])
    assert res.status_code == 404


def test_upload_with_bad_nonce_length_returns_422(client, two_users, make_file_payload):
    payload = make_file_payload("bob")
    payload["nonce"] = "AAAA"          # decodes to 3 bytes, not 12
    res = client.post("/files/upload", json=payload, headers=two_users["alice"])
    assert res.status_code == 422


def test_upload_oversize_ciphertext_returns_422(client, two_users, make_file_payload):
    from backend.schemas import MAX_CIPHERTEXT_B64_LEN
    payload = make_file_payload("bob")
    # One base64 char over the schema cap; validator must reject on LENGTH,
    # before any base64 decode allocates a second multi-MB buffer.
    payload["ciphertext"] = "A" * (MAX_CIPHERTEXT_B64_LEN + 1)
    res = client.post("/files/upload", json=payload, headers=two_users["alice"])
    assert res.status_code == 422


def test_upload_persists_metadata(client, two_users, make_file_payload):
    res = client.post("/files/upload", json=make_file_payload("bob"),
                      headers=two_users["alice"])
    assert res.status_code == 201
    body = res.json()
    assert body["filename"] == "test.txt"
    assert body["content_type"] == "text/plain"
    assert body["size_bytes"] == 16
    assert body["owner_username"] == "alice"


def test_upload_rate_limit_returns_429_after_twenty(client, two_users, make_file_payload):
    # Same per-IP pattern as the login limiter (5/min there, 20/min here).
    for _ in range(20):
        res = client.post("/files/upload", json=make_file_payload("bob"),
                          headers=two_users["alice"])
        assert res.status_code == 201
    res = client.post("/files/upload", json=make_file_payload("bob"),
                      headers=two_users["alice"])
    assert res.status_code == 429


# ---------------------------------------------------------------------------
# Listings
# ---------------------------------------------------------------------------

def test_shared_listing_shows_received_file(client, two_users, uploaded_file):
    res = client.get("/files/shared", headers=two_users["bob"])
    assert res.status_code == 200
    items = res.json()
    assert [f["id"] for f in items] == [uploaded_file]
    assert items[0]["owner_username"] == "alice"
    assert items[0]["is_read"] is False


def test_owned_listing_shows_upload_with_recipient(client, two_users, uploaded_file):
    res = client.get("/files/owned", headers=two_users["alice"])
    items = res.json()
    assert [f["id"] for f in items] == [uploaded_file]
    assert items[0]["recipient_username"] == "bob"


def test_uploader_does_not_see_file_in_shared(client, two_users, uploaded_file):
    res = client.get("/files/shared", headers=two_users["alice"])
    assert res.json() == []


def test_download_marks_file_read(client, two_users, uploaded_file):
    client.get(f"/files/{uploaded_file}/download", headers=two_users["bob"])
    res = client.get("/files/shared", headers=two_users["bob"])
    assert res.json()[0]["is_read"] is True


# ---------------------------------------------------------------------------
# Associated-data display (GET /files/{id}/download, used by verify.html)
#
# Regression test for a bug found via manual UI testing: the recipient slot
# of the informational `associated_data` field was built from the current
# *viewer's* username rather than the file's real recipient. This was
# invisible when the recipient themselves viewed the file (their username IS
# the recipient), but wrong when the owner viewed their own upload (e.g. via
# verify.html) — it showed sender=X:recipient=X instead of the true
# recipient. Cosmetic only: it never affected actual decryption, since each
# client independently rebuilds the AAD from its own knowledge before
# decrypting. See docs/crypto-design.md.
# ---------------------------------------------------------------------------

def test_recipient_view_shows_own_username_in_aad(client, two_users, uploaded_file):
    res = client.get(f"/files/{uploaded_file}/download", headers=two_users["bob"])
    assert res.status_code == 200
    assert res.json()["associated_data"] == (
        "smx:v1:sender=alice:recipient=bob:filename=test.txt"
    )


def test_owner_view_shows_true_recipient_in_aad(client, two_users, uploaded_file):
    """The bug: this used to show recipient=alice (the owner) instead of bob."""
    res = client.get(f"/files/{uploaded_file}/download", headers=two_users["alice"])
    assert res.status_code == 200
    assert res.json()["associated_data"] == (
        "smx:v1:sender=alice:recipient=bob:filename=test.txt"
    )


def test_owner_view_with_ambiguous_recipients_leaves_slot_blank(
    client, three_users, uploaded_file, db_session
):
    """Multiple access rows (legacy-era database): no single recipient, don't guess."""
    _seed_access_row(db_session, uploaded_file, "carol")
    res = client.get(f"/files/{uploaded_file}/download", headers=three_users["alice"])
    assert res.status_code == 200
    assert res.json()["associated_data"] == (
        "smx:v1:sender=alice:recipient=:filename=test.txt"
    )


# ---------------------------------------------------------------------------
# Delete
# ---------------------------------------------------------------------------

def test_recipient_cannot_delete_returns_403(client, two_users, uploaded_file):
    res = client.delete(f"/files/{uploaded_file}", headers=two_users["bob"])
    assert res.status_code == 403


def test_delete_unknown_file_returns_404(client, two_users):
    res = client.delete("/files/99999", headers=two_users["alice"])
    assert res.status_code == 404


def test_deleted_file_leaves_owner_listing(client, two_users, uploaded_file):
    assert client.delete(f"/files/{uploaded_file}",
                         headers=two_users["alice"]).status_code == 200
    res = client.get("/files/owned", headers=two_users["alice"])
    assert res.json() == []


def test_double_delete_returns_404(client, two_users, uploaded_file):
    client.delete(f"/files/{uploaded_file}", headers=two_users["alice"])
    res = client.delete(f"/files/{uploaded_file}", headers=two_users["alice"])
    assert res.status_code == 404


# ---------------------------------------------------------------------------
# Share
# ---------------------------------------------------------------------------

def _seed_access_row(db_session, file_id, username):
    """Insert a FileAccess row directly, bypassing the API.

    Simulates a database written before the legacy no-re-encryption share
    path was removed — the only era in which one file could have multiple
    access rows. The API can no longer create this state.
    """
    import base64
    import os

    from backend import models

    user = (
        db_session.query(models.User)
        .filter(models.User.username == username)
        .one()
    )
    db_session.add(models.FileAccess(
        file_id=file_id,
        recipient_id=user.id,
        encrypted_key=base64.b64encode(os.urandom(32)).decode(),
    ))
    db_session.commit()


def _reencrypt_share_body(recipient):
    import base64
    import os
    return {
        "recipient_username": recipient,
        "new_ciphertext": base64.b64encode(os.urandom(48)).decode(),
        "new_nonce":      base64.b64encode(os.urandom(12)).decode(),
        "new_encrypted_key": base64.b64encode(os.urandom(32)).decode(),
    }


def test_recipient_reencrypt_share_creates_new_file(client, three_users, uploaded_file):
    body = _reencrypt_share_body("carol")
    res = client.post(f"/files/{uploaded_file}/share", json=body,
                      headers=three_users["bob"])
    assert res.status_code == 200, res.text

    # carol sees a NEW file row (share copy), owned by the sharer, flagged
    # is_forwarded, carrying the re-encrypted payload — not the original.
    shared = client.get("/files/shared", headers=three_users["carol"]).json()
    assert len(shared) == 1
    copy = shared[0]
    assert copy["id"] != uploaded_file
    assert copy["owner_username"] == "bob"
    assert copy["is_forwarded"] is True

    dl = client.get(f"/files/{copy['id']}/download",
                    headers=three_users["carol"]).json()
    assert dl["encrypted_key"] == body["new_encrypted_key"]


def test_share_to_existing_recipient_returns_409(client, three_users, uploaded_file):
    # bob already has access to the original file
    res = client.post(f"/files/{uploaded_file}/share",
                      json=_reencrypt_share_body("bob"),
                      headers=three_users["alice"])
    assert res.status_code == 409


def test_share_with_self_returns_400(client, three_users, uploaded_file):
    res = client.post(f"/files/{uploaded_file}/share",
                      json=_reencrypt_share_body("bob"),
                      headers=three_users["bob"])
    assert res.status_code == 400


def test_stranger_cannot_share_returns_404(client, three_users, uploaded_file):
    # carol has no access to the file — 404, not 403 (IDOR posture)
    res = client.post(f"/files/{uploaded_file}/share",
                      json=_reencrypt_share_body("carol"),
                      headers=three_users["carol"])
    assert res.status_code == 404


def test_share_without_reencryption_fields_returns_422(
    client, three_users, uploaded_file
):
    # The legacy no-re-encryption path was removed: all three new_* fields
    # are schema-required, so a body without them is rejected outright
    # instead of silently creating a row the recipient could never decrypt.
    res = client.post(f"/files/{uploaded_file}/share",
                      json={"recipient_username": "carol"},
                      headers=three_users["bob"])
    assert res.status_code == 422


# ---------------------------------------------------------------------------
# Revoke
# ---------------------------------------------------------------------------

def test_targeted_revoke_removes_access(client, two_users, uploaded_file):
    res = client.post(f"/files/{uploaded_file}/revoke",
                      json={"recipient_username": "bob"},
                      headers=two_users["alice"])
    assert res.status_code == 200

    assert client.get(f"/files/{uploaded_file}/download",
                      headers=two_users["bob"]).status_code == 404
    assert client.get("/files/shared", headers=two_users["bob"]).json() == []


def test_full_revoke_removes_all_recipients(
    client, three_users, uploaded_file, db_session
):
    # Give carol a second access row directly in the DB — the API can no
    # longer create multi-recipient rows since the legacy share path was
    # removed, but rows written by it may exist in older databases and the
    # full-revoke sweep must still clear them all.
    _seed_access_row(db_session, uploaded_file, "carol")

    res = client.post(f"/files/{uploaded_file}/revoke", json={},
                      headers=three_users["alice"])
    assert res.status_code == 200

    for user in ("bob", "carol"):
        assert client.get(f"/files/{uploaded_file}/download",
                          headers=three_users[user]).status_code == 404

    # The owner still sees the file — revocation is not deletion.
    owned = client.get("/files/owned", headers=three_users["alice"]).json()
    assert [f["id"] for f in owned] == [uploaded_file]


def test_recipient_cannot_revoke_returns_403(client, two_users, uploaded_file):
    res = client.post(f"/files/{uploaded_file}/revoke", json={},
                      headers=two_users["bob"])
    assert res.status_code == 403


def test_revoke_user_without_access_returns_404(client, three_users, uploaded_file):
    res = client.post(f"/files/{uploaded_file}/revoke",
                      json={"recipient_username": "carol"},
                      headers=three_users["alice"])
    assert res.status_code == 404
