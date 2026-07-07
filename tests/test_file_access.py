"""
Tests for file access control.

Access-control model (from routers/files.py):
- Read operations return 404 (not 403) on failure to prevent IDOR.
- Owner soft-delete (DELETE /files/{id}) sets is_deleted=True but does NOT
  remove the recipient's FileAccess row, so recipients retain download access.
"""


def test_unauthenticated_listing_returns_401(client):
    resp = client.get("/files/shared")
    assert resp.status_code == 401


def test_user_cannot_access_another_users_file_returns_404(
    client, register_user, auth_headers, make_file_payload
):
    register_user("alice", "alice@example.com")
    register_user("bob", "bob@example.com")
    register_user("charlie", "charlie@example.com")

    # Alice uploads a file for Bob.
    resp = client.post(
        "/files/upload",
        json=make_file_payload("bob"),
        headers=auth_headers("alice"),
    )
    assert resp.status_code == 201
    file_id = resp.json()["id"]

    # Charlie has no FileAccess row — must receive 404, not 403.
    resp = client.get(
        f"/files/{file_id}/download",
        headers=auth_headers("charlie"),
    )
    assert resp.status_code == 404


def test_deleted_file_still_accessible_by_recipient(
    client, register_user, auth_headers, make_file_payload
):
    register_user("alice", "alice@example.com")
    register_user("bob", "bob@example.com")

    alice_headers = auth_headers("alice")

    # Alice uploads a file for Bob.
    resp = client.post(
        "/files/upload",
        json=make_file_payload("bob"),
        headers=alice_headers,
    )
    assert resp.status_code == 201
    file_id = resp.json()["id"]

    # Alice (owner) soft-deletes the file.
    resp = client.delete(f"/files/{file_id}", headers=alice_headers)
    assert resp.status_code == 200

    # Bob's FileAccess row is untouched — he must still be able to download.
    resp = client.get(
        f"/files/{file_id}/download",
        headers=auth_headers("bob"),
    )
    assert resp.status_code == 200
