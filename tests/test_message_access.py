"""
Tests for file access control.

Access-control model (from routers/messages.py):
- Read operations return 404 (not 403) on failure to prevent IDOR.
- Sender soft-delete (DELETE /messages/{id}) sets is_deleted=True but does NOT
  remove the recipient's FileAccess row, so recipients retain download access.
"""


def test_unauthenticated_inbox_returns_401(client):
    resp = client.get("/messages/inbox")
    assert resp.status_code == 401


def test_user_cannot_access_another_users_message_returns_404(
    client, register_user, auth_headers, make_message_payload
):
    register_user("alice", "alice@example.com")
    register_user("bob", "bob@example.com")
    register_user("charlie", "charlie@example.com")

    # Alice sends a message to Bob.
    resp = client.post(
        "/messages/send",
        json=make_message_payload("bob"),
        headers=auth_headers("alice"),
    )
    assert resp.status_code == 201
    message_id = resp.json()["id"]

    # Charlie has no FileAccess row — must receive 404, not 403.
    resp = client.get(
        f"/messages/{message_id}/download",
        headers=auth_headers("charlie"),
    )
    assert resp.status_code == 404


def test_deleted_message_still_accessible_by_recipient(
    client, register_user, auth_headers, make_message_payload
):
    register_user("alice", "alice@example.com")
    register_user("bob", "bob@example.com")

    alice_headers = auth_headers("alice")

    # Alice sends a message to Bob.
    resp = client.post(
        "/messages/send",
        json=make_message_payload("bob"),
        headers=alice_headers,
    )
    assert resp.status_code == 201
    message_id = resp.json()["id"]

    # Alice (sender) soft-deletes the message.
    resp = client.delete(f"/messages/{message_id}", headers=alice_headers)
    assert resp.status_code == 200

    # Bob's FileAccess row is untouched — he must still be able to download.
    resp = client.get(
        f"/messages/{message_id}/download",
        headers=auth_headers("bob"),
    )
    assert resp.status_code == 200
