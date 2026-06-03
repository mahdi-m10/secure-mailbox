"""
Tests for POST /auth/register and POST /auth/login.
"""


def test_register_valid_credentials_returns_201(register_user):
    resp = register_user("alice", "alice@example.com")
    assert resp.status_code == 201


def test_register_duplicate_username_returns_409(register_user):
    register_user("alice", "alice@example.com")
    # Same username, different email — must conflict.
    resp = register_user("alice", "alice2@example.com")
    assert resp.status_code == 409


def test_login_valid_credentials_returns_200_with_token(register_user, login_user):
    register_user("alice", "alice@example.com")
    resp = login_user("alice")
    assert resp.status_code == 200
    assert "access_token" in resp.json()


def test_login_wrong_password_returns_401(register_user, client):
    register_user("alice", "alice@example.com")
    resp = client.post(
        "/auth/login",
        json={"username": "alice", "password": "WrongPass1!"},
    )
    assert resp.status_code == 401


def test_login_rate_limit_returns_429_after_five_attempts(register_user, client):
    register_user("alice", "alice@example.com")
    # Exhaust the 5/minute allowance with wrong-password attempts.
    for _ in range(5):
        client.post("/auth/login", json={"username": "alice", "password": "WrongPass1!"})
    # The sixth attempt must be rejected by the rate limiter.
    resp = client.post("/auth/login", json={"username": "alice", "password": "WrongPass1!"})
    assert resp.status_code == 429
