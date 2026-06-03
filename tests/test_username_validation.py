"""
Tests for username validation on POST /auth/register.

Accepted pattern: ^[a-zA-Z0-9_.-]{3,64}$
"""


def test_username_with_html_tags_returns_422(register_user):
    resp = register_user("<b>test</b>", "html@example.com")
    assert resp.status_code == 422


def test_username_with_spaces_returns_422(register_user):
    resp = register_user("user name", "spaces@example.com")
    assert resp.status_code == 422


def test_valid_alphanumeric_username_returns_201(register_user):
    resp = register_user("alice123", "alice@example.com")
    assert resp.status_code == 201


def test_username_too_short_returns_422(register_user):
    # Two characters — below the 3-character minimum.
    resp = register_user("ab", "short@example.com")
    assert resp.status_code == 422
