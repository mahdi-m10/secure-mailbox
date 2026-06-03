import base64
import os

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.database import Base, get_db
from backend.main import app

_TEST_DB_FILE = "test_secure_messenger.db"
_TEST_DB_URL = f"sqlite:///./{_TEST_DB_FILE}"

_test_engine = create_engine(
    _TEST_DB_URL,
    connect_args={"check_same_thread": False},
)
_TestingSession = sessionmaker(bind=_test_engine, autocommit=False, autoflush=False)


@pytest.fixture(scope="session", autouse=True)
def _create_test_schema():
    """Create all tables once for the test session; drop and remove the file after."""
    Base.metadata.create_all(bind=_test_engine)
    yield
    Base.metadata.drop_all(bind=_test_engine)
    _test_engine.dispose()
    if os.path.exists(_TEST_DB_FILE):
        os.remove(_TEST_DB_FILE)


@pytest.fixture(autouse=True)
def _clean_tables():
    """Delete all rows from every table after each test to keep tests independent."""
    yield
    db = _TestingSession()
    try:
        # Reversed sorted_tables deletes children before parents (FK-safe order).
        for table in reversed(Base.metadata.sorted_tables):
            db.execute(table.delete())
        db.commit()
    finally:
        db.close()


@pytest.fixture(autouse=True)
def _reset_rate_limiter():
    """Clear the in-memory rate-limit counters before each test."""
    try:
        from backend.limiter import limiter  # noqa: PLC0415

        # Try the two common internal paths used by slowapi 0.1.x
        storage = getattr(getattr(limiter, "_limiter", None), "storage", None) or getattr(
            limiter, "_storage", None
        )
        if storage is not None and hasattr(storage, "reset"):
            storage.reset()
    except Exception:
        pass
    yield


# ---------------------------------------------------------------------------
# Core fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def client():
    """TestClient wired to the test database (production DB is never touched)."""

    def _override_db():
        db = _TestingSession()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = _override_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Factory fixtures — return callables so tests stay readable
# ---------------------------------------------------------------------------


@pytest.fixture
def register_user(client):
    """Return a helper that POSTs to /auth/register."""

    def _register(username: str, email: str, password: str = "TestPass1!") -> object:
        return client.post(
            "/auth/register",
            json={"username": username, "email": email, "password": password},
        )

    return _register


@pytest.fixture
def login_user(client):
    """Return a helper that POSTs to /auth/login."""

    def _login(username: str, password: str = "TestPass1!") -> object:
        return client.post(
            "/auth/login",
            json={"username": username, "password": password},
        )

    return _login


@pytest.fixture
def auth_headers(client):
    """Return a helper that logs in and returns an Authorization header dict."""

    def _headers(username: str, password: str = "TestPass1!") -> dict:
        resp = client.post(
            "/auth/login",
            json={"username": username, "password": password},
        )
        token = resp.json()["access_token"]
        return {"Authorization": f"Bearer {token}"}

    return _headers


@pytest.fixture
def make_message_payload():
    """Return a helper that builds a valid MessageSend payload with random crypto material."""

    def _payload(recipient_username: str) -> dict:
        # Random nonce (12 bytes) and ciphertext (32 bytes ≥ 16-byte GCM tag minimum).
        return {
            "recipient_username": recipient_username,
            "nonce": base64.b64encode(os.urandom(12)).decode(),
            "ciphertext": base64.b64encode(os.urandom(32)).decode(),
            "encrypted_key": base64.b64encode(os.urandom(32)).decode(),
            "subject": "Test subject",
        }

    return _payload
