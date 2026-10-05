"""
OTP Password Reset Test Suite
=============================
6-digit OTP generation, hashed storage, expiry, single-use, wrong-guess lockout,
resend cooldown, enumeration safety and SMTP failure handling.
"""

import re
from datetime import datetime, timedelta
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.app.main import app
from backend.app.database.connection import Base, get_db
from backend.app.models.scan import UserModel, PasswordResetTokenModel

engine = create_engine("sqlite:///./test_password_reset.db", connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
SEND = "backend.app.api.v1.auth.send_password_reset_otp_email"


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_database():
    app.dependency_overrides[get_db] = override_get_db
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)
    app.dependency_overrides.clear()


def _register(email="testuser@example.com", pwd="OldPassword123!"):
    r = client.post("/api/v1/auth/register", json={"name": "Test User", "email": email, "password": pwd})
    assert r.status_code == 201
    return email, pwd


def _request_otp(email):
    sent = {}
    with patch(SEND, side_effect=lambda to, otp: sent.update(to=to, otp=otp)):
        r = client.post("/api/v1/auth/forgot-password", json={"email": email})
    assert r.status_code == 200
    return sent


def _expire_cooldown(email):
    """Pretend the previous request happened 2 minutes ago."""
    db = TestingSessionLocal()
    for rec in db.query(PasswordResetTokenModel).all():
        rec.created_at = datetime.utcnow() - timedelta(minutes=2)
    db.commit()
    db.close()


def test_unregistered_email_gets_generic_200_and_no_email():
    with patch(SEND) as mock_send:
        r = client.post("/api/v1/auth/forgot-password", json={"email": "nobody@example.com"})
    assert r.status_code == 200
    assert "If an account exists" in r.json()["message"]
    mock_send.assert_not_called()


def test_full_otp_flow():
    email, old = _register()
    sent = _request_otp(email)
    assert sent["to"] == email
    assert re.fullmatch(r"\d{6}", sent["otp"])

    # OTP must never be stored in plain text
    db = TestingSessionLocal()
    rec = db.query(PasswordResetTokenModel).one()
    assert sent["otp"] not in rec.token_hash
    assert rec.used_at is None and rec.expires_at > datetime.utcnow()
    db.close()

    r = client.post("/api/v1/auth/reset-password",
                    json={"email": email, "otp": sent["otp"], "new_password": "NewSecurePassword456!"})
    assert r.status_code == 200
    assert client.post("/api/v1/auth/login", json={"email": email, "password": old}).status_code == 401
    assert client.post("/api/v1/auth/login", json={"email": email, "password": "NewSecurePassword456!"}).status_code == 200


def test_otp_is_single_use():
    email, _ = _register()
    otp = _request_otp(email)["otp"]
    body = {"email": email, "otp": otp, "new_password": "FirstNewPass1!"}
    assert client.post("/api/v1/auth/reset-password", json=body).status_code == 200
    body["new_password"] = "SecondNewPass2!"
    assert client.post("/api/v1/auth/reset-password", json=body).status_code == 400


def test_wrong_otp_rejected_and_locks_after_max_attempts():
    email, old = _register()
    otp = _request_otp(email)["otp"]
    wrong = "000000" if otp != "000000" else "111111"

    for _ in range(5):
        r = client.post("/api/v1/auth/reset-password",
                        json={"email": email, "otp": wrong, "new_password": "Whatever123!"})
        assert r.status_code == 400

    # Correct code no longer works: it was burned by the failed attempts
    r = client.post("/api/v1/auth/reset-password",
                    json={"email": email, "otp": otp, "new_password": "Whatever123!"})
    assert r.status_code == 400
    assert client.post("/api/v1/auth/login", json={"email": email, "password": old}).status_code == 200


def test_expired_otp_rejected():
    email, _ = _register()
    otp = _request_otp(email)["otp"]
    db = TestingSessionLocal()
    rec = db.query(PasswordResetTokenModel).one()
    rec.expires_at = datetime.utcnow() - timedelta(minutes=1)
    db.commit()
    db.close()
    r = client.post("/api/v1/auth/reset-password",
                    json={"email": email, "otp": otp, "new_password": "Whatever123!"})
    assert r.status_code == 400
    assert "Invalid or expired" in r.json()["detail"]


def test_new_request_invalidates_previous_otp():
    email, _ = _register()
    first = _request_otp(email)["otp"]
    _expire_cooldown(email)
    second = _request_otp(email)["otp"]
    if first != second:  # 1-in-a-million collision guard
        r = client.post("/api/v1/auth/reset-password",
                        json={"email": email, "otp": first, "new_password": "Whatever123!"})
        assert r.status_code == 400
    r = client.post("/api/v1/auth/reset-password",
                    json={"email": email, "otp": second, "new_password": "Whatever123!"})
    assert r.status_code == 200


def test_resend_cooldown_blocks_rapid_requests():
    email, _ = _register()
    _request_otp(email)
    with patch(SEND) as mock_send:
        r = client.post("/api/v1/auth/forgot-password", json={"email": email})
    assert r.status_code == 200
    mock_send.assert_not_called()


def test_otp_for_one_user_cannot_reset_another():
    a, _ = _register("a@example.com")
    b, b_old = _register("b@example.com")
    otp_a = _request_otp(a)["otp"]
    r = client.post("/api/v1/auth/reset-password",
                    json={"email": b, "otp": otp_a, "new_password": "Hijack12345!"})
    assert r.status_code == 400
    assert client.post("/api/v1/auth/login", json={"email": b, "password": b_old}).status_code == 200


def test_malformed_otp_rejected_by_validation():
    r = client.post("/api/v1/auth/reset-password",
                    json={"email": "a@example.com", "otp": "12ab56", "new_password": "Whatever123!"})
    assert r.status_code == 422


def test_smtp_unconfigured_returns_503():
    email, _ = _register()
    with patch(SEND, side_effect=ValueError("SMTP not configured")):
        r = client.post("/api/v1/auth/forgot-password", json={"email": email})
    assert r.status_code == 503
    assert "SMTP not configured" in r.json()["detail"]
