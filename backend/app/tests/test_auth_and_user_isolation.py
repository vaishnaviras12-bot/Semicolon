"""
Unit & Integration Tests for Auth, Persistence, Strict User Isolation & Zip Security
====================================================================================
Tests user registration, login, user profile, user-scoped scan history,
Zip Slip security enforcement, active scan reminders, and strict 404 isolation.
"""

import io
import os
import shutil
import zipfile
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.app.main import app
from backend.app.database.connection import Base, get_db
from backend.app.models.scan import UserModel, ScanModel, FindingModel

# In-memory SQLite for isolated test suite
SQLALCHEMY_DATABASE_URL = "sqlite:///./test_auth_isolation.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def override_get_db():
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db
client = TestClient(app)

import backend.app.services.scan_service as ss_module

@pytest.fixture(autouse=True)
def setup_db(monkeypatch):
    app.dependency_overrides[get_db] = override_get_db
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    monkeypatch.setattr(ss_module, "SessionLocal", TestingSessionLocal)
    yield
    Base.metadata.drop_all(bind=engine)
    app.dependency_overrides.clear()


def test_user_registration_and_login():
    """Test user registration, duplicate email rejection, and login JWT token issue."""
    # 1. Register User A
    reg_resp = client.post("/api/auth/register", json={
        "name": "Alice User",
        "email": "alice@example.com",
        "password": "Password123!"
    })
    assert reg_resp.status_code == 201, reg_resp.text
    data = reg_resp.json()
    assert "access_token" in data
    assert data["user"]["email"] == "alice@example.com"
    token_a = data["access_token"]

    # 2. Duplicate registration attempt should fail with 400
    dup_resp = client.post("/api/auth/register", json={
        "name": "Alice Duplicate",
        "email": "alice@example.com",
        "password": "Password123!"
    })
    assert dup_resp.status_code == 400
    assert "already registered" in dup_resp.json()["detail"]

    # 3. Login User A
    login_resp = client.post("/api/auth/login", json={
        "email": "alice@example.com",
        "password": "Password123!"
    })
    assert login_resp.status_code == 200
    token_login = login_resp.json()["access_token"]
    assert token_login

    # 4. GET /api/auth/me with Bearer token
    me_resp = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token_login}"})
    assert me_resp.status_code == 200
    assert me_resp.json()["name"] == "Alice User"

def test_strict_user_isolation():
    """
    Test strict user isolation: User B must receive 404 Not Found when trying
    to view, poll status, fetch findings, fetch reminders, or delete User A's scan.
    """
    # Register Alice (User A)
    reg_a = client.post("/api/auth/register", json={
        "name": "Alice", "email": "alice_iso@example.com", "password": "Password123!"
    }).json()
    token_a = reg_a["access_token"]

    # Register Bob (User B)
    reg_b = client.post("/api/auth/register", json={
        "name": "Bob", "email": "bob_iso@example.com", "password": "Password123!"
    }).json()
    token_b = reg_b["access_token"]

    # Alice creates a scan
    scan_resp = client.post(
        "/api/scans",
        json={"project_name": "Alice Project", "target_name": "Sample Repo"},
        headers={"Authorization": f"Bearer {token_a}"}
    )
    assert scan_resp.status_code == 202
    scan_id = scan_resp.json()["scan_id"]

    # Alice can list her scan
    list_a = client.get("/api/scans", headers={"Authorization": f"Bearer {token_a}"})
    assert len(list_a.json()) == 1
    assert list_a.json()[0]["scan_id"] == scan_id

    # Bob's scan list is empty
    list_b = client.get("/api/scans", headers={"Authorization": f"Bearer {token_b}"})
    assert len(list_b.json()) == 0

    # Bob attempts to access Alice's scan endpoints -> ALL MUST RETURN 404 NOT FOUND
    assert client.get(f"/api/scans/{scan_id}/status", headers={"Authorization": f"Bearer {token_b}"}).status_code == 404
    assert client.get(f"/api/scans/{scan_id}/findings", headers={"Authorization": f"Bearer {token_b}"}).status_code == 404
    assert client.get(f"/api/scans/{scan_id}/cbom", headers={"Authorization": f"Bearer {token_b}"}).status_code == 404
    assert client.get(f"/api/scans/{scan_id}/reminders", headers={"Authorization": f"Bearer {token_b}"}).status_code == 404
    assert client.delete(f"/api/scans/{scan_id}", headers={"Authorization": f"Bearer {token_b}"}).status_code == 404

    # Alice can fetch her own scan status & delete it successfully
    assert client.get(f"/api/scans/{scan_id}/status", headers={"Authorization": f"Bearer {token_a}"}).status_code == 200
    del_resp = client.delete(f"/api/scans/{scan_id}", headers={"Authorization": f"Bearer {token_a}"})
    assert del_resp.status_code == 200
    assert del_resp.json()["message"] == "Scan deleted successfully"

def test_scan_reminders():
    """Test /api/scans/{id}/reminders endpoint generates actionable items for critical/high findings."""
    # Register user
    reg = client.post("/api/auth/register", json={
        "name": "Reminder User", "email": "reminder@example.com", "password": "Password123!"
    }).json()
    token = reg["access_token"]

    # Seed a scan and findings directly in DB
    db = TestingSessionLocal()
    scan_id = "test-scan-reminders-id"
    user_id = reg["user"]["id"]

    scan = ScanModel(id=scan_id, user_id=user_id, project_name="Reminder Test", target_name="Crypto Target")
    f1 = FindingModel(
        id="f1", scan_id=scan_id, artifact_type="algorithm", algorithm="RSA-2048", risk_band="critical", risk_score=9.2,
        shor_vulnerable=True, file_path="crypto/rsa.py", line_number=42, effort_level="High"
    )
    f2 = FindingModel(
        id="f2", scan_id=scan_id, artifact_type="algorithm", algorithm="AES-256-GCM", risk_band="safe", risk_score=0.0,
        shor_vulnerable=False, file_path="crypto/aes.py", line_number=10, effort_level="Low"
    )
    db.add_all([scan, f1, f2])
    db.commit()
    db.close()

    # Call /api/scans/{scan_id}/reminders
    rem_resp = client.get(f"/api/scans/{scan_id}/reminders", headers={"Authorization": f"Bearer {token}"})
    assert rem_resp.status_code == 200
    data = rem_resp.json()
    assert data["count"] == 1
    reminder = data["reminders"][0]
    assert reminder["algorithm"] == "RSA-2048"
    assert reminder["risk_band"] == "critical"
    assert reminder["shor_vulnerable"] is True

def test_zip_slip_security():
    """Test that a malicious ZIP archive with Zip Slip path traversal is rejected."""
    reg = client.post("/api/auth/register", json={
        "name": "Security Tester", "email": "zipsec@example.com", "password": "Password123!"
    }).json()
    token = reg["access_token"]

    # Create in-memory zip file with path traversal entry
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w") as zf:
        zf.writestr("../../malicious_file.py", "print('hacked')")
    zip_buffer.seek(0)

    # Upload zip file
    resp = client.post(
        "/api/scans/upload",
        files={"file": ("malicious.zip", zip_buffer, "application/zip")},
        headers={"Authorization": f"Bearer {token}"}
    )
    assert resp.status_code == 400
    assert "Zip Slip path traversal attack detected" in resp.json()["detail"]


def test_login_and_jwt_regression_cases():
    """Test valid login, invalid password (401), nonexistent email (401), valid JWT, expired JWT, malformed JWT."""
    from datetime import timedelta
    from backend.app.utils.auth import create_access_token

    # 1. Register test user
    reg = client.post("/api/v1/auth/register", json={
        "name": "Auth Tester",
        "email": "authtest@example.com",
        "password": "Password123!"
    })
    assert reg.status_code == 201

    # 2. Valid Login -> 200 OK
    login_ok = client.post("/api/v1/auth/login", json={
        "email": "authtest@example.com",
        "password": "Password123!"
    })
    assert login_ok.status_code == 200
    token = login_ok.json()["access_token"]
    assert token

    # 3. Invalid password -> 401 Unauthorized
    login_bad_pw = client.post("/api/v1/auth/login", json={
        "email": "authtest@example.com",
        "password": "WrongPassword!"
    })
    assert login_bad_pw.status_code == 401

    # 4. Nonexistent email -> 401 Unauthorized
    login_no_user = client.post("/api/v1/auth/login", json={
        "email": "nobody@example.com",
        "password": "Password123!"
    })
    assert login_no_user.status_code == 401

    # 5. Valid JWT -> GET /auth/me returns 200 OK (test both /api/v1/auth/me and /api/auth/me)
    me_v1 = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_v1.status_code == 200
    assert me_v1.json()["email"] == "authtest@example.com"

    me_legacy = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_legacy.status_code == 200

    # 6. Expired JWT -> GET /auth/me returns 401 Unauthorized
    expired_token = create_access_token(
        user_id=reg.json()["user"]["id"],
        email="authtest@example.com",
        expires_delta=timedelta(hours=-2)
    )
    me_expired = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {expired_token}"})
    assert me_expired.status_code == 401

    # 7. Malformed JWT -> GET /auth/me returns 401 Unauthorized
    me_malformed = client.get("/api/v1/auth/me", headers={"Authorization": "Bearer malformed.jwt.token"})
    assert me_malformed.status_code == 401


def test_authenticated_user_access_cbom_and_compliance():
    """Test existing authenticated user can access CBOM and Compliance endpoints."""
    from backend.app.models.scan import CBOMModel

    # Register user
    reg = client.post("/api/v1/auth/register", json={
        "name": "CBOM User",
        "email": "cbomuser@example.com",
        "password": "Password123!"
    }).json()
    token = reg["access_token"]
    user_id = reg["user"]["id"]

    # Seed scan and CBOM
    db = TestingSessionLocal()
    scan_id = "test-cbom-compliance-scan-id"
    scan = ScanModel(id=scan_id, user_id=user_id, project_name="CBOM Project", target_name="Target App", status="completed")
    f1 = FindingModel(
        id="f-cbom-1", scan_id=scan_id, artifact_type="algorithm", algorithm="RSA-2048", risk_band="high", risk_score=7.5,
        shor_vulnerable=True, file_path="app.py", line_number=1, effort_level="Medium", resolution_status="resolved"
    )
    cbom_item = CBOMModel(scan_id=scan_id, cbom_json={"components": [{"name": "RSA", "type": "crypto"}]}, cyclonedx_json={"bomFormat": "CycloneDX"})
    db.add_all([scan, f1, cbom_item])
    db.commit()
    db.close()

    # Access CBOM -> 200 OK
    cbom_resp = client.get(f"/api/v1/scans/{scan_id}/cbom", headers={"Authorization": f"Bearer {token}"})
    assert cbom_resp.status_code == 200
    assert "components" in cbom_resp.json()

    # Access Compliance -> 200 OK
    comp_resp = client.get(f"/api/v1/scans/{scan_id}/compliance", headers={"Authorization": f"Bearer {token}"})
    assert comp_resp.status_code == 200
    assert "summary" in comp_resp.json() or "controls" in comp_resp.json()

