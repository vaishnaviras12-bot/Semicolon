"""
Schema Migration & Compatibility Tests
=======================================
Verifies that backward-compatible schema migrations correctly add missing columns
(e.g., purpose_confidence, resolution_status, detection_sources_json) to existing SQLite tables,
preserve all existing data, and operate idempotently.
"""

import os
import sqlite3
import pytest
from sqlalchemy import create_engine, inspect
from backend.app.database.connection import Base
from backend.app.database.migrations import run_schema_migrations
from backend.app.models.scan import FindingModel, UserModel, ScanModel
from sqlalchemy.orm import sessionmaker

@pytest.fixture
def old_db_path(tmp_path):
    db_file = str(tmp_path / "old_ecdat.db")
    conn = sqlite3.connect(db_file)
    cur = conn.cursor()
    
    # Create older schema tables missing new columns
    cur.execute("""
    CREATE TABLE users (
        id VARCHAR(36) PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        email VARCHAR(255) NOT NULL UNIQUE,
        password_hash VARCHAR(255) NOT NULL,
        created_at DATETIME
    )
    """)
    cur.execute("""
    CREATE TABLE scans (
        id VARCHAR(36) PRIMARY KEY,
        target_name VARCHAR(255) NOT NULL,
        status VARCHAR(50)
    )
    """)
    cur.execute("""
    CREATE TABLE findings (
        id VARCHAR(64) PRIMARY KEY,
        scan_id VARCHAR(36) NOT NULL,
        artifact_type VARCHAR(100) NOT NULL,
        algorithm VARCHAR(100),
        file_path TEXT,
        line_number INTEGER,
        layer VARCHAR(50),
        sensitivity VARCHAR(50),
        exposure_type VARCHAR(50),
        shor_vulnerable BOOLEAN,
        quantum_class VARCHAR(50),
        classically_weak BOOLEAN,
        risk_score FLOAT,
        risk_band VARCHAR(50),
        mosca_status VARCHAR(50)
    )
    """)
    
    # Insert existing seed data
    cur.execute("INSERT INTO users VALUES ('u1', 'Existing User', 'user@example.com', 'hash', '2026-01-01 00:00:00')")
    cur.execute("INSERT INTO scans VALUES ('s1', 'Existing Project', 'completed')")
    cur.execute("INSERT INTO findings VALUES ('f1', 's1', 'crypto_key', 'RSA', 'main.py', 10, 'in_use', 'high', 'external', 1, 'shor', 0, 8.5, 'high', 'ACTION_REQUIRED')")
    
    conn.commit()
    conn.close()
    return db_file

def test_run_schema_migrations_adds_missing_columns_and_preserves_data(old_db_path):
    engine = create_engine(f"sqlite:///{old_db_path}")
    
    # Execute migration
    run_schema_migrations(engine, Base)
    
    # 1. Verify inspector shows added columns
    inspector = inspect(engine)
    finding_cols = {col['name'] for col in inspector.get_columns("findings")}
    
    assert "purpose_confidence" in finding_cols
    assert "resolution_status" in finding_cols
    assert "detection_sources_json" in finding_cols
    
    # 2. Verify existing user, scan, and finding records remain intact
    conn = sqlite3.connect(old_db_path)
    cur = conn.cursor()
    cur.execute("SELECT id, name, email FROM users WHERE id='u1'")
    user = cur.fetchone()
    assert user == ('u1', 'Existing User', 'user@example.com')
    
    cur.execute("SELECT id, target_name FROM scans WHERE id='s1'")
    scan = cur.fetchone()
    assert scan == ('s1', 'Existing Project')
    
    cur.execute("SELECT id, algorithm, risk_band FROM findings WHERE id='f1'")
    finding = cur.fetchone()
    assert finding == ('f1', 'RSA', 'high')
    conn.close()
    
    # 3. Test idempotency: run migration again
    run_schema_migrations(engine, Base)
    
    # 4. Verify new Finding insertion with new fields succeeds
    Session = sessionmaker(bind=engine)
    db = Session()
    new_finding = FindingModel(
        id="f2",
        scan_id="s1",
        artifact_type="certificate",
        algorithm="ECC",
        purpose_confidence=0.9,
        resolution_status="resolved",
        detection_sources_json='["static_scanner", "ml_detector"]'
    )
    db.add(new_finding)
    db.commit()
    
    retrieved = db.query(FindingModel).filter_by(id="f2").first()
    assert retrieved is not None
    assert retrieved.purpose_confidence == 0.9
    assert retrieved.resolution_status == "resolved"
    assert retrieved.detection_sources_json == '["static_scanner", "ml_detector"]'
    db.close()
