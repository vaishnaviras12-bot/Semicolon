"""
Automated Backend & Pipeline Unit Tests
========================================
Tests FastAPI endpoints, scanner orchestration, Cloud/IaC detector, Hardware detector,
CBOM generation, CycloneDX export, Risk Engine, MTech adapter, and Mosca calculations.
"""

import os
import sys
import pytest
from fastapi.testclient import TestClient

_ROOT_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../"))
if _ROOT_PATH not in sys.path:
    sys.path.insert(0, _ROOT_PATH)

from backend.app.main import app
from backend.app.services.scanner_orchestrator import ScannerOrchestrator
from backend.app.migration.mtech_adapter import MTechMigrationAdapter
from backend.app.services.mosca_service import MoscaService

client = TestClient(app)

def test_health_check():
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"

def test_system_info():
    response = client.get("/api/v1/system/info")
    assert response.status_code == 200
    data = response.json()
    assert "cloud_iac" in data["scanners_available"]
    assert "hardware_hsm" in data["scanners_available"]

def test_mtech_adapter():
    adapter = MTechMigrationAdapter()
    rsa_finding = {"algorithm": "RSA-2048", "artifact_type": "algorithm", "shor_vulnerable": True}
    res = adapter.calculate_effort(rsa_finding)
    assert res.migration_effort_hours > 0
    assert res.effort_level in ("Low", "Medium", "High", "Critical")

def test_mosca_service():
    mosca = MoscaService(q_day_year=2035, reference_year=2026)
    finding = {"sensitivity": "critical", "shor_vulnerable": True}
    res = mosca.calculate_finding_mosca(finding, migration_years=2.0)
    assert res["mosca_x"] == 15.0
    assert res["mosca_y"] == 2.0
    assert res["mosca_z"] == 9.0
    assert res["breach"] is True

def test_full_scanner_orchestrator():
    orchestrator = ScannerOrchestrator()
    sample_dir = os.path.abspath("./ECDAT-main/samples")
    result = orchestrator.run_full_scan(sample_dir)
    assert "artifact_count" in result
    assert "cbom" in result
    assert "cyclonedx" in result
    assert result["cyclonedx"]["bomFormat"] == "CycloneDX"
