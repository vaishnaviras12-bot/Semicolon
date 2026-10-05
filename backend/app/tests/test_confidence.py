"""
Regression tests for Confidence propagation and evidence-based confidence model
==================================================================================
"""

import pytest
import os
import sys

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
_ECDAT_ROOT = os.path.join(_ROOT, "ECDAT-main")
if _ECDAT_ROOT not in sys.path:
    sys.path.insert(0, _ECDAT_ROOT)

from cbom.algorithm_resolver import resolve_artifacts
from backend.app.services.scanner_orchestrator import ScannerOrchestrator


def test_explicit_certificate_high_confidence():
    """1. Explicit certificate algorithm -> high evidence confidence (0.95), not 1.00 default."""
    artifacts = [{
        "artifact_type": "certificate",
        "algorithm": "RSA",
        "key_size": 2048,
        "detection_method": "openssl",
        "confidence": 0.95,
        "file_path": "cert.pem"
    }]
    resolved = resolve_artifacts(artifacts)
    assert len(resolved) == 1
    assert resolved[0]["confidence"] == 0.95


def test_direct_crypto_api_high_confidence():
    """2. Direct crypto API -> high confidence (0.95)."""
    artifacts = [{
        "artifact_type": "algorithm",
        "algorithm": "AES-256-GCM",
        "detection_method": "ast_call",
        "confidence": 0.95,
        "file_path": "crypto.py"
    }]
    resolved = resolve_artifacts(artifacts)
    assert len(resolved) == 1
    assert resolved[0]["confidence"] == 0.95


def test_explicit_openssl_cli_command_confidence():
    """3. Explicit OpenSSL crypto command -> high confidence (0.95)."""
    artifacts = [{
        "artifact_type": "algorithm",
        "algorithm": "RSA-2048",
        "detection_method": "openssl_cli",
        "confidence": 0.95,
        "file_path": "Dockerfile"
    }]
    resolved = resolve_artifacts(artifacts)
    assert len(resolved) == 1
    assert resolved[0]["confidence"] == 0.95


def test_exact_iac_parameter_confidence():
    """4. Exact IaC algorithm parameter -> high confidence (0.95)."""
    artifacts = [{
        "artifact_type": "algorithm",
        "algorithm": "RSA-2048",
        "detection_method": "iac_parameter",
        "confidence": 0.95,
        "file_path": "main.tf"
    }]
    resolved = resolve_artifacts(artifacts)
    assert len(resolved) == 1
    assert resolved[0]["confidence"] == 0.95


def test_library_only_finding_not_one_hundred():
    """5. Library-only finding -> does not automatically become 1.00."""
    artifacts = [{
        "artifact_type": "library",
        "library": "OpenSSL",
        "resolution_status": "library-only",
        "detection_method": "dpkg",
        "confidence": 0.65,
        "file_path": "Dockerfile"
    }]
    resolved = resolve_artifacts(artifacts)
    assert len(resolved) == 1
    assert resolved[0]["confidence"] < 0.90
    assert resolved[0]["confidence"] != 1.00


def test_dynamic_finding_confidence():
    """6. Dynamic finding -> confidence reflects unresolved/dynamic evidence (<0.85)."""
    artifacts = [{
        "artifact_type": "algorithm",
        "algorithm": "UNSPECIFIED",
        "resolution_status": "dynamic",
        "detection_method": "env_var",
        "confidence": 0.70,
        "file_path": "dynamic_crypto.py"
    }]
    resolved = resolve_artifacts(artifacts)
    assert len(resolved) == 1
    assert resolved[0]["confidence"] == 0.70


def test_correlated_java_finding_confidence_preserved():
    """7. Correlated Java finding -> confidence is preserved after merge and not clamped to 1.00."""
    artifacts = [
        {
            "artifact_type": "algorithm",
            "algorithm": "RSA",
            "detection_method": "ast_call",
            "confidence": 0.95,
            "file_path": "Signer.java",
            "line_number": 10
        },
        {
            "artifact_type": "algorithm",
            "algorithm": "SHA256withRSA",
            "detection_method": "semgrep",
            "confidence": 0.90,
            "file_path": "Signer.java",
            "line_number": 10
        }
    ]
    resolved = resolve_artifacts(artifacts)
    assert len(resolved) == 1
    assert 0.95 <= resolved[0]["confidence"] < 1.00


def test_deduplicated_findings_not_reset_to_one_hundred():
    """8. Deduplicated findings -> confidence is not reset or clamped to 1.00."""
    artifacts = [
        {
            "artifact_type": "algorithm",
            "algorithm": "AES",
            "detection_method": "ast_call",
            "confidence": 0.95,
            "file_path": "app.py",
            "line_number": 5
        },
        {
            "artifact_type": "algorithm",
            "algorithm": "AES",
            "detection_method": "treesitter",
            "confidence": 0.95,
            "file_path": "app.py",
            "line_number": 5
        }
    ]
    resolved = resolve_artifacts(artifacts)
    assert len(resolved) == 1
    assert resolved[0]["confidence"] < 1.00


def test_orchestrator_preserves_finding_confidence():
    """9. Scanner orchestrator preserves exact finding confidence."""
    orchestrator = ScannerOrchestrator()
    res = orchestrator.run_full_scan("backend/app")
    for f in res.get("findings", []):
        assert 0.0 <= f["confidence"] <= 0.99
