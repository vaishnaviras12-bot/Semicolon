"""
Regression tests for PQCRecommendationService (Purpose-Aware Recommendation Logic)
===================================================================================
"""

import pytest
import os
import sys

# Ensure backend root is in sys.path
_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from backend.app.services.recommendation_service import PQCRecommendationService

@pytest.fixture
def service():
    return PQCRecommendationService()

@pytest.fixture
def dummy_migration_info():
    return {
        "migration_effort_hours": 80.0,
        "breaking_change_risk": "high"
    }


def test_rsa_signing_recommendation(service, dummy_migration_info):
    """1. RSA + signing -> ML-DSA-65"""
    artifact = {
        "algorithm": "RSA-2048",
        "purpose": "signing",
        "shor_vulnerable": True,
        "file_path": "crypto_app.py",
        "code_snippet": "sig = rsa.sign(data)",
    }
    rec = service.generate_recommendation(artifact, dummy_migration_info)
    assert rec["primary"] == "ML-DSA-65 (NIST FIPS 204)"
    assert "ML-KEM" not in rec["primary"]
    assert "Signature" in rec["remediation_diff"]["after"]
    assert "KeyEncapsulation" not in rec["remediation_diff"]["after"]


def test_rsa_signature_verification_recommendation(service, dummy_migration_info):
    """2. RSA + signature_verification -> ML-DSA-65"""
    artifact = {
        "algorithm": "RSA-2048",
        "purpose": "signature_verification",
        "shor_vulnerable": True,
        "file_path": "cert.pem",
    }
    rec = service.generate_recommendation(artifact, dummy_migration_info)
    assert rec["primary"] == "ML-DSA-65 (NIST FIPS 204)"
    assert "ML-KEM" not in rec["primary"]


def test_rsa_key_establishment_recommendation(service, dummy_migration_info):
    """3. RSA + key_establishment -> ML-KEM-768"""
    artifact = {
        "algorithm": "RSA-2048",
        "purpose": "key_establishment",
        "shor_vulnerable": True,
        "file_path": "tls_handshake.py",
        "code_snippet": "cipher = Cipher.getInstance('RSA/ECB/PKCS1Padding')",
    }
    rec = service.generate_recommendation(artifact, dummy_migration_info)
    assert rec["primary"] == "ML-KEM-768 (NIST FIPS 203)"
    assert "KeyEncapsulation" in rec["remediation_diff"]["after"]


def test_rsa_unknown_purpose_recommendation(service, dummy_migration_info):
    """4. RSA + unknown purpose -> NOT ML-KEM, status=Manual Cryptographic Review Required"""
    artifact = {
        "algorithm": "RSA-2048",
        "purpose": "unknown",
        "shor_vulnerable": True,
        "file_path": "keygen.py",
        "code_snippet": "key = RSA.generate(2048)",
    }
    rec = service.generate_recommendation(artifact, dummy_migration_info)
    assert rec["primary"] == "Manual Cryptographic Review Required"
    assert "ML-KEM" not in rec["primary"]
    assert "Manual Cryptographic Review Required" in rec["remediation_diff"]["after"]


def test_rsa_ambiguous_purpose_recommendation(service, dummy_migration_info):
    """5. RSA + ambiguous purpose -> Manual Cryptographic Review Required recommendation"""
    artifact = {
        "algorithm": "RSA-2048",
        "purpose": "ambiguous",
        "shor_vulnerable": True,
        "file_path": "helper.py",
        "code_snippet": "import RSA",
    }
    rec = service.generate_recommendation(artifact, dummy_migration_info)
    assert rec["primary"] == "Manual Cryptographic Review Required"


def test_rsa_shor_vulnerable_signing_recommendation(service, dummy_migration_info):
    """6. RSA + Shor vulnerability + signing -> ML-DSA-65, must NOT produce ML-KEM remediation code"""
    artifact = {
        "algorithm": "RSA-2048",
        "purpose": "signing",
        "shor_vulnerable": True,
        "file_path": "signer.py",
        "code_snippet": "Signature.getInstance('SHA256withRSA')",
    }
    rec = service.generate_recommendation(artifact, dummy_migration_info)
    assert rec["primary"] == "ML-DSA-65 (NIST FIPS 204)"
    assert "KeyEncapsulation" not in rec["remediation_diff"]["after"]
    assert "ML-KEM-768" not in rec["remediation_diff"]["after"]
    assert "Signature" in rec["remediation_diff"]["after"]


def test_rsa_shor_vulnerable_unknown_purpose_recommendation(service, dummy_migration_info):
    """7. RSA + Shor vulnerability + unknown purpose -> Manual Cryptographic Review Required recommendation"""
    artifact = {
        "algorithm": "RSA-2048",
        "purpose": "unknown",
        "shor_vulnerable": True,
        "file_path": "app.py",
        "code_snippet": "RSA.generate(2048)",
    }
    rec = service.generate_recommendation(artifact, dummy_migration_info)
    assert rec["primary"] == "Manual Cryptographic Review Required"
    assert "Manual Cryptographic Review Required" in rec["remediation_diff"]["after"]


def test_sha1_pure_hash_recommendation(service, dummy_migration_info):
    """8. Pure SHA-1 -> Hash replacement recommendation, NOT ML-KEM or ML-DSA"""
    artifact = {
        "algorithm": "SHA-1",
        "purpose": "hashing",
        "family": "Hash",
        "shor_vulnerable": False,
        "file_path": "hash_util.py",
        "code_snippet": "digest = hashlib.sha1(data).hexdigest()",
    }
    rec = service.generate_recommendation(artifact, dummy_migration_info)
    assert "SHA-256" in rec["primary"]
    assert "ML-KEM" not in rec["primary"]
    assert "ML-DSA" not in rec["primary"]
    assert "hashlib.sha256" in rec["remediation_diff"]["after"]


def test_sha256_with_rsa_signature_recommendation(service, dummy_migration_info):
    """9. SHA256withRSA -> RSA signature recommendation (ML-DSA-65)"""
    artifact = {
        "algorithm": "RSA",
        "signature_algorithm": "SHA256withRSA",
        "purpose": "signing",
        "family": "Asymmetric",
        "shor_vulnerable": True,
        "file_path": "SignatureApp.java",
        "code_snippet": "Signature.getInstance('SHA256withRSA')",
    }
    rec = service.generate_recommendation(artifact, dummy_migration_info)
    assert rec["primary"] == "ML-DSA-65 (NIST FIPS 204)"
    assert "ML-KEM" not in rec["primary"]


def test_library_only_recommendation(service, dummy_migration_info):
    """10. resolution_status = library-only -> Usage Not Detected, Not applicable — Usage Not Detected"""
    artifact = {
        "algorithm": "OpenSSL (library-only)",
        "resolution_status": "library-only",
        "artifact_type": "library",
        "file_path": "Dockerfile",
    }
    rec = service.generate_recommendation(artifact, dummy_migration_info)
    assert rec["primary"] == "Usage Not Detected"
    assert rec["hybrid"] == "Not applicable — Usage Not Detected"



