"""
Unit & Integration Tests for Experimental liboqs PQC Prototype Service
========================================================================
"""

import pytest
import os
import sys
from unittest.mock import patch, MagicMock

# Ensure backend root is in sys.path
_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from backend.app.services.pqc_prototype_service import run_pqc_prototype, determine_pqc_target


def test_determine_pqc_target_kem():
    rec = {"primary": "ML-KEM-768 (NIST FIPS 203)"}
    target = determine_pqc_target("RSA-2048", rec, purpose="key_establishment")
    assert target["pqc_algorithm"] == "ML-KEM-768"
    assert target["operation_mode"] == "encapsulate_decapsulate"
    assert target["is_supported"] is True


def test_determine_pqc_target_dsa():
    rec = {"primary": "ML-DSA-65 (NIST FIPS 204)"}
    target = determine_pqc_target("RSA-2048", rec, purpose="signing")
    assert target["pqc_algorithm"] == "ML-DSA-65"
    assert target["operation_mode"] == "sign_verify"
    assert target["is_supported"] is True


def test_determine_pqc_target_hybrid_note():
    rec = {"primary": "X25519 + ML-KEM-768 (Hybrid KEM)"}
    target = determine_pqc_target("ECDH", rec, purpose="key_establishment")
    assert target["hybrid_note"] == "PQC component prototype only"


def test_determine_pqc_target_manual_review():
    rec = {"primary": "ML-KEM-768 (NIST FIPS 203)"}
    target = determine_pqc_target("RSA-2048", rec, purpose="unknown")
    assert target["is_supported"] is True
    assert target["operation_mode"] == "encapsulate_decapsulate"
    assert target["pqc_algorithm"] == "ML-KEM-768"


def test_determine_pqc_target_legacy_ambiguous_finding():
    rec = {"primary": "ML-KEM-768 / ML-DSA-65"}
    target = determine_pqc_target("ECC prime256v1", rec, purpose=None)
    assert target["is_supported"] is True
    assert target["pqc_algorithm"] in ("ML-DSA-65", "ML-KEM-768")


def test_ml_kem_768_simulated_live():
    """Test 1 — ML-KEM-768 key generation, encapsulation, decapsulation, shared secret match."""
    finding_data = {
        "algorithm": "ECDH",
        "purpose": "key_establishment",
        "recommendation": {"primary": "ML-KEM-768 (NIST FIPS 203)"}
    }

    mock_client = MagicMock()
    mock_client.generate_keypair.return_value = b"public_key_32_bytes_sample_data"
    mock_client.encap_secret.return_value = (b"ciphertext_sample_data", b"shared_secret_12345")
    mock_client.decap_secret.return_value = b"shared_secret_12345"

    mock_oqs = MagicMock()
    mock_oqs.get_enabled_kem_mechanisms.return_value = ["ML-KEM-768"]
    mock_oqs.KeyEncapsulation.return_value.__enter__.return_value = mock_client

    with patch("backend.app.services.pqc_prototype_service.OQS_AVAILABLE", True), \
         patch("backend.app.services.pqc_prototype_service.oqs", mock_oqs, create=True):
        res = run_pqc_prototype(finding_data)
        assert res["status"] == "success"
        assert res["algorithm"] == "ML-KEM-768"
        assert res["operation"] == "encapsulate_decapsulate"
        assert res["validation"]["key_generation"] is True
        assert res["validation"]["encapsulation"] is True
        assert res["validation"]["decapsulation"] is True
        assert res["validation"]["shared_secret_match"] is True
        assert res["metrics"]["key_generation_ms"] >= 0
        assert res["metrics"]["public_key_bytes"] == 31
        assert res["metrics"]["ciphertext_bytes"] == 22


def test_ml_dsa_65_simulated_live():
    """Test 2 — ML-DSA-65 key generation, signing, verification."""
    finding_data = {
        "algorithm": "RSA-2048",
        "purpose": "signing",
        "recommendation": {"primary": "ML-DSA-65 (NIST FIPS 204)"}
    }

    mock_signer = MagicMock()
    mock_signer.generate_keypair.return_value = b"pub_key_bytes"
    mock_signer.sign.return_value = b"signature_bytes"
    mock_signer.verify.return_value = True

    mock_oqs = MagicMock()
    mock_oqs.get_enabled_sig_mechanisms.return_value = ["ML-DSA-65"]
    mock_oqs.Signature.return_value.__enter__.return_value = mock_signer

    with patch("backend.app.services.pqc_prototype_service.OQS_AVAILABLE", True), \
         patch("backend.app.services.pqc_prototype_service.oqs", mock_oqs, create=True):
        res = run_pqc_prototype(finding_data)
        assert res["status"] == "success"
        assert res["algorithm"] == "ML-DSA-65"
        assert res["operation"] == "sign_verify"
        assert res["validation"]["key_generation"] is True
        assert res["validation"]["signing"] is True
        assert res["validation"]["verification"] is True
        assert res["metrics"]["key_generation_ms"] >= 0
        assert res["metrics"]["signature_bytes"] == 15


def test_unavailable_liboqs():
    """Test 3 — unavailable liboqs."""
    finding_data = {
        "algorithm": "RSA-2048",
        "purpose": "signing",
        "recommendation": {"primary": "ML-DSA-65 (NIST FIPS 204)"}
    }

    with patch("backend.app.services.pqc_prototype_service.OQS_AVAILABLE", False):
        res = run_pqc_prototype(finding_data)
        assert res["status"] == "unavailable"
        assert res["library"] == "liboqs"
        assert "unavailable" in res["message"]
        assert res["metrics"] is None


def test_rsa_unknown_purpose_automated_default():
    """Test RSA with unknown purpose maps to automated default ML-KEM-768 execution."""
    finding_data = {
        "algorithm": "RSA-2048",
        "purpose": "unknown",
        "recommendation": {"primary": "ML-KEM-768 (NIST FIPS 203)"}
    }

    with patch("backend.app.services.pqc_prototype_service.OQS_AVAILABLE", True):
        res = run_pqc_prototype(finding_data)
        assert res["status"] == "success"
        assert res["algorithm"] == "ML-KEM-768"
        assert res["operation"] == "encapsulate_decapsulate"
        assert res["metrics"] is not None


def test_sha1_pure_hash_not_applicable():
    """Test pure SHA-1 returns status='not_applicable' and does NOT map to ML-KEM or ML-DSA."""
    finding_data = {
        "algorithm": "SHA-1",
        "purpose": "hashing",
        "family": "Hash",
        "recommendation": {"primary": "SHA-256 / SHA-384"}
    }
    target = determine_pqc_target("SHA-1", finding_data["recommendation"], purpose="hashing")
    assert target["operation_mode"] == "not_applicable"
    assert target["is_supported"] is False

    res = run_pqc_prototype(finding_data)
    assert res["status"] == "not_applicable"
    assert res["operation"] == "not_applicable"
    assert "hash algorithm and does not map directly" in res["reason"]
    assert res["metrics"] is None


def test_sha256_with_rsa_prototype():
    """Test SHA256withRSA maps to ML-DSA-65 prototype operation."""
    finding_data = {
        "algorithm": "RSA",
        "signature_algorithm": "SHA256withRSA",
        "purpose": "signing",
        "recommendation": {"primary": "ML-DSA-65 (NIST FIPS 204)"}
    }
    target = determine_pqc_target("RSA", finding_data["recommendation"], purpose="signing")
    assert target["pqc_algorithm"] == "ML-DSA-65"
    assert target["operation_mode"] == "sign_verify"
    assert target["is_supported"] is True


def test_ecdsa_signing_prototype():
    """Test ECDSA maps to ML-DSA-65 prototype operation."""
    finding_data = {
        "algorithm": "ECDSA",
        "purpose": "signature_verification",
        "recommendation": {"primary": "ML-DSA-65 (NIST FIPS 204)"}
    }
    target = determine_pqc_target("ECDSA", finding_data["recommendation"], purpose="signature_verification")
    assert target["pqc_algorithm"] == "ML-DSA-65"
    assert target["operation_mode"] == "sign_verify"
    assert target["is_supported"] is True


def test_ecdh_x25519_kem_prototype():
    """Test ECDH / X25519 maps to ML-KEM-768 prototype operation."""
    finding_data = {
        "algorithm": "X25519",
        "purpose": "key_establishment",
        "recommendation": {"primary": "ML-KEM-768 (NIST FIPS 203)"}
    }
    target = determine_pqc_target("X25519", finding_data["recommendation"], purpose="key_establishment")
    assert target["pqc_algorithm"] == "ML-KEM-768"
    assert target["operation_mode"] == "encapsulate_decapsulate"
    assert target["is_supported"] is True


def test_rsa_unknown_purpose_automated_ml_kem_prototype():
    """Test RSA with unknown purpose maps to automated ML-KEM-768 prototype execution."""
    finding_data = {
        "algorithm": "RSA-2048",
        "purpose": "unknown",
        "recommendation": {"primary": "ML-KEM-768 (NIST FIPS 203)"}
    }
    target = determine_pqc_target("RSA-2048", finding_data["recommendation"], purpose="unknown")
    assert target["operation_mode"] == "encapsulate_decapsulate"
    assert target["is_supported"] is True
    res = run_pqc_prototype(finding_data)
    assert res["status"] == "success"
    assert res["operation"] == "encapsulate_decapsulate"

