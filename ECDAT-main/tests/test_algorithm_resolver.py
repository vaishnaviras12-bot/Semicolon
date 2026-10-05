"""
Unit tests for ECDAT Central Algorithm Resolution and Normalization Layer
==========================================================================
"""

import pytest
import os
import sys

# Ensure ECDAT-main is on sys.path
_ECDAT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _ECDAT_DIR not in sys.path:
    sys.path.insert(0, _ECDAT_DIR)

from cbom.algorithm_resolver import resolve_artifact, resolve_artifacts, AlgorithmResolver


def test_rsa_oid_lookup():
    artifact = {
        "artifact_type": "certificate",
        "oid": "1.2.840.113549.1.1.11",
        "code_snippet": "OID 1.2.840.113549.1.1.11 sha256WithRSAEncryption",
        "file_path": "cert.pem",
    }
    resolved = resolve_artifact(artifact)
    assert resolved["resolution_status"] == "resolved"
    assert resolved["algorithm"] == "RSA"
    assert resolved["signature_hash"] == "SHA-256"


def test_ecdsa_p256_oid_lookup():
    artifact = {
        "artifact_type": "certificate",
        "oid": "1.2.840.10045.3.1.7",
        "file_path": "server.crt",
    }
    resolved = resolve_artifact(artifact)
    assert resolved["resolution_status"] == "resolved"
    assert resolved["algorithm"] == "ECDSA"
    assert resolved["curve"] == "P-256"


def test_java_cipher_literal_parsing():
    artifact = {
        "artifact_type": "algorithm",
        "code_snippet": 'Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");',
        "file_path": "CryptoUtils.java",
    }
    resolved = resolve_artifact(artifact)
    assert resolved["resolution_status"] == "resolved"
    assert resolved["algorithm"] == "AES"
    assert resolved["mode"] == "GCM"
    assert resolved["padding"] == "NoPadding"
    assert resolved["purpose"] == "encryption"


def test_java_signature_parsing_and_rsa_purpose():
    artifact = {
        "artifact_type": "algorithm",
        "code_snippet": 'Signature sig = Signature.getInstance("SHA256withRSA"); sig.sign();',
        "file_path": "Signer.java",
    }
    resolved = resolve_artifact(artifact)
    assert resolved["resolution_status"] == "resolved"
    assert resolved["algorithm"] == "RSA"
    assert resolved["purpose"] == "signing"
    assert resolved["purpose"] != "kem"


def test_python_cryptography_aes_gcm():
    artifact = {
        "artifact_type": "algorithm",
        "code_snippet": 'cipher = AES.new(key, AES.MODE_GCM)',
        "file_path": "encrypt.py",
    }
    resolved = resolve_artifact(artifact)
    assert resolved["resolution_status"] == "resolved"
    assert resolved["algorithm"] == "AES"
    assert resolved["mode"] == "GCM"
    assert resolved["family"] == "Symmetric"


def test_python_rsa_key_generation():
    artifact = {
        "artifact_type": "algorithm",
        "code_snippet": 'private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)',
        "file_path": "keygen.py",
    }
    resolved = resolve_artifact(artifact)
    assert resolved["resolution_status"] == "resolved"
    assert resolved["algorithm"] == "RSA"
    assert resolved["key_size"] == 2048
    # RSA generation without operational sign/encrypt call should resolve to purpose 'unknown' or 'key_establishment'
    assert resolved["purpose"] in ("unknown", "key_establishment")


def test_js_crypto_createhash_sha256():
    artifact = {
        "artifact_type": "hash",
        "code_snippet": 'const hash = crypto.createHash("sha256");',
        "file_path": "hasher.js",
    }
    resolved = resolve_artifact(artifact)
    assert resolved["resolution_status"] == "resolved"
    assert resolved["algorithm"] == "SHA-256"
    assert resolved["family"] == "Hash"
    assert resolved["purpose"] == "hashing"


def test_certificate_key_and_signature_separation():
    artifact = {
        "artifact_type": "certificate",
        "algorithm": "RSA",
        "key_size": 2048,
        "certificate_signature_algorithm": "SHA256withRSA",
        "certificate_issuer": "CN=Test CA",
        "file_path": "tls.crt",
    }
    resolved = resolve_artifact(artifact)
    assert resolved["resolution_status"] == "resolved"
    assert resolved["public_key_algorithm"] == "RSA"
    assert resolved["signature_algorithm"] == "SHA256withRSA"
    assert resolved["certificate_details"]["public_key_algorithm"] == "RSA"
    assert resolved["certificate_details"]["signature_algorithm"] == "SHA256withRSA"


def test_docker_library_only_detection():
    artifact = {
        "artifact_type": "import_signal",
        "file_path": "Dockerfile",
        "code_snippet": "RUN apt-get update && apt-get install -y openssl",
        "library": "openssl",
    }
    resolved = resolve_artifact(artifact)
    assert resolved["resolution_status"] == "library-only"
    assert resolved["observed_algorithm_usage"] == "unknown"
    assert resolved["cbom_category"] == "Library"


def test_dependency_manifest_library_only():
    artifact = {
        "artifact_type": "import_signal",
        "file_path": "requirements.txt",
        "code_snippet": "cryptography==41.0.0",
        "library": "cryptography",
    }
    resolved = resolve_artifact(artifact)
    assert resolved["resolution_status"] == "library-only"
    assert resolved["observed_algorithm_usage"] == "unknown"


def test_dynamic_call_detection():
    artifact = {
        "artifact_type": "algorithm",
        "code_snippet": 'Cipher cipher = Cipher.getInstance(algoVariable);',
        "file_path": "DynamicCrypto.java",
    }
    resolved = resolve_artifact(artifact)
    assert resolved["resolution_status"] == "dynamic"
    assert resolved["algorithm"] == "Runtime-configured"


def test_evidence_correlation_and_merging():
    artifacts = [
        {
            "file_path": "CryptoService.py",
            "line_number": 42,
            "algorithm": "AES-256",
            "detection_method": "python_ast",
            "confidence": 0.8,
            "code_snippet": "AES.new(key, AES.MODE_GCM)",
        },
        {
            "file_path": "CryptoService.py",
            "line_number": 42,
            "algorithm": "AES",
            "detection_method": "semgrep",
            "confidence": 0.9,
            "code_snippet": "AES.new(key, AES.MODE_GCM)",
        },
    ]
    resolved_merged = resolve_artifacts(artifacts, merge_evidence=True)
    assert len(resolved_merged) == 1
    merged_item = resolved_merged[0]
    assert merged_item["algorithm"] == "AES"
    assert merged_item["key_size"] == 256
    assert set(merged_item["detection_sources"]) == {"python_ast", "semgrep"}
    assert merged_item["confidence"] >= 0.9


def test_correlation_test_1_library_only():
    """Test 1: Standalone Dockerfile package installation with no source usage remains library-only"""
    artifacts = [
        {
            "artifact_type": "import_signal",
            "file_path": "Dockerfile",
            "code_snippet": "RUN apt-get update && apt-get install -y openssl",
            "library": "openssl",
        }
    ]
    resolved = resolve_artifacts(artifacts, merge_evidence=True)
    assert len(resolved) == 1
    item = resolved[0]
    assert any("No source API usage detected" in e for e in item["purpose_evidence"])


def test_correlation_test_2_docker_rsa_source_usage():
    """Test 2: Dockerfile + RSA source usage correlates into 1 resolved RSA finding"""
    artifacts = [
        {
            "artifact_type": "import_signal",
            "file_path": "Dockerfile",
            "code_snippet": "RUN apt-get update && apt-get install -y openssl",
            "library": "openssl",
        },
        {
            "artifact_type": "algorithm",
            "file_path": "Signer.java",
            "line_number": 14,
            "code_snippet": 'Signature sig = Signature.getInstance("SHA256withRSA"); sig.sign();',
        }
    ]
    resolved = resolve_artifacts(artifacts, merge_evidence=True)
    assert len(resolved) == 1
    item = resolved[0]
    assert item["algorithm"] == "RSA"
    assert item["purpose"] == "signing"
    assert item["resolution_status"] == "resolved"
    assert "dockerfile" in item["detection_sources"]


def test_correlation_test_3_docker_ecdh_source_usage():
    """Test 3: Dockerfile + ECDH source usage correlates into 1 resolved ECDH finding"""
    artifacts = [
        {
            "artifact_type": "import_signal",
            "file_path": "Dockerfile",
            "code_snippet": "RUN pip install cryptography",
            "library": "cryptography",
        },
        {
            "artifact_type": "algorithm",
            "file_path": "key_exchange.py",
            "line_number": 22,
            "code_snippet": 'shared_key = ECDH().derive(peer_key)',
            "algorithm": "ECDH",
        }
    ]
    resolved = resolve_artifacts(artifacts, merge_evidence=True)
    assert len(resolved) == 1
    item = resolved[0]
    assert item["algorithm"] == "ECDH"
    assert item["purpose"] == "key_establishment"
    assert item["resolution_status"] == "resolved"


def test_correlation_test_4_docker_sha256_source_usage():
    """Test 4: Dockerfile + SHA-256 source usage correlates into 1 resolved SHA-256 finding"""
    artifacts = [
        {
            "artifact_type": "import_signal",
            "file_path": "Dockerfile",
            "code_snippet": "RUN apt-get install -y libssl-dev",
            "library": "libssl-dev",
        },
        {
            "artifact_type": "algorithm",
            "file_path": "hash_util.c",
            "line_number": 10,
            "code_snippet": 'EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);',
        }
    ]
    resolved = resolve_artifacts(artifacts, merge_evidence=True)
    assert len(resolved) == 1
    item = resolved[0]
    assert item["algorithm"] == "SHA-256"
    assert item["purpose"] == "hashing"
    assert item["resolution_status"] == "resolved"


def test_correlation_test_5_docker_aes_source_usage():
    """Test 5: Dockerfile + AES source usage correlates into 1 resolved AES finding"""
    artifacts = [
        {
            "artifact_type": "import_signal",
            "file_path": "Dockerfile",
            "code_snippet": "RUN apt-get install -y openssl",
            "library": "openssl",
        },
        {
            "artifact_type": "algorithm",
            "file_path": "cipher.c",
            "line_number": 5,
            "code_snippet": 'EVP_CIPHER_CTX_new(EVP_aes_256_gcm());',
        }
    ]
    resolved = resolve_artifacts(artifacts, merge_evidence=True)
    assert len(resolved) == 1
    item = resolved[0]
    assert item["algorithm"] == "AES"
    assert item["key_size"] == 256
    assert item["mode"] == "GCM"
    assert item["purpose"] == "encryption"
    assert item["resolution_status"] == "resolved"


def test_correlation_test_6_certificate_correlation():
    """Test 6: Certificate public key & signature algorithm correlation"""
    artifacts = [
        {
            "artifact_type": "import_signal",
            "file_path": "Dockerfile",
            "code_snippet": "RUN apt-get install -y openssl",
            "library": "openssl",
        },
        {
            "artifact_type": "certificate",
            "file_path": "server.crt",
            "algorithm": "RSA",
            "key_size": 2048,
            "certificate_signature_algorithm": "SHA256withRSA",
        }
    ]
    resolved = resolve_artifacts(artifacts, merge_evidence=True)
    assert len(resolved) == 1
    item = resolved[0]
    assert item["public_key_algorithm"] == "RSA"
    assert item["key_size"] == 2048
    assert item["purpose"] == "signature_verification"


def test_correlation_test_7_binary_correlation():
    """Test 7: Binary crypto symbol correlation with Dockerfile"""
    artifacts = [
        {
            "artifact_type": "import_signal",
            "file_path": "Dockerfile",
            "code_snippet": "RUN apt-get install -y openssl",
            "library": "openssl",
        },
        {
            "artifact_type": "algorithm",
            "file_path": "bin/app.exe",
            "code_snippet": "Imported symbol: EVP_DigestSignInit",
            "algorithm": "RSA",
            "detection_method": "binary_analysis",
        }
    ]
    resolved = resolve_artifacts(artifacts, merge_evidence=True)
    assert len(resolved) == 1
    item = resolved[0]
    assert item["algorithm"] == "RSA"
    assert "dockerfile" in item["detection_sources"]


def test_correlation_test_8_dynamic_algorithm():
    """Test 8: Dynamic algorithm parameter call remains dynamic without fabricated algorithm"""
    artifacts = [
        {
            "artifact_type": "algorithm",
            "file_path": "Dynamic.java",
            "code_snippet": 'Signature.getInstance(config["algo"]);',
        }
    ]
    resolved = resolve_artifacts(artifacts, merge_evidence=True)
    assert len(resolved) == 1
    item = resolved[0]
    assert item["resolution_status"] == "dynamic"
    assert item["algorithm"] == "Runtime-configured"


def test_correlation_test_9_multiple_sources_deduplication():
    """Test 9: Dockerfile + Source + Binary + Cert correlate into 1 canonical artifact with multi-source evidence"""
    artifacts = [
        {"artifact_type": "import_signal", "file_path": "Dockerfile", "code_snippet": "RUN apt-get install -y openssl", "library": "openssl"},
        {"artifact_type": "algorithm", "file_path": "Signer.py", "line_number": 10, "algorithm": "RSA", "code_snippet": "rsa.sign()", "detection_method": "treesitter"},
        {"artifact_type": "algorithm", "file_path": "Signer.py", "line_number": 10, "algorithm": "RSA", "code_snippet": "rsa.sign()", "detection_method": "binary_analysis"},
        {"artifact_type": "certificate", "file_path": "cert.pem", "algorithm": "RSA", "key_size": 2048},
    ]
    resolved = resolve_artifacts(artifacts, merge_evidence=True)
    rsa_items = [a for a in resolved if a.get("algorithm") == "RSA"]
    assert len(rsa_items) >= 1
    primary_rsa = rsa_items[0]
    assert primary_rsa["resolution_status"] == "resolved"
    assert "dockerfile" in primary_rsa["detection_sources"]

