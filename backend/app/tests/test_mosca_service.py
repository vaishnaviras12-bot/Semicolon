"""
Mosca Service Unit Tests
========================
Verifies:
1. Breach calculations at P25 (8y), P50 (13y), and P75 (21y).
2. Classification rules:
   - ECDSA -> signature-only
   - Ed25519 -> signature-only
   - RSA key exchange / encryption -> HNDL-relevant (dual-use)
   - RSA certificate / unspecified -> HNDL-relevant (dual-use note)
   - AES / Hash -> Not Shor-vulnerable / Not HNDL-relevant
"""

import pytest
from backend.app.services.mosca_service import MoscaService

@pytest.fixture
def mosca_svc():
    return MoscaService(p25=8, p50=13, p75=21)

def test_classification_rules(mosca_svc):
    # 1. ECDSA (pure signature)
    ecdsa_art = {"algorithm": "ECDSA-P256", "purpose": "digital_signature", "shor_vulnerable": True}
    c_ecdsa = mosca_svc.classify_artifact(ecdsa_art)
    assert c_ecdsa["is_shor"] is True
    assert c_ecdsa["signature_only"] is True
    assert c_ecdsa["hndl_relevant"] is False

    # 2. Ed25519 (pure signature)
    ed_art = {"algorithm": "Ed25519", "purpose": "signature", "shor_vulnerable": True}
    c_ed = mosca_svc.classify_artifact(ed_art)
    assert c_ed["signature_only"] is True
    assert c_ed["hndl_relevant"] is False

    # 3. RSA Key Exchange / Encryption (HNDL-relevant dual-use)
    rsa_enc = {"algorithm": "RSA-2048", "purpose": "key_exchange", "shor_vulnerable": True}
    c_rsa_enc = mosca_svc.classify_artifact(rsa_enc)
    assert c_rsa_enc["is_shor"] is True
    assert c_rsa_enc["hndl_relevant"] is True
    assert c_rsa_enc["is_dual_use"] is True
    assert "dual-use" in c_rsa_enc["purpose_note"]

    # 4. RSA Certificate (unspecified / dual-use)
    rsa_cert = {"algorithm": "RSA-4096", "purpose": None, "shor_vulnerable": True, "artifact_type": "certificate"}
    c_rsa_cert = mosca_svc.classify_artifact(rsa_cert)
    assert c_rsa_cert["hndl_relevant"] is True
    assert c_rsa_cert["is_dual_use"] is True

    # 5. AES-256 (not Shor-vulnerable)
    aes_art = {"algorithm": "AES-256-GCM", "purpose": "encryption", "shor_vulnerable": False}
    c_aes = mosca_svc.classify_artifact(aes_art)
    assert c_aes["is_shor"] is False
    assert c_aes["hndl_relevant"] is False
    assert c_aes["signature_only"] is False

def test_breach_calculation_p25_p50_p75(mosca_svc):
    # Shelf-life X = 10y, Migration Y = 4y -> RequiredUntil = 14y
    # P25 = 8y -> at_p25 = +6y (Breached)
    # P50 = 13y -> at_p50 = +1y (Breached)
    # P75 = 21y -> at_p75 = -7y (Safe)
    art = {"algorithm": "RSA-2048", "sensitivity": "high", "shor_vulnerable": True}
    res = mosca_svc.calculate_finding_mosca(art, migration_years=4.0)

    assert res["required_until"] == 14.0
    assert res["at_p25"] == 6.0
    assert res["breach_p25"] is True
    assert res["at_p50"] == 1.0
    assert res["breach_p50"] is True
    assert res["at_p75"] == -7.0
    assert res["breach_p75"] is False
    assert res["status"] == "breach-median"
