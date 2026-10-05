"""
ECDAT Scanner — Hardware & Security Module (HSM) Detector
==========================================================
Statically inspects source code, configurations, build files, and scripts for evidence of
hardware-backed cryptography, HSMs, PKCS#11 providers, TPM 2.0 modules, YubiHSM, and smart cards.
"""

import os
import re
from typing import Any, Dict, List

HARDWARE_CRYPTO_PATTERNS = [
    # PKCS#11 Native Modules & Libraries
    {
        "pattern": r"libpkcs11\.so|pkcs11\.dll|SunPKCS11|CKM_RSA_PKCS|CK_SESSION_HANDLE|pkcs11\.h|#include\s*<pkcs11\.h>",
        "name": "PKCS#11 Hardware Security Module Interface",
        "category": "PKCS#11 HSM",
        "algorithm": "Hardware Key Store / RSA / ECC",
        "confidence": 0.95,
    },
    # TPM 2.0 Evidence
    {
        "pattern": r"/dev/tpm\d*|tpm2_tss|TSS2_SYS|TPM2B_PUBLIC|tpm2_createprimary|TPM_ALG_RSA|TPM_ALG_ECC",
        "name": "Trusted Platform Module (TPM 2.0)",
        "category": "TPM 2.0",
        "algorithm": "Hardware TPM Key / RSA-2048 / ECC P-256",
        "confidence": 0.90,
    },
    # YubiHSM / Smartcards
    {
        "pattern": r"yubihsm|openSC|pcsc-lite|winscard|SmartCard|SCARD_E_NO_SMARTCARD",
        "name": "YubiHSM / Smart Card Hardware Tokens",
        "category": "Hardware Token",
        "algorithm": "Hardware Key Store / RSA / ECC",
        "confidence": 0.90,
    },
    # Java Hardware Provider Keystores
    {
        "pattern": r'KeyStore\.getInstance\s*\(\s*["\']PKCS11["\']\s*\)|SunPKCS11-|\.addProvider\s*\(\s*new\s+SunPKCS11',
        "name": "Java PKCS#11 Hardware Security Provider",
        "category": "Java Hardware KeyStore",
        "algorithm": "Hardware Keystore / RSA / ECC",
        "confidence": 0.95,
    },
    # AWS CloudHSM / Azure HSM Native Client Libraries
    {
        "pattern": r"libcloudhsm_pkcs11\.so|aws_cloudhsm_client|AzureDedicatedHSM",
        "name": "Cloud Hardware Security Module Client Library",
        "category": "Cloud HSM Client",
        "algorithm": "Hardware HSM Key",
        "confidence": 0.95,
    },
]


def scan_hardware_file(file_path: str) -> List[Dict[str, Any]]:
    """Scan code or config file for static hardware-backed crypto evidence."""
    findings = []
    ext = os.path.splitext(file_path)[1].lower()

    # Skip large binary files unless they are relevant source/config files
    if ext in (".png", ".jpg", ".pdf", ".zip", ".tar", ".gz", ".exe", ".dll", ".so") and not file_path.endswith("pkcs11.so"):
        return findings

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except Exception:
        return findings

    lines = content.splitlines()

    for rule in HARDWARE_CRYPTO_PATTERNS:
        matches = re.finditer(rule["pattern"], content, re.IGNORECASE)
        for match in matches:
            start_pos = match.start()
            line_no = content[:start_pos].count("\n") + 1
            snippet = lines[line_no - 1].strip() if line_no <= len(lines) else match.group(0)

            findings.append({
                "artifact_type": "hardware_backed_crypto",
                "algorithm": rule["algorithm"],
                "purpose": "Hardware-backed Cryptographic Operations",
                "file_path": file_path,
                "line_number": line_no,
                "code_snippet": snippet[:200],
                "detection_method": "hardware_hsm_static_analysis",
                "confidence": rule["confidence"],
                "hardware_reference": {
                    "category": rule["category"],
                    "name": rule["name"],
                    "pattern_matched": rule["pattern"],
                    "evidence_type": "hardware_backed_crypto_reference",
                },
                "evidence": {
                    "hardware_type": rule["category"],
                    "description": rule["name"],
                    "confidence_level": "strong evidence" if rule["confidence"] >= 0.9 else "inferred",
                }
            })

    return findings
