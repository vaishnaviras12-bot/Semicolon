"""
ECDAT Scanner — Cloud & IaC Detector
====================================
Statically analyzes CloudFormation, Terraform, Kubernetes YAML/Helm, Azure Bicep/ARM,
GCP deployment manifests, and CI/CD configs for cryptographic assets, KMS/HSM references,
TLS listener configurations, and external-facing exposure.
"""

import json
import os
import re
from typing import Any, Dict, List, Optional, Tuple

try:
    import yaml
except ImportError:
    yaml = None

class CloudDetectorError(Exception):
    pass


CLOUD_RESOURCE_PATTERNS = [
    # AWS KMS
    {
        "pattern": r"aws_kms_key|AWS::KMS::Key|kms\.amazonaws\.com|aws:kms|service:\s*kms|provider:\s*aws",
        "provider": "AWS",
        "service": "AWS KMS",
        "algorithm": "UNSPECIFIED",
        "asset_type": "cloud_kms_key",
        "confidence": 0.9,
    },
    # AWS ACM / Certs
    {
        "pattern": r"aws_acm_certificate|AWS::CertificateManager::Certificate|acm\.amazonaws\.com",
        "provider": "AWS",
        "service": "AWS ACM",
        "algorithm": "UNSPECIFIED",
        "asset_type": "cloud_certificate",
        "confidence": 0.9,
    },
    # AWS CloudHSM
    {
        "pattern": r"aws_cloudhsm_v2_cluster|AWS::CloudHSMv2::Cluster|cloudhsm\.amazonaws\.com",
        "provider": "AWS",
        "service": "AWS CloudHSM",
        "algorithm": "Hardware KMS / PKCS#11",
        "asset_type": "hardware_hsm",
        "confidence": 0.95,
    },
    # AWS Secrets Manager
    {
        "pattern": r"aws_secretsmanager_secret|AWS::SecretsManager::Secret|secretsmanager\.amazonaws\.com",
        "provider": "AWS",
        "service": "AWS Secrets Manager",
        "algorithm": "UNSPECIFIED",
        "asset_type": "key_reference",
        "confidence": 0.85,
    },
    # Azure Key Vault
    {
        "pattern": r"azurerm_key_vault|Microsoft\.KeyVault/vaults|vault\.azure\.net|service:\s*key-vault|provider:\s*azure",
        "provider": "Azure",
        "service": "Azure Key Vault",
        "algorithm": "UNSPECIFIED",
        "asset_type": "cloud_kms_key",
        "confidence": 0.9,
    },
    # Azure Managed HSM
    {
        "pattern": r"azurerm_key_vault_managed_hardware_security_module|Microsoft\.KeyVault/managedHSMs",
        "provider": "Azure",
        "service": "Azure Managed HSM",
        "algorithm": "FIPS 140-2 Level 3 HSM",
        "asset_type": "hardware_hsm",
        "confidence": 0.95,
    },
    # GCP KMS
    {
        "pattern": r"google_kms_crypto_key|cloudkms\.googleapis\.com|google_kms_key_ring|service:\s*cloud-kms|provider:\s*gcp|cryptoKeyVersion",
        "provider": "GCP",
        "service": "GCP Cloud KMS",
        "algorithm": "UNSPECIFIED",
        "asset_type": "cloud_kms_key",
        "confidence": 0.9,
    },
    # GCP Cloud HSM
    {
        "pattern": r"HARDWARE_SECURITY_MODULE|protectionLevel:\s*HARDWARE",
        "provider": "GCP",
        "service": "GCP Cloud HSM",
        "algorithm": "FIPS 140-2 Level 3 HSM",
        "asset_type": "hardware_hsm",
        "confidence": 0.95,
    },
    # Kubernetes TLS Secret / Ingress
    {
        "pattern": r"kubernetes\.io/tls|kind:\s*Ingress|cert-manager\.io|kind:\s*Certificate",
        "provider": "Kubernetes",
        "service": "Kubernetes Ingress / TLS Secret",
        "algorithm": "TLS X.509 Certificate",
        "asset_type": "protocol",
        "confidence": 0.85,
    },
    # HashiCorp Vault
    {
        "pattern": r"vault_generic_secret|vault_transit_secret_backend_key|vault\.hashicorp\.com",
        "provider": "HashiCorp",
        "service": "HashiCorp Vault",
        "algorithm": "UNSPECIFIED",
        "asset_type": "key_reference",
        "confidence": 0.9,
    },
]

NETWORKING_PUBLIC_PATTERNS = [
    r"0\.0\.0\.0/0",
    r"::/0",
    r"internet-facing",
    r"PubliclyAccessible\s*:\s*true",
    r"public_ly_accessible\s*=\s*true",
    r"type:\s*LoadBalancer",
]

TLS_POLICY_PATTERNS = [
    (r"ELBSecurityPolicy-2016-08|ELBSecurityPolicy-TLS-1-0", "TLS 1.0 (Deprecated / Weak)", "TLSv1.0", "high"),
    (r"ELBSecurityPolicy-TLS-1-1", "TLS 1.1 (Deprecated / Weak)", "TLSv1.1", "high"),
    (r"ELBSecurityPolicy-TLS13|ELBSecurityPolicy-TLS-1-2-2017", "TLS 1.2 / TLS 1.3", "TLSv1.2", "moderate"),
    (r"ssl_protocols.*TLSv1\b|ssl_protocols.*TLSv1\.1\b", "Nginx Legacy TLS", "TLSv1.0", "high"),
]


def _parse_cloud_block_params(snippet_block: str, default_alg: str) -> Tuple[Optional[str], Optional[int], Optional[str], Optional[str]]:
    """
    Parses exact algorithm, key_size, mode, and purpose from an IaC resource block.
    Returns (algorithm_display, key_size, mode, purpose).
    """
    lines = snippet_block.splitlines()
    sub_lines = [lines[0]] if lines else []
    for l in lines[1:]:
        if re.match(r'^\s*(resource|module|variable|output|resource_group)\s+["\']', l, re.IGNORECASE):
            break
        sub_lines.append(l)
    block_upper = "\n".join(sub_lines).upper()

    alg = None
    key_size = None
    mode = None
    purpose = None

    if "SYMMETRIC_DEFAULT" in block_upper or "AES_256" in block_upper or "AES-256" in block_upper:
        alg = "AES-256-GCM"
        key_size = 256
        mode = "GCM"
        purpose = "encryption"
    elif "RSA_SIGN_PKCS1_2048_SHA256" in block_upper:
        alg = "RSA-2048"
        key_size = 2048
        purpose = "signing"
    elif "RSA_4096" in block_upper or "RSA-4096" in block_upper or ("KEY_SIZE" in block_upper and "4096" in block_upper):
        alg = "RSA-4096"
        key_size = 4096
    elif "RSA_2048" in block_upper or "RSA-2048" in block_upper or ("KEY_SIZE" in block_upper and "2048" in block_upper) or ("RSA" in block_upper and "2048" in block_upper):
        alg = "RSA-2048"
        key_size = 2048
    elif "RSA" in block_upper and "4096" in block_upper:
        alg = "RSA-4096"
        key_size = 4096
    elif "ES256" in block_upper:
        alg = "ES256"
        purpose = "signing"
    elif "RSASSA_PKCS1_V1_5_SHA_256" in block_upper:
        alg = "RSASSA_PKCS1_V1_5_SHA_256"
        purpose = "signing"

    # Purpose matching
    if any(k in block_upper for k in ("SIGN_VERIFY", "ASYMMETRIC_SIGN", "SIGN")):
        purpose = purpose or "signing"
    elif any(k in block_upper for k in ("ENCRYPT_DECRYPT", "ENCRYPT")):
        purpose = purpose or "encryption"

    if not alg:
        if default_alg and default_alg != "UNSPECIFIED" and "/" not in default_alg:
            alg = default_alg
        else:
            alg = "UNSPECIFIED"

    return alg, key_size, mode, purpose


def scan_cloud_file(file_path: str) -> List[Dict[str, Any]]:
    """Scan a cloud / IaC configuration file for cryptographic assets and risk indicators."""
    findings = []
    ext = os.path.splitext(file_path)[1].lower()
    fname = os.path.basename(file_path).lower()

    is_cloud_file = (
        ext in (".tf", ".tfvars", ".hcl", ".yaml", ".yml", ".json", ".bicep") or
        "dockerfile" in fname or "cloudformation" in fname or "kubernetes" in fname
    )

    if not is_cloud_file:
        return findings

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except Exception as e:
        return findings

    lines = content.splitlines()

    # Config file crypto setting parsing (e.g. settings.json, appsettings.json)
    if "settings" in fname or "config" in fname:
        if "rsa_key_size" in content.lower():
            m = re.search(r'"rsa_key_size"\s*:\s*(\d+)', content, re.IGNORECASE)
            ks = int(m.group(1)) if m else 2048
            findings.append({
                "artifact_type": "algorithm",
                "algorithm": f"RSA-{ks}",
                "key_size": ks,
                "file_path": file_path,
                "line_number": 1,
                "code_snippet": "rsa_key_size: " + str(ks),
                "detection_method": "config_static_analysis",
                "confidence": 0.85,
            })
        if "elliptic_curve" in content.lower():
            findings.append({
                "artifact_type": "algorithm",
                "algorithm": "ECDSA P-256",
                "curve": "P-256",
                "file_path": file_path,
                "line_number": 1,
                "code_snippet": "elliptic_curve: secp256r1",
                "detection_method": "config_static_analysis",
                "confidence": 0.85,
            })
        if "symmetric_cipher" in content.lower():
            findings.append({
                "artifact_type": "algorithm",
                "algorithm": "AES-256",
                "key_size": 256,
                "file_path": file_path,
                "line_number": 1,
                "code_snippet": "symmetric_cipher: AES-256",
                "detection_method": "config_static_analysis",
                "confidence": 0.85,
            })

    # Search for container environment variables (e.g. ECDAT_ALGORITHM: "AES-256-GCM")
    for match in re.finditer(r'([A-Z0-9_]*ALGORITHM[A-Z0-9_]*|ECDAT_[A-Z0-9_]+)\s*:\s*["\']?([^"\'\n]+)["\']?', content, re.IGNORECASE):
        env_var = match.group(1).upper()
        env_val = match.group(2).strip()
        start_pos = match.start()
        line_no = content[:start_pos].count("\n") + 1
        snippet = lines[line_no - 1].strip() if line_no <= len(lines) else match.group(0)

        finding = {
            "artifact_type": "config_env",
            "algorithm": env_val,
            "env_var_name": env_var,
            "config_value": env_val,
            "file_path": file_path,
            "line_number": line_no,
            "code_snippet": snippet[:200],
            "detection_method": "cloud_iac_static_analysis",
            "confidence": 0.9,
            "resolution_status": "dynamic" if ("${" in env_val or "$" in env_val or env_val.startswith("$")) else "resolved",
        }
        findings.append(finding)

    # 1. Search for Cloud Cryptographic Resources
    for rule in CLOUD_RESOURCE_PATTERNS:
        matches = re.finditer(rule["pattern"], content, re.IGNORECASE)
        for match in matches:
            # Determine line number
            start_pos = match.start()
            line_no = content[:start_pos].count("\n") + 1
            snippet = lines[line_no - 1].strip() if line_no <= len(lines) else match.group(0)

            # Inspect surrounding block context (15 lines) for exact parameters
            block_end = min(len(lines), line_no + 15)
            block_text = "\n".join(lines[line_no - 1 : block_end])
            
            alg_display, parsed_ks, parsed_mode, parsed_purpose = _parse_cloud_block_params(block_text, rule["algorithm"])

            # Check if file has public exposure hints nearby
            is_external = any(re.search(p, content, re.IGNORECASE) for p in NETWORKING_PUBLIC_PATTERNS)
            exposure_level = "external" if is_external else "internal"

            finding = {
                "artifact_type": rule["asset_type"],
                "algorithm": alg_display,
                "key_size": parsed_ks or (2048 if "RSA-2048" in alg_display else None),
                "mode": parsed_mode,
                "protocol": "TLS" if rule["asset_type"] == "protocol" else None,
                "provider": rule["provider"],
                "service": rule["service"],
                "resource": snippet[:80],
                "file_path": file_path,
                "line_number": line_no,
                "code_snippet": snippet[:200],
                "detection_method": "cloud_iac_static_analysis",
                "confidence": rule["confidence"],
                "exposure": {
                    "internet_facing": is_external,
                    "public_registry": False,
                    "third_party_api": True if rule["provider"] in ("AWS", "Azure", "GCP") else False,
                },
                "evidence": {
                    "provider": rule["provider"],
                    "service": rule["service"],
                    "pattern": rule["pattern"],
                    "confidence_level": "strong evidence" if rule["confidence"] >= 0.9 else "inferred",
                    "exposure_inferred": exposure_level,
                }
            }
            if parsed_purpose:
                finding["purpose"] = parsed_purpose
            findings.append(finding)

    # 2. Search for TLS Policy / Legacy TLS in Cloud Configs
    for pattern, name, version, default_band in TLS_POLICY_PATTERNS:
        for match in re.finditer(pattern, content, re.IGNORECASE):
            start_pos = match.start()
            line_no = content[:start_pos].count("\n") + 1
            snippet = lines[line_no - 1].strip() if line_no <= len(lines) else match.group(0)

            findings.append({
                "artifact_type": "protocol",
                "algorithm": name,
                "protocol": name,
                "protocol_version": version,
                "file_path": file_path,
                "line_number": line_no,
                "code_snippet": snippet[:200],
                "detection_method": "cloud_tls_policy_analysis",
                "confidence": 0.85,
                "exposure": {
                    "internet_facing": True,
                    "public_registry": False,
                    "third_party_api": False,
                },
                "evidence": {
                    "tls_policy": name,
                    "confidence_level": "confirmed",
                }
            })

    return findings
