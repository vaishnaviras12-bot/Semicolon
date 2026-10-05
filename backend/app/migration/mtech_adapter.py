"""
MTech Migration Effort Adapter & Calculation Engine
==================================================
Implements the MTech migration effort assessment methodology for cryptographic assets,
evaluating code changes, configuration, certificate rotation, protocol updates,
testing, and deployment requirements.
"""

from typing import Any, Dict, Optional
from pydantic import BaseModel, Field

class MigrationAssessment(BaseModel):
    migration_effort_hours: float = Field(..., description="Total estimated effort in hours")
    migration_effort_days: float = Field(..., description="Total estimated effort in work days")
    migration_effort_years: float = Field(..., description="Total estimated effort in work years")
    effort_level: str = Field(..., description="Low | Medium | High | Critical")
    breaking_change_risk: str = Field(..., description="low | medium | high")
    code_change_effort_hours: float = 0.0
    config_change_effort_hours: float = 0.0
    certificate_rotation_effort_hours: float = 0.0
    protocol_migration_effort_hours: float = 0.0
    testing_effort_hours: float = 0.0
    deployment_effort_hours: float = 0.0
    dependencies: list[str] = Field(default_factory=list)
    compatibility_risk: str = "low"
    confidence: float = 0.85
    calculation_source: str = "mtech_effort_adapter_fallback"


class MTechMigrationAdapter:
    """
    Adapter that evaluates migration effort according to MTech methodology criteria
    with fallback heuristics based on cryptographic asset properties.
    """

    def calculate_effort(self, artifact: Dict[str, Any]) -> MigrationAssessment:
        alg = str(artifact.get("algorithm") or "").upper()
        artifact_type = str(artifact.get("artifact_type") or "").lower()
        purpose = str(artifact.get("purpose") or "").lower()
        is_shor = bool(artifact.get("shor_vulnerable") or any(k in alg for k in ["RSA", "ECC", "ECDSA", "ECDH", "DH", "ED25519"]))
        is_cert = artifact_type in ("certificate", "pkcs12", "x509") or "cert" in artifact_type
        is_protocol = artifact_type == "protocol" or "tls" in alg.lower()
        is_cloud = bool(artifact.get("cloud_provider"))

        # Base hours breakdown
        code_hours = 0.0
        config_hours = 0.0
        cert_hours = 0.0
        proto_hours = 0.0
        test_hours = 8.0
        deploy_hours = 8.0
        dependencies = []
        breaking_risk = "low"

        if is_cert:
            cert_hours = 16.0
            config_hours = 8.0
            test_hours = 12.0
            deploy_hours = 8.0
            dependencies.append("CA PKI reissuance")
            dependencies.append("Client certificate trust store update")
            breaking_risk = "medium"
        elif is_protocol:
            proto_hours = 32.0
            config_hours = 16.0
            test_hours = 24.0
            deploy_hours = 16.0
            dependencies.append("TLS handshake protocol upgrade")
            dependencies.append("Client cipher suite compatibility matrix")
            breaking_risk = "high"
        elif is_shor:
            # Asymmetric PQC migration (RSA/ECDSA -> ML-DSA or RSA/ECDH -> ML-KEM)
            code_hours = 24.0
            proto_hours = 16.0
            test_hours = 24.0
            deploy_hours = 16.0
            dependencies.append("NIST PQC library integration (liboqs / Bouncy Castle PQC)")
            dependencies.append("Public key & ciphertext buffer size expansion (ML-KEM / ML-DSA)")
            breaking_risk = "high"
        elif "AES" in alg or "CHACHA" in alg:
            # Symmetric key size expansion (AES-128 -> AES-256)
            code_hours = 8.0
            config_hours = 4.0
            test_hours = 8.0
            deploy_hours = 4.0
            dependencies.append("Key material rotation")
            breaking_risk = "low"
        else:
            # Classical weak (MD5, SHA1, DES)
            code_hours = 12.0
            test_hours = 8.0
            deploy_hours = 4.0
            dependencies.append("Deprecation of insecure hashing/cipher primitive")
            breaking_risk = "medium"

        if is_cloud:
            config_hours += 8.0
            deploy_hours += 8.0
            dependencies.append("Cloud IAM policy & KMS key policy update")

        total_hours = code_hours + config_hours + cert_hours + proto_hours + test_hours + deploy_hours
        total_days = round(total_hours / 8.0, 2)
        total_years = round(total_hours / (8.0 * 220.0), 3)

        if total_hours <= 16:
            effort_level = "Low"
        elif total_hours <= 60:
            effort_level = "Medium"
        elif total_hours <= 160:
            effort_level = "High"
        else:
            effort_level = "Critical"

        return MigrationAssessment(
            migration_effort_hours=total_hours,
            migration_effort_days=total_days,
            migration_effort_years=total_years,
            effort_level=effort_level,
            breaking_change_risk=breaking_risk,
            code_change_effort_hours=code_hours,
            config_change_effort_hours=config_hours,
            certificate_rotation_effort_hours=cert_hours,
            protocol_migration_effort_hours=proto_hours,
            testing_effort_hours=test_hours,
            deployment_effort_hours=deploy_hours,
            dependencies=dependencies,
            compatibility_risk=breaking_risk,
            confidence=0.85,
            calculation_source="mtech_effort_adapter_fallback",
        )
