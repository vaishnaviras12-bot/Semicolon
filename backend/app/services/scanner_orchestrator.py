"""
Full Pipeline Scanner Orchestrator Service
============================================
Orchestrates raw detector scanning, deduplication, CBOM generation, risk engine evaluation,
MTech migration calculation, Mosca theorem horizon analysis, PQC recommendations,
and result enrichment.
"""

import os
import sys
import uuid
import logging
from typing import Any, Dict, List

# Add ECDAT-main root to sys.path
_ECDAT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../ECDAT-main"))
if _ECDAT_DIR not in sys.path:
    sys.path.insert(0, _ECDAT_DIR)

from scanner.scanner import scan_directory, deduplicate_findings
from backend.app.services.cbom_service import CBOMService
from backend.app.services.risk_service import RiskService
from backend.app.services.mosca_service import MoscaService
from backend.app.services.recommendation_service import PQCRecommendationService
from backend.app.migration.mtech_adapter import MTechMigrationAdapter

import re

logger = logging.getLogger("ecdat.scanner_orchestrator")

def filter_redundant_import_signals(artifacts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    files_with_concrete = set()
    for a in artifacts:
        if a.get("artifact_type") not in ("import_signal", "warning"):
            fp = a.get("file_path") or a.get("location")
            if fp:
                files_with_concrete.add(os.path.normpath(str(fp)).replace("\\", "/"))

    filtered = []
    for a in artifacts:
        if a.get("artifact_type") == "import_signal":
            fp = a.get("file_path") or a.get("location")
            norm_fp = os.path.normpath(str(fp)).replace("\\", "/") if fp else None
            if norm_fp in files_with_concrete:
                continue
        filtered.append(a)
    return filtered

def format_asset_name(rec: Dict[str, Any]) -> str:
    fp = rec.get("file_path") or rec.get("location") or rec.get("asset")
    if fp:
        name = os.path.basename(str(fp))
        if name:
            return name
    if rec.get("service"):
        return str(rec["service"])
    if rec.get("library"):
        return str(rec["library"])
    return str(rec.get("artifact_type") or "Crypto Asset")

try:
    from algorithm_resolver import resolve_artifacts
except ImportError:
    from ECDAT.cbom.algorithm_resolver import resolve_artifacts


def format_algorithm_display(rec: Dict[str, Any]) -> str:
    status = rec.get("resolution_status", "resolved")
    alg = str(rec.get("algorithm") or "Unresolved Cryptographic Artifact")

    if status == "library-only":
        lib = rec.get("library") or rec.get("asset") or "Crypto Library"
        return f"{lib} (library-only)"
    if status == "dynamic" or alg == "Runtime-configured":
        return "Runtime-configured"
    if status == "insufficient-evidence" or alg == "UNSPECIFIED":
        return "Unresolved Cryptographic Artifact"

    ks = rec.get("key_size")
    curve = rec.get("curve") or rec.get("certificate_ec_curve")
    mode = rec.get("mode")

    if re.search(r"-\d{3,4}$", alg):
        return alg

    alg_u = alg.upper()
    if alg_u in ("RSA", "DSA", "DH"):
        return f"{alg_u}-{ks}" if ks else alg_u
    elif alg_u in ("EC", "ECC", "ECDSA", "ECDH"):
        c_str = f" {curve}" if curve else ""
        if "ECDSA" in alg_u:
            return f"ECDSA{c_str}"
        elif "ECDH" in alg_u:
            return f"ECDH{c_str}"
        return f"ECC{c_str}"
    elif alg_u == "AES":
        if ks and mode:
            return f"AES-{ks}-{mode}"
        elif ks:
            return f"AES-{ks}"
        elif mode:
            return f"AES ({mode})"
        return "AES"
    return alg


from backend.app.services.compliance_service import ComplianceService


def infer_sensitivity(rec: Dict[str, Any]) -> str:
    explicit = rec.get("sensitivity")
    if explicit and str(explicit).lower() in ("critical", "high", "moderate", "low"):
        return str(explicit).lower()

    alg = str(rec.get("algorithm") or "").upper()
    file_path = str(rec.get("file_path") or rec.get("asset") or "").lower()
    art_type = str(rec.get("artifact_type") or "").lower()
    code = str(rec.get("code_snippet") or "").lower()
    purpose = str(rec.get("purpose") or "").lower()
    mode = str(rec.get("mode") or "").upper()

    if any(k in file_path for k in ("key.pem", "private", "kms", "secret", "auth_key")) or art_type in ("key", "private_key"):
        return "critical"
    if mode == "ECB" or "md5" in alg or "md5" in code:
        return "critical"
    if "jwt" in code or "token" in code or "secret" in code:
        return "critical"

    if alg in ("RSA", "ECDSA", "ECC", "DH", "DSA", "AES-256", "AES-128", "AES") or "rsa" in code or "ec" in code:
        if art_type in ("algorithm", "certificate", "protocol") or "generate" in code or "encrypt" in code:
            return "high"
    if any(k in file_path for k in ("auth", "login", "pay", "cert", "token", "session")) or "auth" in purpose:
        return "high"

    if art_type == "library" or any(k in file_path for k in ("cache", "test", "package.json", "requirements.txt")):
        return "low"

    return "moderate"


class ScannerOrchestrator:
    def __init__(self):
        self.cbom_service = CBOMService()
        self.risk_service = RiskService()
        self.mosca_service = MoscaService()
        self.recommendation_service = PQCRecommendationService()
        self.mtech_adapter = MTechMigrationAdapter()
        self.compliance_service = ComplianceService()

    def run_full_scan(self, target_path: str, scan_id: str = None) -> Dict[str, Any]:
        if not scan_id:
            scan_id = str(uuid.uuid4())

        logger.info(f"Starting full scan for {target_path} (scan_id: {scan_id})")

        # Step 1: Execute raw scanner
        raw_artifacts = scan_directory(target_path)
        logger.info(f"Discovered {len(raw_artifacts)} raw artifacts.")

        # Step 2: Deduplicate raw findings & filter redundant import signals
        deduped_artifacts = deduplicate_findings(raw_artifacts)
        deduped_artifacts = filter_redundant_import_signals(deduped_artifacts)

        # Step 2.5: Algorithm Resolution & Normalization Layer
        resolved_artifacts = resolve_artifacts(deduped_artifacts, merge_evidence=True)

        # Normalize file paths to relative workspace paths
        target_path_norm = os.path.abspath(target_path).replace("\\", "/").rstrip("/")
        for rec in resolved_artifacts:
            rec["sensitivity"] = infer_sensitivity(rec)
            fp = str(rec.get("file_path") or rec.get("location") or "")
            if fp:
                fp_norm = os.path.abspath(fp).replace("\\", "/")
                if fp_norm.startswith(target_path_norm):
                    rec["file_path"] = fp_norm[len(target_path_norm):].lstrip("/")

        # Step 3: CBOM generation
        cbom_data = self.cbom_service.build_cbom(resolved_artifacts)
        cyclonedx_data = self.cbom_service.export_cyclonedx(cbom_data)

        # Step 4: Risk evaluation
        risk_data = self.risk_service.evaluate_risk(resolved_artifacts)

        # Step 5: Process enriched findings (MTech, Mosca, Recommendations)
        enriched_findings = []
        findings_mosca_list = []
        total_effort_hours = 0.0

        for idx, scored in enumerate(risk_data["scored_findings"]):
            rec = scored["record"]
            fid = f"finding-{scan_id[:8]}-{idx + 1}"
            rec["finding_id"] = fid

            asset_name = format_asset_name(rec)
            alg_display = format_algorithm_display(rec)
            rec["asset"] = asset_name
            rec["algorithm_display"] = alg_display

            # MTech Migration Effort
            migration_assessment = self.mtech_adapter.calculate_effort(rec)
            rec["migration_effort_hours"] = migration_assessment.migration_effort_hours
            rec["migration_effort_years"] = migration_assessment.migration_effort_years
            rec["effort_level"] = migration_assessment.effort_level
            rec["breaking_change_risk"] = migration_assessment.breaking_change_risk
            total_effort_hours += migration_assessment.migration_effort_hours

            # Mosca Analysis
            mosca_assessment = self.mosca_service.calculate_finding_mosca(
                rec, migration_assessment.migration_effort_years
            )
            findings_mosca_list.append(mosca_assessment)

            # PQC Recommendation
            pqc_recommendation = self.recommendation_service.generate_recommendation(
                rec, migration_assessment.model_dump()
            )

            finding_item = {
                "id": fid,
                "scan_id": scan_id,
                "asset": asset_name,
                "artifact_type": rec.get("artifact_type", "algorithm"),
                "algorithm": alg_display,
                "canonical_algorithm": rec.get("algorithm"),
                "key_size": rec.get("key_size"),
                "mode": rec.get("mode"),
                "curve": rec.get("curve"),
                "family": rec.get("family"),
                "purpose": rec.get("purpose", "unknown"),
                "purpose_confidence": rec.get("purpose_confidence", 0.5),
                "purpose_evidence": rec.get("purpose_evidence", []),
                "resolution_status": rec.get("resolution_status", "resolved"),
                "resolution_reason": rec.get("resolution_reason", ""),
                "protocol": rec.get("protocol"),
                "library": rec.get("library"),
                "file_path": rec.get("file_path"),
                "line_number": rec.get("line_number"),
                "code_snippet": rec.get("code_snippet"),
                "detection_method": rec.get("detection_method", "static_analysis"),
                "detection_sources": rec.get("detection_sources", [rec.get("detection_method", "static_analysis")]),
                "confidence": rec.get("confidence", 0.8),
                "layer": scored["layer"],
                "sensitivity": rec.get("sensitivity", "moderate"),
                "exposure_type": "external" if rec.get("exposure", {}).get("internet_facing") else "internal",
                "shor_vulnerable": scored["shor_vulnerable"],
                "quantum_class": scored["quantum_class"],
                "classically_weak": scored["classically_weak"],
                "risk_score": scored["risk_score"],
                "risk_band": scored["risk_band"],
                "mosca_x": mosca_assessment["mosca_x"],
                "mosca_y": mosca_assessment["mosca_y"],
                "mosca_z": mosca_assessment["mosca_z"],
                "mosca_margin": mosca_assessment["margin"],
                "mosca_status": mosca_assessment["status"],
                "hndl_relevant": mosca_assessment["hndl_relevant"],
                "migration_effort_hours": migration_assessment.migration_effort_hours,
                "migration_effort_years": migration_assessment.migration_effort_years,
                "effort_level": migration_assessment.effort_level,
                "breaking_change_risk": migration_assessment.breaking_change_risk,
                "recommendation": pqc_recommendation,
                "evidence": (
                    {
                        **(rec["evidence"] if isinstance(rec.get("evidence"), dict) else {"text": rec["evidence"]} if rec.get("evidence") else {}),
                        **({"certificate_details": rec.get("certificate_details")} if rec.get("certificate_details") else {}),
                        **({"provider": rec.get("provider")} if rec.get("provider") else {}),
                        **({"service": rec.get("service")} if rec.get("service") else {}),
                        **({"resource": rec.get("resource")} if rec.get("resource") else {}),
                    }
                ),
                "certificate_details": rec.get("certificate_details"),
            }
            enriched_findings.append(finding_item)

        # Portfolio Mosca calculation
        portfolio_mosca = self.mosca_service.calculate_portfolio_mosca(findings_mosca_list)

        # Compliance Assessment calculation
        compliance_data = self.compliance_service.evaluate_compliance(enriched_findings)

        return {
            "scan_id": scan_id,
            "artifact_count": len(enriched_findings),
            "shor_count": risk_data["shor_count"],
            "readiness_score": risk_data["readiness_score"],
            "top_risk_band": risk_data["top_band"],
            "band_counts": risk_data["band_counts"],
            "portfolio_mosca": portfolio_mosca,
            "total_effort_hours": round(total_effort_hours, 1),
            "findings": enriched_findings,
            "cbom": cbom_data,
            "cyclonedx": cyclonedx_data,
            "compliance": compliance_data,
        }
