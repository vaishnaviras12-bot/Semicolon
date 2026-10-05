"""
Mosca Theorem Calculation Service
=================================
Calculates Mosca Theorem parameters against expert Q-Day distribution (P25, P50, P75):
  X = data lifetime / shelf life (years)
  Y = migration effort (years)
  Z = Q-Day distribution (P25: ~8y, P50: ~13y, P75: ~21y from reference year)

Evaluates HNDL exposure and signature-forgery risk with conservative dual-use handling.
"""

from typing import Any, Dict, List
from backend.app.config import settings

class MoscaService:
    def __init__(self, p25: int = None, p50: int = None, p75: int = None, q_day_year: int = None, reference_year: int = None, **kwargs):
        if p50 is None and q_day_year is not None and reference_year is not None:
            p50 = q_day_year - reference_year
        self.p25 = p25 if p25 is not None else getattr(settings, "QDAY_P25", 8)
        self.p50 = p50 if p50 is not None else getattr(settings, "QDAY_P50", 13)
        self.p75 = p75 if p75 is not None else getattr(settings, "QDAY_P75", 21)

    def classify_artifact(self, artifact: Dict[str, Any]) -> Dict[str, Any]:
        """
        Classifies artifact as HNDL-relevant, signature-only, or non-Shor.
        Handles RSA dual-use conservatively: unless RSA purpose is proved signature-only,
        it is classified as HNDL-relevant with a dual-use note.
        """
        alg = str(artifact.get("algorithm") or "").upper()
        purpose = str(artifact.get("purpose") or "").lower()
        artifact_type = str(artifact.get("artifact_type") or "").lower()
        is_shor = bool(artifact.get("shor_vulnerable")) or artifact.get("quantum_class") == "shor" or any(
            k in alg for k in ["RSA", "ECC", "ECDSA", "ECDH", "DH", "DSA", "ED25519", "X25519", "ED448"]
        )

        # Non-Shor algorithms (AES, SHA, HMAC, DES) carry no Shor HNDL or signature-forgery quantum risk
        if not is_shor:
            return {
                "is_shor": False,
                "hndl_relevant": False,
                "signature_only": False,
                "is_dual_use": False,
                "purpose_note": "Not Shor-vulnerable"
            }

        # Pure signature-only algorithms (cannot do key exchange or encryption)
        is_strictly_sig_alg = any(k in alg for k in ["ECDSA", "DSA", "ED25519", "ED448"]) or artifact_type == "code_signing"
        is_sig_purpose = any(p in purpose for p in ["signature", "sign", "verify"]) and not any(p in purpose for p in ["encrypt", "key_exchange", "exchange", "kex", "establishment"])

        if is_strictly_sig_alg or (is_sig_purpose and "RSA" not in alg):
            return {
                "is_shor": True,
                "hndl_relevant": False,
                "signature_only": True,
                "is_dual_use": False,
                "purpose_note": "Signature-only forgery risk"
            }

        # RSA dual-use handling
        if "RSA" in alg:
            if is_sig_purpose and "encrypt" not in purpose and "exchange" not in purpose:
                return {
                    "is_shor": True,
                    "hndl_relevant": False,
                    "signature_only": True,
                    "is_dual_use": False,
                    "purpose_note": "RSA signature usage"
                }
            return {
                "is_shor": True,
                "hndl_relevant": True,
                "signature_only": False,
                "is_dual_use": True,
                "purpose_note": "dual-use — confirm usage"
            }

        # Default Shor-vulnerable key exchange / encryption asset (ECC, ECDH, DH, X25519)
        return {
            "is_shor": True,
            "hndl_relevant": True,
            "signature_only": False,
            "is_dual_use": False,
            "purpose_note": "HNDL key exchange / encryption"
        }

    def calculate_finding_mosca(self, artifact: Dict[str, Any], migration_years: float) -> Dict[str, Any]:
        classification = self.classify_artifact(artifact)
        sensitivity = str(artifact.get("sensitivity") or "").lower()

        # Derive X (data lifetime / shelf life years)
        if sensitivity == "critical":
            x = 15.0
        elif sensitivity == "high":
            x = 10.0
        elif sensitivity == "moderate" or sensitivity == "medium":
            x = 5.0
        elif sensitivity == "low":
            x = 2.0
        else:
            x = 5.0 if classification["is_shor"] else 2.0

        y = float(migration_years)
        required_until = round(x + y, 2)

        at_p25 = round(required_until - self.p25, 2)
        at_p50 = round(required_until - self.p50, 2)
        at_p75 = round(required_until - self.p75, 2)

        breach_p25 = at_p25 > 0
        breach_p50 = at_p50 > 0
        breach_p75 = at_p75 > 0

        if at_p75 > 0:
            status = "breach-likely"
        elif at_p50 > 0:
            status = "breach-median"
        elif at_p25 > 0:
            status = "breach-possible"
        else:
            status = "safe"

        return {
            "mosca_x": x,
            "mosca_y": y,
            "mosca_z": self.p50,
            "required_until": required_until,
            "qday": {"p25": self.p25, "p50": self.p50, "p75": self.p75},
            "at_p25": at_p25,
            "at_p50": at_p50,
            "at_p75": at_p75,
            "breach_p25": breach_p25,
            "breach_p50": breach_p50,
            "breach_p75": breach_p75,
            "breach": breach_p50,
            "margin_years": -at_p50,
            "mosca_margin": -at_p50,
            "margin": -at_p50,
            "status": status,
            "hndl_relevant": classification["hndl_relevant"],
            "signature_only": classification["signature_only"],
            "is_dual_use": classification["is_dual_use"],
            "purpose_note": classification["purpose_note"],
        }

    def calculate_portfolio_mosca(self, findings_mosca: List[Dict[str, Any]]) -> Dict[str, Any]:
        hndl_items = [item for item in findings_mosca if item.get("hndl_relevant")]
        sig_items = [item for item in findings_mosca if item.get("signature_only")]

        if not hndl_items:
            return {
                "portfolio_x": 0.0,
                "portfolio_y": 0.0,
                "portfolio_required_until": 0.0,
                "qday": {"p25": self.p25, "p50": self.p50, "p75": self.p75},
                "at_p25": round(0.0 - self.p25, 2),
                "at_p50": round(0.0 - self.p50, 2),
                "at_p75": round(0.0 - self.p75, 2),
                "portfolio_status": "safe",
                "hndl_count": 0,
                "signature_count": len(sig_items),
                "breach_p25_count": 0,
                "breach_p50_count": 0,
                "breach_p75_count": 0,
            }

        portfolio_x = max([item["mosca_x"] for item in hndl_items], default=5.0)
        portfolio_y = max([item["mosca_y"] for item in hndl_items], default=0.5)
        required_until = round(portfolio_x + portfolio_y, 2)

        at_p25 = round(required_until - self.p25, 2)
        at_p50 = round(required_until - self.p50, 2)
        at_p75 = round(required_until - self.p75, 2)

        if at_p75 > 0:
            status = "breach-likely"
        elif at_p50 > 0:
            status = "breach-median"
        elif at_p25 > 0:
            status = "breach-possible"
        else:
            status = "safe"

        return {
            "portfolio_x": portfolio_x,
            "portfolio_y": portfolio_y,
            "portfolio_required_until": required_until,
            "qday": {"p25": self.p25, "p50": self.p50, "p75": self.p75},
            "at_p25": at_p25,
            "at_p50": at_p50,
            "at_p75": at_p75,
            "portfolio_status": status,
            "hndl_count": len(hndl_items),
            "signature_count": len(sig_items),
            "breach_p25_count": sum(1 for item in hndl_items if item.get("breach_p25")),
            "breach_p50_count": sum(1 for item in hndl_items if item.get("breach_p50")),
            "breach_p75_count": sum(1 for item in hndl_items if item.get("breach_p75")),
        }
