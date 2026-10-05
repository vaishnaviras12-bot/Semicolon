"""
Risk Assessment Engine Service
==============================
Interfaces with ECDAT's QARS-style Risk Engine (`ecdat_risk_engine.py`) to perform
quantum-risk classification (Shor / Grover / Classical Weakness), layer scoring,
attenuation, factors, and overall risk band aggregation.
"""

import os
import sys
from typing import Any, Dict, List

# Ensure parent directory is on sys.path to import ecdat_risk_engine.py
_ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../"))
if _ROOT_DIR not in sys.path:
    sys.path.insert(0, _ROOT_DIR)

import ecdat_risk_engine as risk_module

class RiskService:
    def __init__(self, q_day_year: int = 2035, reference_year: int = 2026):
        self.config = risk_module.DEFAULT_CONFIG.copy()
        self.config["q_day_year"] = q_day_year
        self.config["reference_year"] = reference_year

    def evaluate_risk(self, raw_artifacts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Runs consolidation, assessment, layer scoring, and risk score computation."""
        consolidated = risk_module.consolidate(raw_artifacts, self.config)
        scored_findings = []

        shor_count = 0
        grover_count = 0
        classical_weak_count = 0
        band_counts = {"critical": 0, "high": 0, "moderate": 0, "low": 0, "safe": 0}

        for rec in consolidated:
            a, err = risk_module.assess(rec)
            layer, layer_desc = risk_module.classify_layer(rec)
            rec["layer"] = layer

            if a is not None:
                scored = risk_module.score_finding(rec, a, self.config)
                q_class = a.get("quantum_class", "unresolved")
                is_shor = bool(a.get("shor_vulnerable"))
                is_class_weak = bool(a.get("classical_weak"))

                if is_shor:
                    shor_count += 1
                elif q_class == "grover":
                    grover_count += 1

                if is_class_weak:
                    classical_weak_count += 1

                score_raw = scored.get("score", 0.10)
                score = round(score_raw * 100, 1)
                band = risk_module.band_of(score_raw, self.config)
                band_counts[band] = band_counts.get(band, 0) + 1

                scored_findings.append({
                    "record": rec,
                    "assessment": a,
                    "layer": layer,
                    "quantum_class": q_class,
                    "shor_vulnerable": is_shor,
                    "classically_weak": is_class_weak,
                    "risk_score": score,
                    "risk_band": band,
                    "scoring_detail": scored,
                })
            else:
                band_counts["safe"] = band_counts.get("safe", 0) + 1
                scored_findings.append({
                    "record": rec,
                    "assessment": {"resolved": False, "quantum_class": "unresolved", "shor_vulnerable": False},
                    "layer": layer,
                    "quantum_class": "unresolved",
                    "shor_vulnerable": False,
                    "classically_weak": False,
                    "risk_score": 10.0,
                    "risk_band": "safe",
                    "scoring_detail": {"error": err},
                })

        # Calculate readiness score
        total = len(scored_findings)
        readiness_score = max(0, min(100, int(((total - shor_count) / max(1, total)) * 100)))

        # Determine top risk band
        if band_counts["critical"] > 0:
            top_band = "critical"
        elif band_counts["high"] > 0:
            top_band = "high"
        elif band_counts["moderate"] > 0:
            top_band = "moderate"
        elif band_counts["low"] > 0:
            top_band = "low"
        else:
            top_band = "safe"

        return {
            "scored_findings": scored_findings,
            "shor_count": shor_count,
            "grover_count": grover_count,
            "classical_weak_count": classical_weak_count,
            "readiness_score": readiness_score,
            "top_band": top_band,
            "band_counts": band_counts,
        }
