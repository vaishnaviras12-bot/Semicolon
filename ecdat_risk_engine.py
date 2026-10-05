#!/usr/bin/env python3
"""
ECDAT Risk Engine  (QARS-style, layer-separated, Shor/Grover-attenuated)
========================================================================
Input : ECDAT scanner JSON (list of findings, or {"findings": [...]}).
Output: risk report JSON (per-finding risk blocks, layer scores, overall,
        worst-layer, Mosca margins, review queue, unscored inventory,
        data-quality report).  NO recommendation logic lives here.

Pipeline
    1. consolidate   merge duplicate detections of the same crypto use
    2. assess        algorithm -> quantum class (Shor / Grover / classically weak / unresolved)
    3. layer         in_transit | in_use | at_rest
    4. score         adjusted layer score per finding (ECDAT_Scanner_QARS_Integration, s.5-6)
    5. aggregate     layer scores -> overall + worst-layer
    6. report        bands, Mosca margins, review queue, data quality

Per-finding formula (design doc s.6):
    S = w1*a*F_time + w2*a*F_mig + w3*b*Sens + w4*b*Exp + w5*Comp
    F_time = clamp((x + y) / z_eff)      Mosca ratio; z_eff = 0 for classically-weak crypto
    F_mig  = clamp(y / z)
    a, b   = 1.0/1.0 (Shor or classically weak), 0.15/0.30 (Grover-only)

All weights, attenuation values, thresholds and the Q-day year are PLANNING
PARAMETERS (expert judgement), not measurements.  Override via --config.

Usage
    python ecdat_risk_engine.py scanner_output.json -o risk_report.json
    python ecdat_risk_engine.py scanner_output.json --config cfg.json --q-day-year 2032
    python ecdat_risk_engine.py --selftest
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict

ENGINE_VERSION = "1.0.0"

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #
DEFAULT_CONFIG = {
    "reference_year": 2026,
    "q_day_year": 2035,  # planning horizon (NIST IR 8547 draft disallow-after year); NOT a forecast
    "weights": {"time": 0.30, "migration": 0.15, "sensitivity": 0.20,
                "exposure": 0.15, "compliance": 0.20},
    "attenuation": {
        "shor": {"alpha": 1.0, "beta": 1.0},
        "classical_weak": {"alpha": 1.0, "beta": 1.0},
        "grover": {"alpha": 0.15, "beta": 0.30},
    },
    "sensitivity_map": {"low": 0.25, "moderate": 0.50, "high": 0.75, "critical": 1.00},
    "sensitivity_default": "moderate",
    "exposure": {"baseline": 0.10,
                 "flags": {"internet_facing": 0.50, "public_registry": 0.30, "third_party_api": 0.20}},
    "time_defaults": {"data_lifetime_years": 5, "migration_effort_years": 2},
    "compliance": {
        "scanner_patterns": [["deprecated", 1.0], ["weak", 1.0], ["policy review", 0.5]],
        "quantum_vulnerable_public_key": 0.60,
        "classically_weak": 1.00,
    },
    "band_lower_bounds": {"moderate": 0.30, "high": 0.55, "critical": 0.80},
    "layer_weights": {"in_transit": 0.40, "in_use": 0.30, "at_rest": 0.30},
    "layer_aggregation_max_share": 0.70,   # layer = share*max + (1-share)*mean of finding scores
    "min_confidence_for_aggregation": 0.50,
    "review_confidence_below": 0.80,
    "review_band_at_or_above": "high",
    "sensitivity_q_day_years": [2030, 2032, 2035, 2040, 2045],
}

BANDS = ["low", "moderate", "high", "critical"]
LAYERS = ["in_transit", "in_use", "at_rest"]


def deep_merge(base: dict, over: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in (over or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def clamp(v: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, v))


# --------------------------------------------------------------------------- #
# Cryptographic knowledge base (quantum class of each algorithm)
# --------------------------------------------------------------------------- #
def _norm(name) -> str:
    return re.sub(r"[^A-Z0-9]", "", str(name or "").upper())


# Shor-vulnerable public-key families (fully broken by a large fault-tolerant quantum computer)
SHOR_FAMILY = {
    "RSA": "RSA", "DSA": "DSA", "DH": "DH", "DIFFIEHELLMAN": "DH", "ELGAMAL": "ELGAMAL",
    "EC": "EC", "ECC": "EC", "ECDSA": "EC", "ECDH": "EC", "EDDSA": "EC",
    "ED25519": "EC", "ED448": "EC", "X25519": "EC", "X448": "EC",
}
# Grover-only: symmetric ciphers and modern hashes (effective strength roughly halved, not broken)
GROVER_SYMMETRIC = {"AES", "CHACHA20", "CAMELLIA", "ARIA", "SM4"}
GROVER_HASH = {"SHA224", "SHA256", "SHA384", "SHA512", "SHA512256", "SHA3", "SHA3224",
               "SHA3256", "SHA3384", "SHA3512", "BLAKE2", "BLAKE2B", "BLAKE2S", "BLAKE3"}
# Classically broken / deprecated today (quantum is irrelevant; risk is present now)
CLASSICAL_WEAK = {"MD2", "MD4", "MD5", "SHA1", "DES", "3DES", "TRIPLEDES", "TDES", "RC2", "RC4"}
LEGACY_TLS = {"SSLV2", "SSLV3", "TLSV1", "TLSV10", "TLSV11", "SSL2", "SSL3", "TLS10", "TLS11"}
NAME_RANK = {"ECDSA": 3, "ECDH": 3, "ED25519": 3, "ED448": 3, "EDDSA": 3, "X25519": 3, "ECC": 2, "EC": 1}


def assess_algorithm(algorithm, key_size, mode=None, sig_alg=None) -> dict:
    """Return quantum classification for one algorithm attribute set."""
    n = _norm(algorithm)
    out = {"resolved": True, "family": None, "quantum_class": None, "shor_vulnerable": False,
           "classical_weak": False, "reasons": [], "flags": []}
    if not n or n == "UNSPECIFIED":
        out.update(resolved=False, quantum_class="unresolved")
        return out
    aes = re.match(r"^AES(\d{3})?$", n)
    if n in SHOR_FAMILY:
        out.update(family=SHOR_FAMILY[n], shor_vulnerable=True)
        if n in ("RSA", "DSA", "DH"):
            if key_size is None:
                out["flags"].append("key_size_unverified")
            elif key_size < 2048:
                out["classical_weak"] = True
                out["reasons"].append(f"{n}-{key_size} below 2048-bit classical minimum")
        out["quantum_class"] = "shor"
    elif aes or n in GROVER_SYMMETRIC:
        out.update(family="AES" if aes else n, quantum_class="grover")
        if key_size is None and not (aes and aes.group(1)):
            out["flags"].append("key_size_unverified")
        if mode and str(mode).upper() == "ECB":
            out["classical_weak"] = True
            out["reasons"].append("ECB mode")
    elif n in GROVER_HASH:
        out.update(family=n, quantum_class="grover")
    elif n in CLASSICAL_WEAK:
        out.update(family=n, classical_weak=True, quantum_class="classical_weak")
        out["reasons"].append(f"{algorithm} is classically broken/deprecated")
    else:
        out.update(resolved=False, quantum_class="unresolved")
        out["reasons"].append("algorithm not in knowledge base")
        return out
    if sig_alg:
        s = _norm(sig_alg)
        if "MD5" in s or "SHA1" in s:
            out["classical_weak"] = True
            out["reasons"].append(f"weak signature hash in {sig_alg}")
    if out["classical_weak"]:
        out["quantum_class"] = "classical_weak" if not out["shor_vulnerable"] else "shor"
    return out


# --------------------------------------------------------------------------- #
# Step 1: consolidation
# --------------------------------------------------------------------------- #
def _family_key(rec) -> str:
    n = _norm(rec.get("algorithm"))
    if n in SHOR_FAMILY:
        return SHOR_FAMILY[n]
    if n and n != "UNSPECIFIED":
        return n
    return "?"


def _group_key(rec):
    at = rec.get("artifact_type")
    f = rec.get("file_path") or rec.get("location")
    fam = _family_key(rec)
    if at == "import_signal":
        return ("imp", f, rec.get("library"), at)
    tclass = "primitive" if (at in ("algorithm", "hash") and fam != "?") else at
    return ("f", f, rec.get("line_number"), fam, tclass)


def _spec(rec):
    return (rec.get("key_size") is not None,
            rec.get("purpose") not in (None, "unknown"),
            NAME_RANK.get(_norm(rec.get("algorithm")), 0),
            rec.get("confidence") or 0.0)


def _exp_tuple(r):
    e = r.get("exposure") or {}
    return tuple(bool(e.get(k, r.get(k))) for k in ("internet_facing", "public_registry", "third_party_api"))


def consolidate(records, cfg):
    groups = defaultdict(list)
    order = []
    for r in records:
        k = _group_key(r)
        if k not in groups:
            order.append(k)
        groups[k].append(r)
    smap = cfg["sensitivity_map"]
    merged = []
    for k in order:
        recs = groups[k]
        p = max(recs, key=_spec)
        m = dict(p)
        m["confidence"] = max((r.get("confidence") or 0.0) for r in recs)
        sizes = [r["key_size"] for r in recs if r.get("key_size") is not None]
        m["key_size"] = min(sizes) if sizes else None
        m["_key_size_conflict"] = len(set(sizes)) > 1
        names = [r.get("algorithm") for r in recs if _norm(r.get("algorithm")) not in ("", "UNSPECIFIED")]
        m["algorithm"] = max(names, key=lambda a: NAME_RANK.get(_norm(a), 0)) if names else p.get("algorithm")
        for fld in ("purpose", "mode", "curve", "certificate_ec_curve"):
            vals = [r.get(fld) for r in recs if r.get(fld) not in (None, "unknown")]
            if vals:
                m[fld] = vals[0]
        sens = [str(r.get("sensitivity")).lower() for r in recs if r.get("sensitivity")]
        sens = [s for s in sens if s in smap]
        m["sensitivity"] = max(sens, key=lambda s: smap[s]) if sens else None
        tuples = [_exp_tuple(r) for r in recs if r.get("exposure") or "internet_facing" in r]
        if tuples:
            m["_exposure"] = {n: any(t[i] for t in tuples)
                              for i, n in enumerate(("internet_facing", "public_registry", "third_party_api"))}
        else:
            m["_exposure"] = None
        m["_exposure_inconsistent"] = len(set(tuples)) > 1
        m["_detectors"] = sorted({r.get("detection_method") for r in recs if r.get("detection_method")})
        m["_artifact_ids"] = [r.get("artifact_id") for r in recs]
        m["_finding_ids"] = [r.get("finding_id") for r in recs if r.get("finding_id")]
        m["_group_size"] = len(recs)
        merged.append(m)
    return merged


# --------------------------------------------------------------------------- #
# Step 2/3: assessment and layer classification
# --------------------------------------------------------------------------- #
def classify_layer(rec):
    at = rec.get("artifact_type")
    fmt = str(rec.get("certificate_source_format") or "").upper()
    if at == "pkcs12" or fmt in ("P12", "PFX", "PKCS12"):
        return "at_rest", "PKCS#12 bundle stored on disk"
    if at == "certificate":
        return "in_transit", "X.509 certificate (TLS/PKI identity)"
    if at in ("protocol", "certificate_reference"):
        return "in_transit", "TLS configuration / certificate reference"
    if at in ("key_reference", "certificate_generation"):
        return "at_rest", "stored key/certificate material"
    if rec.get("docker_instruction") and at in ("algorithm", "hash"):
        return "at_rest", "key material generated/baked into container image"
    return "in_use", "cryptographic primitive used by running code"


def assess(rec):
    at = rec.get("artifact_type")
    if at == "warning":
        return None, f"scanner warning: {rec.get('warning_type') or 'unknown'}"
    if at == "pkcs12" and rec.get("certificate_password_protected"):
        return None, "password-protected PKCS#12; contents not inspected"
    if at == "protocol":
        v = _norm(rec.get("protocol_version"))
        if v in LEGACY_TLS:
            return {"resolved": True, "family": "TLS", "quantum_class": "classical_weak",
                    "shor_vulnerable": False, "classical_weak": True,
                    "reasons": [f"legacy protocol version {rec.get('protocol_version')}"], "flags": []}, None
        return None, "TLS version alone does not reveal key-exchange/signature algorithm"
    a = assess_algorithm(rec.get("algorithm"), rec.get("key_size"), rec.get("mode"),
                         rec.get("certificate_signature_algorithm"))
    if not a["resolved"]:
        if at == "import_signal":
            return None, "import signal only; algorithm not identified"
        if at in ("library", "certificate_reference", "certificate_generation", "key_reference"):
            return None, f"{at} carries no algorithm attributes"
        return None, "algorithm unresolved"
    return a, None


# --------------------------------------------------------------------------- #
# Step 4: scoring
# --------------------------------------------------------------------------- #
def band_of(score: float, cfg) -> str:
    b = cfg["band_lower_bounds"]
    if score >= b["critical"]:
        return "critical"
    if score >= b["high"]:
        return "high"
    if score >= b["moderate"]:
        return "moderate"
    return "low"


def _compliance(rec, a, cfg):
    c = cfg["compliance"]
    val, src = 0.0, "none"
    for item in (rec.get("compliance") or []):
        for pat, v in c["scanner_patterns"]:
            if pat in str(item).lower() and v > val:
                val, src = v, "scanner"
    if a["classical_weak"] and c["classically_weak"] > val:
        val, src = c["classically_weak"], "engine:classically_weak"
    if a["shor_vulnerable"] and c["quantum_vulnerable_public_key"] > val:
        val, src = c["quantum_vulnerable_public_key"], "engine:quantum_vulnerable_public_key"
    return val, src


def score_finding(rec, a, cfg):
    w = cfg["weights"]
    flags = list(a["flags"])
    if rec.get("_key_size_conflict"):
        flags.append("key_size_conflict_across_detectors")
    if rec.get("_exposure_inconsistent"):
        flags.append("exposure_inconsistent_across_detectors")

    # attenuation
    cls = a["quantum_class"]
    att = cfg["attenuation"]["grover" if cls == "grover" else
                             "classical_weak" if a["classical_weak"] and not a["shor_vulnerable"] else "shor"]
    if a["classical_weak"] and cls == "grover":      # e.g. AES-ECB: weakness is classical, not Grover-limited
        att = cfg["attenuation"]["classical_weak"]
    alpha, beta = att["alpha"], att["beta"]

    # time inputs
    td = cfg["time_defaults"]
    x = rec.get("data_lifetime_years", rec.get("x_value"))
    y = rec.get("migration_effort_years", rec.get("y_value"))
    if x is None or y is None:
        flags.append("time_inputs_defaulted")
        x = td["data_lifetime_years"] if x is None else x
        y = td["migration_effort_years"] if y is None else y
    z = cfg["q_day_year"] - cfg["reference_year"]
    z_eff = 0 if a["classical_weak"] else z
    f_time = 1.0 if z_eff <= 0 else clamp((x + y) / z_eff)
    f_mig = 1.0 if z <= 0 else clamp(y / z)

    # sensitivity / exposure / compliance
    sl = rec.get("sensitivity")
    if sl is None:
        sl = cfg["sensitivity_default"]
        flags.append("sensitivity_defaulted")
    sens = cfg["sensitivity_map"][sl]
    ex = rec.get("_exposure")
    if ex is None:
        flags.append("exposure_missing")
        ex = {}
    ecfg = cfg["exposure"]
    expo = clamp(ecfg["baseline"] + sum(v for k, v in ecfg["flags"].items() if ex.get(k)))
    comp, comp_src = _compliance(rec, a, cfg)

    terms = {
        "time": w["time"] * alpha * f_time,
        "migration": w["migration"] * alpha * f_mig,
        "sensitivity": w["sensitivity"] * beta * sens,
        "exposure": w["exposure"] * beta * expo,
        "compliance": w["compliance"] * comp,
    }
    score = clamp(sum(terms.values()))
    return {
        "score": score,
        "alpha": alpha, "beta": beta,
        "factors": {"time": f_time, "migration": f_mig, "sensitivity": sens,
                    "exposure": expo, "compliance": comp, "compliance_source": comp_src},
        "terms": terms,
        "sensitivity_label": sl,
        "mosca": {"data_lifetime_x": x, "migration_years_y": y, "q_day_horizon_z": z,
                  "z_effective": z_eff, "x_plus_y": x + y,
                  "margin_years": z_eff - (x + y), "violated": (x + y) > z_eff},
        "flags": flags,
    }


# --------------------------------------------------------------------------- #
# Steps 1-6: engine
# --------------------------------------------------------------------------- #
def _loc(rec):
    f = rec.get("file_path") or rec.get("location")
    ln = rec.get("line_number")
    return f"{f}:{ln}" if ln is not None else f


def _aggregate(scored, cfg):
    share = cfg["layer_aggregation_max_share"]
    minc = cfg["min_confidence_for_aggregation"]
    layers = {}
    for L in LAYERS:
        fs = [s for s in scored if s["risk"]["layer"] == L]
        inc = [s for s in fs if s["confidence"] >= minc]
        if inc:
            sc = [s["risk"]["layer_score"] for s in inc]
            val = share * max(sc) + (1 - share) * (sum(sc) / len(sc))
            top = sorted(inc, key=lambda s: -s["risk"]["layer_score"])[:3]
            layers[L] = {"score": val, "band": band_of(val, cfg), "n_findings": len(fs),
                         "n_aggregated": len(inc),
                         "max_finding_score": max(sc), "mean_finding_score": sum(sc) / len(sc),
                         "band_counts": dict(Counter(s["risk"]["band"] for s in inc)),
                         "top_drivers": [s["finding_id"] for s in top]}
        else:
            layers[L] = {"score": None, "band": None, "n_findings": len(fs), "n_aggregated": 0}
    lw = cfg["layer_weights"]
    present = [L for L in LAYERS if layers[L]["score"] is not None]
    if not present:
        return layers, None, None
    tot = sum(lw[L] for L in present)
    overall = sum(lw[L] * layers[L]["score"] for L in present) / tot
    worst_layer = max(present, key=lambda L: layers[L]["score"])
    return layers, {"score": overall, "band": band_of(overall, cfg),
                    "layers_included": present}, {"layer": worst_layer,
                                                  "score": layers[worst_layer]["score"],
                                                  "band": layers[worst_layer]["band"]}


def _run_core(records, cfg):
    merged = consolidate(records, cfg)
    scored, unscored = [], []
    for i, rec in enumerate(merged):
        layer, layer_why = classify_layer(rec)
        a, reason = assess(rec)
        fid = (rec["_finding_ids"] or [None])[0] or f"ECDAT-UNSCORED-{rec['_artifact_ids'][0]}"
        if a is None:
            unscored.append({
                "finding_id": fid, "merged_artifact_ids": rec["_artifact_ids"],
                "artifact_type": rec.get("artifact_type"), "location": _loc(rec),
                "library": rec.get("library"), "layer_hint": layer,
                "confidence": rec["confidence"], "reason": reason})
            continue
        s = score_finding(rec, a, cfg)
        band = band_of(s["score"], cfg)
        rev = []
        thr = BANDS.index(cfg["review_band_at_or_above"])
        if BANDS.index(band) >= thr and rec["confidence"] < cfg["review_confidence_below"]:
            rev.append("high_risk_low_confidence")
        rev += [f for f in s["flags"] if f in (
            "key_size_unverified", "key_size_conflict_across_detectors",
            "exposure_inconsistent_across_detectors", "time_inputs_defaulted",
            "sensitivity_defaulted", "exposure_missing")]
        if rec.get("purpose") in (None, "unknown"):
            rev.append("purpose_unknown")
        scored.append({
            "finding_id": fid,
            "merged_finding_ids": rec["_finding_ids"],
            "merged_artifact_ids": rec["_artifact_ids"],
            "artifact_type": rec.get("artifact_type"),
            "algorithm": rec.get("algorithm"), "key_size": rec.get("key_size"),
            "mode": rec.get("mode"), "purpose": rec.get("purpose"),
            "location": _loc(rec), "library": rec.get("library"),
            "confidence": rec["confidence"],
            "detectors": rec["_detectors"], "n_duplicate_detections": rec["_group_size"],
            "risk": {
                "layer": layer, "layer_rule": layer_why,
                "quantum_class": a["quantum_class"],
                "shor_vulnerable": a["shor_vulnerable"],
                "classical_weak": a["classical_weak"],
                "classical_weak_reasons": a["reasons"],
                "attenuation": {"alpha": s["alpha"], "beta": s["beta"]},
                "sensitivity_label": s["sensitivity_label"],
                "factors": s["factors"], "terms": s["terms"],
                "mosca": s["mosca"],
                "layer_score": s["score"], "band": band,
                "review_flags": sorted(set(rev)),
            },
        })
    layers, overall, worst = _aggregate(scored, cfg)
    return merged, scored, unscored, layers, overall, worst


def _round(o, nd=4):
    if isinstance(o, float):
        return round(o, nd)
    if isinstance(o, dict):
        return {k: _round(v, nd) for k, v in o.items()}
    if isinstance(o, list):
        return [_round(v, nd) for v in o]
    return o


def run(records, config=None, input_sha256=None):
    cfg = deep_merge(DEFAULT_CONFIG, config or {})
    wsum = sum(cfg["weights"].values())
    if abs(wsum - 1.0) > 1e-6:
        raise ValueError(f"weights must sum to 1.0 (got {wsum:.4f})")
    merged, scored, unscored, layers, overall, worst = _run_core(records, cfg)
    scored.sort(key=lambda s: (-s["risk"]["layer_score"], s["location"] or ""))

    # ---- summaries -------------------------------------------------------
    by_band = {b: sum(1 for s in scored if s["risk"]["band"] == b) for b in reversed(BANDS)}
    by_class = dict(Counter(s["risk"]["quantum_class"] for s in scored))
    algo = defaultdict(list)
    for s in scored:
        key = f"{s['algorithm']}" + (f"-{s['key_size']}" if s["key_size"] else "")
        algo[key].append(s["risk"]["layer_score"])
    by_algorithm = {k: {"count": len(v), "max_score": max(v), "mean_score": sum(v) / len(v),
                        "band_of_max": band_of(max(v), cfg)}
                    for k, v in sorted(algo.items(), key=lambda kv: -max(kv[1]))}
    files = defaultdict(list)
    for s in scored:
        files[(s["location"] or "").rsplit(":", 1)[0] if s["artifact_type"] not in ("certificate", "pkcs12")
              else s["location"]].append(s["risk"]["layer_score"])
    by_file = {k: {"count": len(v), "max_score": max(v), "mean_score": sum(v) / len(v)}
               for k, v in sorted(files.items(), key=lambda kv: -max(kv[1]))}

    review = [{"finding_id": s["finding_id"], "location": s["location"], "band": s["risk"]["band"],
               "layer_score": s["risk"]["layer_score"], "flags": s["risk"]["review_flags"]}
              for s in scored if s["risk"]["review_flags"]]

    # ---- data quality ----------------------------------------------------
    demo = sum(1 for r in records if r.get("demo_enrichment"))
    dup_groups = [m for m in merged if m["_group_size"] > 1]
    dq = {
        "input_records": len(records),
        "records_with_demo_enrichment": demo,
        "demo_enrichment_note": ("sensitivity, exposure, data_lifetime, migration_effort and compliance "
                                 "were set by scanner demo enrichment, not live context analysis")
        if demo else None,
        "duplicate_groups_merged": len(dup_groups),
        "records_absorbed_by_merge": sum(m["_group_size"] - 1 for m in dup_groups),
        "groups_with_conflicting_exposure": sum(1 for m in dup_groups if m["_exposure_inconsistent"]),
        "groups_with_conflicting_key_size": sum(1 for m in dup_groups if m["_key_size_conflict"]),
        "exposure_merge_rule": "OR across duplicate detections (order-independent, conservative)",
        "unscored_by_reason": dict(Counter(u["reason"] for u in unscored)),
    }

    # ---- Q-day sensitivity ----------------------------------------------
    sens_rows = []
    for yr in cfg["sensitivity_q_day_years"]:
        c2 = copy.deepcopy(cfg)
        c2["q_day_year"] = yr
        _, sc2, _, ly2, ov2, wr2 = _run_core(records, c2)
        sens_rows.append({"q_day_year": yr, "overall_score": ov2["score"] if ov2 else None,
                          "overall_band": ov2["band"] if ov2 else None,
                          "worst_layer": wr2["layer"] if wr2 else None,
                          "worst_layer_score": wr2["score"] if wr2 else None,
                          "mosca_violations": sum(1 for s in sc2 if s["risk"]["mosca"]["violated"]),
                          "critical": sum(1 for s in sc2 if s["risk"]["band"] == "critical"),
                          "high": sum(1 for s in sc2 if s["risk"]["band"] == "high")})

    report = {
        "engine": {"name": "ECDAT Risk Engine", "version": ENGINE_VERSION,
                   "input_sha256": input_sha256,
                   "formula": "S = w1*a*F_time + w2*a*F_mig + w3*b*Sens + w4*b*Exp + w5*Comp",
                   "note": "weights/attenuation/thresholds/Q-day year are planning parameters, not measurements",
                   "config": cfg},
        "summary": {
            "input_records": len(records),
            "consolidated_findings": len(merged),
            "scored": len(scored), "unscored": len(unscored),
            "overall": overall, "worst_layer": worst,
            "layer_scores": layers,
            "by_band": by_band, "by_quantum_class": by_class,
            "mosca_violations": sum(1 for s in scored if s["risk"]["mosca"]["violated"]),
            "review_queue_size": len(review),
            "top_risks": [{"finding_id": s["finding_id"], "algorithm": s["algorithm"],
                           "key_size": s["key_size"], "location": s["location"],
                           "layer": s["risk"]["layer"], "layer_score": s["risk"]["layer_score"],
                           "band": s["risk"]["band"]} for s in scored[:10]],
        },
        "q_day_sensitivity": sens_rows,
        "by_algorithm": by_algorithm,
        "by_file": by_file,
        "findings": scored,
        "review_queue": review,
        "unscored": unscored,
        "data_quality": dq,
    }
    return _round(report)


def load_records(path):
    raw = open(path, "rb").read()
    data = json.loads(raw.decode("utf-8-sig"))
    if isinstance(data, dict):
        data = data.get("findings") or data.get("results") or []
    return data, hashlib.sha256(raw).hexdigest()


# --------------------------------------------------------------------------- #
# Self-test
# --------------------------------------------------------------------------- #
def _selftest():
    def rec(**kw):
        base = dict(artifact_type="algorithm", algorithm="RSA", key_size=2048, file_path="a.py",
                    line_number=1, detection_method="ast_call", confidence=0.95, artifact_id="t",
                    finding_id="T-1", purpose="signing", sensitivity="Critical", data_lifetime_years=5,
                    migration_effort_years=6, exposure={"internet_facing": True, "public_registry": False,
                                                        "third_party_api": False}, compliance=[])
        base.update(kw)
        return base

    def one(**kw):
        r = run([rec(**kw)])
        return r["findings"][0]["risk"] if r["findings"] else None

    t = 0

    def ok(cond, msg):
        nonlocal t
        assert cond, "FAIL: " + msg
        t += 1

    ok(abs(sum(DEFAULT_CONFIG["weights"].values()) - 1) < 1e-9, "weights sum to 1")
    rsa = one()
    aes = one(algorithm="AES", key_size=256, purpose="encryption", sensitivity="High",
              migration_effort_years=2)
    ok(rsa["shor_vulnerable"] and rsa["attenuation"] == {"alpha": 1.0, "beta": 1.0}, "RSA is Shor, no attenuation")
    ok(aes["quantum_class"] == "grover" and aes["attenuation"]["alpha"] == 0.15, "AES-256 Grover attenuation")
    ok(aes["layer_score"] < 0.30 <= rsa["layer_score"], "AES-256 far below RSA-2048")
    weak = one(key_size=1024)
    ok(weak["classical_weak"] and weak["mosca"]["z_effective"] == 0 and weak["band"] == "critical",
       "RSA-1024 classically weak -> critical")
    md5 = one(algorithm="MD5", key_size=None, purpose="integrity", sensitivity="High",
              data_lifetime_years=0, migration_effort_years=2)
    ok(md5["factors"]["time"] == 1.0 and md5["band"] in ("high", "critical"), "MD5 not hidden by x=0")
    ok(one(algorithm="AES", key_size=256, mode="ECB")["classical_weak"], "AES-ECB classically weak")
    # Mosca: later Q-day lowers score
    lo = run([rec()], {"q_day_year": 2045})["findings"][0]["risk"]["layer_score"]
    hi = run([rec()], {"q_day_year": 2030})["findings"][0]["risk"]["layer_score"]
    ok(lo < hi, "later Q-day -> lower score")
    # consolidation
    r = run([rec(detection_method="tree_sitter", key_size=None), rec(detection_method="semgrep"),
             rec(detection_method="pattern_match", confidence=0.7)])
    ok(r["summary"]["consolidated_findings"] == 1 and r["findings"][0]["n_duplicate_detections"] == 3,
       "duplicates merged")
    ok(r["findings"][0]["key_size"] == 2048 and r["findings"][0]["confidence"] == 0.95, "merge keeps best attrs")
    # unscored
    u = run([rec(artifact_type="import_signal", algorithm="UNSPECIFIED", key_size=None)])
    ok(u["summary"]["scored"] == 0 and u["summary"]["unscored"] == 1 and u["summary"]["overall"] is None,
       "import signal unscored")
    # review flag
    lc = run([rec(confidence=0.6, key_size=1024)])
    ok("high_risk_low_confidence" in lc["findings"][0]["risk"]["review_flags"], "low-confidence review flag")
    # worst layer >= overall
    two = run([rec(), rec(artifact_type="certificate", file_path="c.pem", line_number=None,
                          algorithm="AES", key_size=256, sensitivity="Low", finding_id="T-2")])
    s = two["summary"]
    ok(s["worst_layer"]["score"] >= s["overall"]["score"], "worst-layer >= overall")
    # bad weights rejected
    try:
        run([rec()], {"weights": {"time": 0.9}})
        ok(False, "bad weights rejected")
    except ValueError:
        ok(True, "bad weights rejected")
    print(f"selftest: {t}/{t} passed")


def main(argv=None):
    ap = argparse.ArgumentParser(description="ECDAT quantum risk engine (risk scoring only)")
    ap.add_argument("input", nargs="?", help="scanner output JSON")
    ap.add_argument("-o", "--output", default="risk_report.json")
    ap.add_argument("--config", help="JSON file with config overrides")
    ap.add_argument("--q-day-year", type=int, help="override planning Q-day year")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args(argv)
    if a.selftest:
        return _selftest()
    if not a.input:
        ap.error("input JSON required")
    cfg = json.load(open(a.config)) if a.config else {}
    if a.q_day_year:
        cfg["q_day_year"] = a.q_day_year
    records, sha = load_records(a.input)
    rep = run(records, cfg, sha)
    with open(a.output, "w", encoding="utf-8") as fh:
        json.dump(rep, fh, indent=2, ensure_ascii=False)
    s = rep["summary"]
    print(f"records={s['input_records']} consolidated={s['consolidated_findings']} "
          f"scored={s['scored']} unscored={s['unscored']}")
    if s["overall"]:
        print(f"overall={s['overall']['score']} ({s['overall']['band']})  "
              f"worst_layer={s['worst_layer']['layer']} {s['worst_layer']['score']} ({s['worst_layer']['band']})")
    print("bands:", s["by_band"])
    print(f"written: {a.output}")


if __name__ == "__main__":
    sys.exit(main())
