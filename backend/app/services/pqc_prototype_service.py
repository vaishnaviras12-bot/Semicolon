"""
PQC Experimental Prototype Service using Open Quantum Safe (liboqs)
===================================================================
Executes real in-memory post-quantum cryptographic operations (ML-KEM-768, ML-DSA-65)
using liboqs / python-oqs bindings.

Key Principles:
1. Performs REAL liboqs crypto operations when liboqs is available.
2. Measures execution timings using time.perf_counter().
3. Never persists private keys to disk, DB, or logs (in-memory execution only).
4. Handles liboqs unavailable status gracefully (status = 'unavailable').
5. Handles unsupported / ambiguous recommendations cleanly (status = 'unsupported').
6. Never modifies scanned files, application source code, or certificates.
"""

import sys
import platform
import time
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger("ecdat.pqc_prototype_service")

# Check for liboqs python bindings
OQS_AVAILABLE = False
OQS_IMPORT_ERROR: Optional[str] = None
try:
    import oqs  # type: ignore
    OQS_AVAILABLE = True
except (Exception, SystemExit) as err:
    OQS_AVAILABLE = False
    _os_name = platform.system()
    _lib_name = "oqs.dll" if _os_name == "Windows" else ("liboqs.so" if _os_name == "Linux" else "liboqs.dylib")
    OQS_IMPORT_ERROR = f"Native {_lib_name} shared library not found or failed to load: {str(err)}"


def get_pqc_environment_diagnostics() -> Dict[str, Any]:
    """
    Returns OS-independent environment diagnostics regarding liboqs availability,
    platform information, and enabled post-quantum algorithms.
    """
    diag = {
        "operating_system": platform.system(),
        "os_release": platform.release(),
        "cpu_architecture": f"{platform.architecture()[0]} {platform.machine()}",
        "python_version": sys.version.split()[0],
        "python_executable": sys.executable,
        "oqs_available": OQS_AVAILABLE,
        "library": "liboqs",
        "enabled_signature_mechanisms": [],
        "enabled_kem_mechanisms": [],
        "ml_dsa_65_supported": False,
        "ml_kem_768_supported": False,
        "unavailability_reason": OQS_IMPORT_ERROR if not OQS_AVAILABLE else None
    }

    if OQS_AVAILABLE:
        try:
            sigs = oqs.get_enabled_sig_mechanisms()
            kems = oqs.get_enabled_kem_mechanisms()
            diag["enabled_signature_mechanisms"] = sigs
            diag["enabled_kem_mechanisms"] = kems
            diag["ml_dsa_65_supported"] = any(m in sigs for m in ("ML-DSA-65", "Dilithium3", "MLDSA65"))
            diag["ml_kem_768_supported"] = any(m in kems for m in ("ML-KEM-768", "Kyber768", "MLKEM768"))
        except Exception as e:
            diag["unavailability_reason"] = f"Error querying oqs mechanisms: {str(e)}"

    return diag


def determine_pqc_target(algorithm: str, recommendation: Optional[Dict[str, Any]], purpose: Optional[str] = None) -> Dict[str, Any]:
    """
    Determines the target PQC algorithm and operational mode from existing finding and recommendation metadata.
    """
    rec = recommendation or {}
    primary = str(rec.get("primary", "")).strip()
    purp = str(purpose or "").lower()
    alg_upper = str(algorithm or "").upper()

    hybrid_note = None
    if "+" in primary or "HYBRID" in primary.upper():
        hybrid_note = "PQC component prototype only"

    # 0. Non-asymmetric algorithms (Hashes, Symmetric Ciphers, MACs) do NOT map to ML-KEM or ML-DSA prototypes
    is_mac_alg = (purp in ("mac", "authentication")) or any(m in alg_upper for m in ["HMAC", "POLY1305", "CMAC"])
    is_hash_alg = not is_mac_alg and ((purp in ("hashing", "hash")) or any(h in alg_upper for h in ["SHA1", "SHA-1", "MD5", "SHA256", "SHA-256", "SHA384", "SHA-384", "SHA512", "SHA-512", "SHA3", "BLAKE"]))
    is_symmetric_alg = not is_mac_alg and ((purp in ("encryption", "symmetric_encryption")) or any(s in alg_upper for s in ["AES", "CHACHA", "3DES", "DES", "BLOWFISH", "RC4", "CIPHER"]))
    is_composite_sig = any(sig in alg_upper for sig in ["RSA", "ECDSA", "DSA", "ED25519", "WITH"])

    if (is_hash_alg or is_symmetric_alg or is_mac_alg) and not is_composite_sig and purp not in ("signing", "signature_verification", "key_establishment", "key_exchange"):
        if is_mac_alg:
            target_alg = primary if (primary and "ML-" not in primary and "Manual" not in primary) else "HMAC-SHA256"
            reason_msg = f"{algorithm} is a Message Authentication Code (MAC) and relies on symmetric key sizing."
            setup_msg = "MAC operations rely on symmetric key sizing (256-bit+ secret keying) and do not map directly to asymmetric ML-KEM/ML-DSA experimental operations."
        elif is_hash_alg:
            target_alg = primary if (primary and "ML-" not in primary and "Manual" not in primary) else "SHA-256 / SHA-384"
            reason_msg = f"{algorithm} is a hash algorithm and does not map directly to ML-KEM or ML-DSA experimental operations."
            setup_msg = "Hash algorithms (SHA-1, SHA-256, etc.) should be migrated to modern secure hashes (SHA-256 / SHA-384 / SHA-3). Lattice PQC prototypes apply to asymmetric key exchange and signatures."
        elif is_symmetric_alg:
            target_alg = primary if (primary and "ML-" not in primary and "Manual" not in primary) else "AES-256-GCM"
            reason_msg = f"{algorithm} is a symmetric cipher; PQC resilience relies on increasing key lengths (AES-256)."
            setup_msg = "Symmetric ciphers are evaluated under Grover's security model (256-bit keying); liboqs lattice prototype is applicable to asymmetric KEM/Signature standards."

        return {
            "pqc_algorithm": target_alg,
            "operation_mode": "not_applicable",
            "is_supported": False,
            "reason": reason_msg,
            "setup_info": setup_msg,
            "hybrid_note": hybrid_note
        }

    # 1. Asymmetric / Shor-vulnerable algorithm PQC target resolution
    if "ML-DSA" in primary or "SLH-DSA" in primary or "FALCON" in primary or purp in ("signing", "signature_verification") or any(k in alg_upper for k in ["ECDSA", "ED25519", "DSA"]):
        pqc_alg = "ML-DSA-65"
        op_mode = "sign_verify"
        is_supported = True
        reason = None
    else:
        # Automated default for key establishment, encryption, and unresolved asymmetric algorithms (RSA/ECC)
        pqc_alg = "ML-KEM-768"
        op_mode = "encapsulate_decapsulate"
        is_supported = True
        reason = None
        if purp in ("unknown", "ambiguous", "none", "null", "") or not primary or "Manual" in primary:
            hybrid_note = "Automated Experimental Mapping"

    return {
        "pqc_algorithm": pqc_alg,
        "operation_mode": op_mode,
        "is_supported": is_supported,
        "reason": reason,
        "hybrid_note": hybrid_note
    }


def _resolve_oqs_mechanism(pqc_alg: str, op_mode: str) -> Optional[str]:
    """Maps PQC algorithm display names to exact oqs mechanism strings."""
    if not OQS_AVAILABLE:
        return pqc_alg

    if op_mode == "sign_verify":
        try:
            enabled = oqs.get_enabled_sig_mechanisms()
            candidates = [pqc_alg, pqc_alg.replace("-", ""), "ML-DSA-65", "Dilithium3", "Dilithium-3", "MLDSA65"]
            for c in candidates:
                if c in enabled:
                    return c
        except Exception:
            pass
        return None
    elif op_mode == "encapsulate_decapsulate":
        try:
            enabled = oqs.get_enabled_kem_mechanisms()
            candidates = [pqc_alg, pqc_alg.replace("-", ""), "ML-KEM-768", "Kyber768", "Kyber-768", "MLKEM768"]
            for c in candidates:
                if c in enabled:
                    return c
        except Exception:
            pass
        return None
    return None


def run_pqc_prototype(finding_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Executes an isolated, in-memory experimental PQC prototype operation using liboqs.
    Does NOT modify scanned files, database models, or application code.
    """
    alg = finding_data.get("algorithm", "RSA-2048")
    rec = finding_data.get("recommendation", {})
    purpose = finding_data.get("purpose")

    target_info = determine_pqc_target(alg, rec, purpose)
    pqc_alg = target_info["pqc_algorithm"]
    op_mode = target_info["operation_mode"]
    is_supported = target_info["is_supported"]
    hybrid_note = target_info["hybrid_note"]

    # 1. Not Applicable Check (e.g. Hashes, Symmetric Ciphers, MACs)
    if op_mode == "not_applicable":
        return {
            "status": "not_applicable",
            "mode": "experimental",
            "library": "liboqs",
            "algorithm": pqc_alg,
            "operation": op_mode,
            "message": "PQC prototype execution is not applicable for non-asymmetric cryptographic primitives.",
            "reason": target_info.get("reason") or f"{alg} does not map directly to ML-KEM or ML-DSA experimental operations.",
            "setup_info": target_info.get("setup_info") or "PQC lattice prototypes (ML-KEM-768 / ML-DSA-65) apply to asymmetric key exchange and signatures.",
            "hybrid_note": hybrid_note,
            "validation": {
                "key_generation": False,
                "operation": False,
                "verification": False
            },
            "metrics": None
        }

    # 2. Environment Check: liboqs unavailable
    if not OQS_AVAILABLE:
        return {
            "status": "unavailable",
            "mode": "experimental",
            "library": "liboqs",
            "algorithm": pqc_alg,
            "operation": op_mode,
            "message": "Experimental PQC prototype unavailable",
            "reason": "liboqs is not installed/configured in the current environment.",
            "setup_info": "Install a compatible liboqs library and Python oqs binding to execute live prototype operations.",
            "hybrid_note": hybrid_note,
            "validation": {
                "key_generation": False,
                "operation": False,
                "verification": False
            },
            "metrics": None
        }

    # 3. Needs Review Check (e.g. RSA with unknown purpose)
    if op_mode == "needs_review":
        return {
            "status": "needs_review",
            "mode": "experimental",
            "library": "liboqs",
            "algorithm": pqc_alg,
            "operation": op_mode,
            "message": "PQC prototype operation requires manual purpose resolution.",
            "reason": target_info.get("reason") or "Operational purpose is unresolved.",
            "setup_info": "Manual cryptographic review is required for this finding before running a prototype.",
            "candidate_algorithms": target_info.get("candidate_algorithms", []),
            "hybrid_note": hybrid_note,
            "validation": {
                "key_generation": False,
                "operation": False,
                "verification": False
            },
            "metrics": None
        }

    # 4. Unsupported Check
    if not is_supported:
        return {
            "status": "unsupported",
            "mode": "experimental",
            "library": "liboqs",
            "algorithm": pqc_alg,
            "operation": op_mode,
            "message": "PQC prototype operation is unsupported.",
            "reason": target_info.get("reason") or "No unambiguous PQC prototype operation mapped.",
            "setup_info": "Manual code review is required for this finding before running a prototype.",
            "hybrid_note": hybrid_note,
            "validation": {
                "key_generation": False,
                "operation": False,
                "verification": False
            },
            "metrics": None
        }

    # 3. Live OQS Execution
    try:
        oqs_mech = _resolve_oqs_mechanism(pqc_alg, op_mode)
        if not oqs_mech:
            return {
                "status": "unsupported",
                "mode": "experimental",
                "library": "liboqs",
                "algorithm": pqc_alg,
                "operation": op_mode,
                "message": f"Algorithm '{pqc_alg}' is not enabled in the installed liboqs build.",
                "reason": f"Mechanism '{pqc_alg}' not found in enabled oqs mechanisms.",
                "setup_info": "Build liboqs with support for NIST FIPS 203/204 mechanisms.",
                "hybrid_note": hybrid_note,
                "validation": {
                    "key_generation": False,
                    "operation": False,
                    "verification": False
                },
                "metrics": None
            }

        # --- ML-DSA-65 (Digital Signatures) ---
        if op_mode == "sign_verify":
            start_kg = time.perf_counter()
            with oqs.Signature(oqs_mech) as signer:
                pub_key = signer.generate_keypair()
                kg_ms = (time.perf_counter() - start_kg) * 1000.0

                test_msg = b"ECDAT experimental PQC prototype message"
                start_sign = time.perf_counter()
                signature = signer.sign(test_msg)
                sign_ms = (time.perf_counter() - start_sign) * 1000.0

                start_val = time.perf_counter()
                is_valid = signer.verify(test_msg, signature, pub_key)
                val_ms = (time.perf_counter() - start_val) * 1000.0

            status_str = "success" if is_valid else "failed"
            return {
                "status": status_str,
                "mode": "experimental",
                "library": "liboqs",
                "algorithm": pqc_alg,
                "operation": "sign_verify",
                "message": "Real liboqs digital signature signing and verification succeeded." if is_valid else "Signature verification failed.",
                "hybrid_note": hybrid_note,
                "validation": {
                    "key_generation": True,
                    "signing": True,
                    "verification": is_valid
                },
                "metrics": {
                    "key_generation_ms": round(kg_ms, 3),
                    "signing_ms": round(sign_ms, 3),
                    "verification_ms": round(val_ms, 3),
                    "public_key_bytes": len(pub_key),
                    "signature_bytes": len(signature)
                }
            }

        # --- ML-KEM-768 (Key Encapsulation) ---
        elif op_mode == "encapsulate_decapsulate":
            start_kg = time.perf_counter()
            with oqs.KeyEncapsulation(oqs_mech) as client:
                pub_key = client.generate_keypair()
                kg_ms = (time.perf_counter() - start_kg) * 1000.0

                start_encap = time.perf_counter()
                ciphertext, shared_secret_server = client.encap_secret(pub_key)
                encap_ms = (time.perf_counter() - start_encap) * 1000.0

                start_decap = time.perf_counter()
                shared_secret_client = client.decap_secret(ciphertext)
                decap_ms = (time.perf_counter() - start_decap) * 1000.0

                secrets_match = (shared_secret_server == shared_secret_client)

            status_str = "success" if secrets_match else "failed"
            return {
                "status": status_str,
                "mode": "experimental",
                "library": "liboqs",
                "algorithm": pqc_alg,
                "operation": "encapsulate_decapsulate",
                "message": "Real liboqs key encapsulation and decapsulation succeeded." if secrets_match else "Shared secret match failed.",
                "hybrid_note": hybrid_note,
                "validation": {
                    "key_generation": True,
                    "encapsulation": True,
                    "decapsulation": True,
                    "shared_secret_match": secrets_match
                },
                "metrics": {
                    "key_generation_ms": round(kg_ms, 3),
                    "encapsulation_ms": round(encap_ms, 3),
                    "decapsulation_ms": round(decap_ms, 3),
                    "public_key_bytes": len(pub_key),
                    "ciphertext_bytes": len(ciphertext),
                    "shared_secret_bytes": len(shared_secret_server)
                }
            }

    except Exception as err:
        logger.error(f"Error executing liboqs prototype for {pqc_alg}: {err}")
        return {
            "status": "failed",
            "mode": "experimental",
            "library": "liboqs",
            "algorithm": pqc_alg,
            "operation": op_mode,
            "message": f"Cryptographic execution error during liboqs prototype: {str(err)}",
            "reason": str(err),
            "hybrid_note": hybrid_note,
            "validation": {
                "key_generation": False,
                "operation": False,
                "verification": False
            },
            "metrics": None
        }
