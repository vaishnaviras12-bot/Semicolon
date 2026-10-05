"""
ECDAT — Central Algorithm Resolution and Normalization Layer
=============================================================
Resolves raw scanner outputs, import signals, certificates, dependency files,
and dynamic code calls into canonical algorithm representations with clear,
explicit resolution statuses.

This module enforces:
1. OID dictionary lookups (RSA, ECDSA, Ed25519, Ed448, X25519, SHA-2, SHA-3, AES).
2. API literal argument parser (Java, Python, JS/TS, C/OpenSSL).
3. Canonical algorithm name standardization and alias mapping.
4. Operational parameters extraction (family, variant, mode, padding, key_size, curve_or_group).
5. Certificate key separation (public-key algorithm vs certificate signature algorithm).
6. Docker & dependency container resolution ('library-only' status, observed_algorithm_usage: unknown).
7. Dynamic algorithm detection ('Runtime-configured' algorithm, resolution_status: 'dynamic').
8. AST, Tree-sitter, Semgrep evidence correlation & merging across detection methods.
9. Cryptographic purpose resolution (signing, signature_verification, key_establishment, encryption, hashing, mac, unknown, ambiguous).
"""

import os
import re
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# 1. OID Dictionary Lookup
# ---------------------------------------------------------------------------
OID_DICTIONARY: Dict[str, Dict[str, Any]] = {
    # RSA OIDs
    "1.2.840.113549.1.1.1": {"algorithm": "RSA", "variant": "PKCS1v15", "family": "Asymmetric"},
    "1.2.840.113549.1.1.10": {"algorithm": "RSA", "variant": "PSS", "family": "Asymmetric", "padding": "PSS"},
    "1.2.840.113549.1.1.5": {"algorithm": "RSA", "variant": "sha1WithRSAEncryption", "family": "Asymmetric", "signature_hash": "SHA-1"},
    "1.2.840.113549.1.1.11": {"algorithm": "RSA", "variant": "sha256WithRSAEncryption", "family": "Asymmetric", "signature_hash": "SHA-256"},
    "1.2.840.113549.1.1.12": {"algorithm": "RSA", "variant": "sha384WithRSAEncryption", "family": "Asymmetric", "signature_hash": "SHA-384"},
    "1.2.840.113549.1.1.13": {"algorithm": "RSA", "variant": "sha512WithRSAEncryption", "family": "Asymmetric", "signature_hash": "SHA-512"},

    # EC / ECDSA OIDs
    "1.2.840.10045.2.1": {"algorithm": "ECC", "family": "Asymmetric"},
    "1.2.840.10045.4.3.2": {"algorithm": "ECDSA", "family": "Asymmetric", "signature_hash": "SHA-256"},
    "1.2.840.10045.4.3.3": {"algorithm": "ECDSA", "family": "Asymmetric", "signature_hash": "SHA-384"},
    "1.2.840.10045.4.3.4": {"algorithm": "ECDSA", "family": "Asymmetric", "signature_hash": "SHA-512"},
    "1.2.840.10045.3.1.7": {"algorithm": "ECDSA", "family": "Asymmetric", "curve": "P-256"},
    "1.3.132.0.34": {"algorithm": "ECDSA", "family": "Asymmetric", "curve": "P-384"},
    "1.3.132.0.35": {"algorithm": "ECDSA", "family": "Asymmetric", "curve": "P-521"},

    # EdDSA / DH / X25519 OIDs
    "1.3.101.112": {"algorithm": "Ed25519", "family": "Asymmetric", "curve": "Ed25519"},
    "1.3.101.113": {"algorithm": "Ed448", "family": "Asymmetric", "curve": "Ed448"},
    "1.3.101.110": {"algorithm": "X25519", "family": "Asymmetric", "curve": "X25519"},
    "1.3.101.111": {"algorithm": "X448", "family": "Asymmetric", "curve": "X448"},
    "1.2.840.10046.2.1": {"algorithm": "DH", "family": "Asymmetric"},

    # Hash OIDs
    "2.16.840.1.101.3.4.2.1": {"algorithm": "SHA-256", "family": "Hash"},
    "2.16.840.1.101.3.4.2.2": {"algorithm": "SHA-384", "family": "Hash"},
    "2.16.840.1.101.3.4.2.3": {"algorithm": "SHA-512", "family": "Hash"},
    "2.16.840.1.101.3.4.2.7": {"algorithm": "SHA3-256", "family": "Hash"},
    "2.16.840.1.101.3.4.2.8": {"algorithm": "SHA3-384", "family": "Hash"},
    "2.16.840.1.101.3.4.2.9": {"algorithm": "SHA3-512", "family": "Hash"},
    "1.3.14.3.2.26": {"algorithm": "SHA-1", "family": "Hash"},
    "1.2.840.113549.2.5": {"algorithm": "MD5", "family": "Hash"},

    # AES OIDs
    "2.16.840.1.101.3.4.1.1": {"algorithm": "AES", "key_size": 128, "mode": "ECB", "family": "Symmetric"},
    "2.16.840.1.101.3.4.1.2": {"algorithm": "AES", "key_size": 128, "mode": "CBC", "family": "Symmetric"},
    "2.16.840.1.101.3.4.1.6": {"algorithm": "AES", "key_size": 128, "mode": "GCM", "family": "Symmetric"},
    "2.16.840.1.101.3.4.1.21": {"algorithm": "AES", "key_size": 256, "mode": "ECB", "family": "Symmetric"},
    "2.16.840.1.101.3.4.1.22": {"algorithm": "AES", "key_size": 256, "mode": "CBC", "family": "Symmetric"},
    "2.16.840.1.101.3.4.1.46": {"algorithm": "AES", "key_size": 256, "mode": "GCM", "family": "Symmetric"},
}


# ---------------------------------------------------------------------------
# 2. Canonical Name Standardization & Alias Mapping
# ---------------------------------------------------------------------------
ALIAS_MAP: Dict[str, str] = {
    # RSA
    "RSA": "RSA",
    "RSAENCRYPTION": "RSA",
    "RSASSA-PKCS1-V1_5": "RSA",
    "RSASSA_PKCS1_V1_5_SHA_256": "RSA",
    "RSA_SIGN_PKCS1_2048_SHA256": "RSA",
    "RSASSA-PSS": "RSA",
    "RSA-PSS": "RSA",
    "RSA-2048": "RSA",
    "RSA-4096": "RSA",
    "RSA-1024": "RSA",
    "RSA-3072": "RSA",
    "RS256": "RSA",
    "RS384": "RSA",
    "RS512": "RSA",
    "PS256": "RSA",
    "PS384": "RSA",
    "PS512": "RSA",

    # EC / ECDSA / ECDH / EdDSA
    "EC": "ECC",
    "ECC": "ECC",
    "ECDSA": "ECDSA",
    "ECPUBLICKEY": "ECC",
    "ID-ECPUBLICKEY": "ECC",
    "ID_ECPUBLICKEY": "ECC",
    "ES256": "ECDSA",
    "ES384": "ECDSA",
    "ES512": "ECDSA",
    "ECDH": "ECDH",
    "ED25519": "Ed25519",
    "ED448": "Ed448",
    "X25519": "X25519",
    "X448": "X448",
    "CURVE25519": "X25519",
    "SECP256R1": "ECC",
    "SECP384R1": "ECC",
    "SECP521R1": "ECC",
    "P-256": "ECC",
    "P-384": "ECC",
    "P-521": "ECC",

    # Hashes
    "MD5": "MD5",
    "SHA1": "SHA-1",
    "SHA-1": "SHA-1",
    "SHA256": "SHA-256",
    "SHA-256": "SHA-256",
    "SHA384": "SHA-384",
    "SHA-384": "SHA-384",
    "SHA512": "SHA-512",
    "SHA-512": "SHA-512",
    "SHA3-256": "SHA3-256",
    "SHA3_256": "SHA3-256",
    "SHA3-384": "SHA3-384",
    "SHA3-512": "SHA3-512",

    # Symmetric
    "AES": "AES",
    "AES-128": "AES",
    "AES-192": "AES",
    "AES-256": "AES",
    "AES-128-GCM": "AES",
    "AES-256-GCM": "AES",
    "AES-128-CBC": "AES",
    "AES-256-CBC": "AES",
    "AES-128-ECB": "AES",
    "AES-256-ECB": "AES",
    "DES": "DES",
    "3DES": "3DES",
    "TRIPLEDES": "3DES",
    "DES-EDE3": "3DES",
    "CHACHA20": "ChaCha20",
    "CHACHA20-POLY1305": "ChaCha20",

    # Key Exchange / Protocols / Signatures
    "DH": "DH",
    "DIFFIE-HELLMAN": "DH",
    "DSA": "DSA",
    "HMAC": "HMAC",
    "HMAC-SHA256": "HMAC-SHA256",
    "HMAC-SHA512": "HMAC-SHA512",
    "TLS": "TLS",
    "TLS1.2": "TLS-1.2",
    "TLS1.3": "TLS-1.3",
    "TLS-1.2": "TLS-1.2",
    "TLS-1.3": "TLS-1.3",
    "SSL": "SSL",
    "SSH": "SSH",
}

FAMILY_MAP: Dict[str, str] = {
    "RSA": "Asymmetric",
    "ECC": "Asymmetric",
    "ECDSA": "Asymmetric",
    "ECDH": "Asymmetric",
    "Ed25519": "Asymmetric",
    "Ed448": "Asymmetric",
    "X25519": "Asymmetric",
    "X448": "Asymmetric",
    "DH": "Asymmetric",
    "DSA": "Asymmetric",
    "AES": "Symmetric",
    "DES": "Symmetric",
    "3DES": "Symmetric",
    "ChaCha20": "Symmetric",
    "SHA-256": "Hash",
    "SHA-384": "Hash",
    "SHA-512": "Hash",
    "SHA3-256": "Hash",
    "SHA3-384": "Hash",
    "SHA3-512": "Hash",
    "SHA-1": "Hash",
    "MD5": "Hash",
    "HMAC": "MAC",
    "HMAC-SHA256": "MAC",
    "HMAC-SHA512": "MAC",
    "TLS-1.2": "Protocol",
    "TLS-1.3": "Protocol",
    "SSL": "Protocol",
    "SSH": "Protocol",
}


class AlgorithmResolver:
    """
    Central Resolution Engine that processes raw artifacts into normalized CBOM entries.
    """

    def __init__(self):
        pass

    def resolve_artifact(self, artifact: Dict[str, Any]) -> Dict[str, Any]:
        """
        Non-destructively resolves algorithm name, parameters, purpose, and resolution status.
        """
        res = dict(artifact)

        raw_alg = str(res.get("algorithm") or "").strip()
        art_type = str(res.get("artifact_type") or "").lower()
        code_snippet = str(res.get("code_snippet") or res.get("evidence") or "")
        file_path = str(res.get("file_path") or res.get("location") or "")

        # -------------------------------------------------------------------
        # Rule A: OID Resolution (Certificates, ASN.1)
        # -------------------------------------------------------------------
        oid = res.get("oid") or self._extract_oid(code_snippet)
        if oid and oid in OID_DICTIONARY:
            oid_info = OID_DICTIONARY[oid]
            res["algorithm"] = oid_info["algorithm"]
            res["family"] = oid_info["family"]
            if "variant" in oid_info:
                res["variant"] = oid_info["variant"]
            if "signature_hash" in oid_info:
                res["signature_hash"] = oid_info["signature_hash"]
            if "key_size" in oid_info and not res.get("key_size"):
                res["key_size"] = oid_info["key_size"]
            if "mode" in oid_info and not res.get("mode"):
                res["mode"] = oid_info["mode"]
            if "curve" in oid_info and not res.get("curve"):
                res["curve"] = oid_info["curve"]
            res["resolution_status"] = "resolved"
            res["resolution_reason"] = f"Resolved via OID lookup: {oid}"
            self._enrich_purpose(res)
            return res

        # -------------------------------------------------------------------
        # Rule B: Certificate Artifact Resolution
        # -------------------------------------------------------------------
        if art_type in ("certificate", "cert") or self._is_cert_file(file_path):
            return self._resolve_certificate(res)

        # -------------------------------------------------------------------
        # Rule C: Dependency / Docker / Import-Signal (Library-only)
        # -------------------------------------------------------------------
        if art_type in ("import_signal", "library", "dependency", "container") or self._is_manifest_file(file_path):
            # Check if code snippet actually invokes a specific algorithm operation
            extracted_alg, extra_params = self._parse_api_literals(code_snippet)
            if extracted_alg and extracted_alg != "UNSPECIFIED":
                res["algorithm"] = extracted_alg
                res.update(extra_params)
                res["resolution_status"] = "resolved"
                res["resolution_reason"] = "Extracted literal algorithm from API call context"
                self._enrich_purpose(res)
                return res
            
            # Check for Docker CLI command literals (e.g. openssl genrsa -2048, openssl dgst -sha256, openssl enc -aes-256-gcm)
            docker_alg, docker_params = self._parse_docker_cli_commands(code_snippet)
            if docker_alg:
                res["algorithm"] = docker_alg
                res.update(docker_params)
                res["resolution_status"] = "resolved"
                res["resolution_reason"] = "Extracted literal algorithm from Docker CLI command execution"
                self._enrich_purpose(res)
                return res

            # Pure library import signal or container package
            res["resolution_status"] = "library-only"
            res["resolution_reason"] = "Cryptographic library or dependency identified without specific static algorithm call"
            res["observed_algorithm_usage"] = "unknown"
            res["cbom_category"] = "Library"
            if not res.get("algorithm") or res["algorithm"] == "UNSPECIFIED":
                res["algorithm"] = res.get("library") or self._infer_library_name(file_path, code_snippet) or "Crypto-Library"
            return res

        extracted_alg, extra_params = self._parse_api_literals(code_snippet)
        if extracted_alg:
            res.update(extra_params)
            # If original algorithm string has key_size/mode (e.g. AES-256), extract before overriding
            self._extract_embedded_params(raw_alg, res)
            if raw_alg.upper().startswith("HMAC") and not extracted_alg.upper().startswith("HMAC"):
                pass
            else:
                raw_alg = extracted_alg

        # -------------------------------------------------------------------
        # Rule E: Dynamic Algorithm Call Detection
        # -------------------------------------------------------------------
        if self._is_dynamic_call(code_snippet, raw_alg):
            res["algorithm"] = "Runtime-configured"
            res["resolution_status"] = "dynamic"
            res["resolution_reason"] = "Algorithm parameter passed dynamically via variable or runtime configuration"
            res["purpose"] = self._resolve_purpose(res, code_snippet)
            res["purpose_confidence"] = 0.6
            res["purpose_evidence"] = ["Dynamic crypto API invocation detected"]
            return res

        # -------------------------------------------------------------------
        # Rule F: Canonical Standardization & Alias Normalization
        # -------------------------------------------------------------------
        canonical = self._canonicalize_algorithm(raw_alg)

        if canonical and canonical != "UNSPECIFIED":
            res["algorithm"] = canonical
            res["family"] = FAMILY_MAP.get(canonical, res.get("family", "Unknown"))
            res["resolution_status"] = "resolved"
            res["resolution_reason"] = f"Canonicalized from raw algorithm string '{raw_alg}'"
            
            # Extract key_size/mode from raw string if missing (e.g. RSA-2048, AES-256-GCM)
            self._extract_embedded_params(raw_alg, res)
            self._enrich_purpose(res)
            return res

        # -------------------------------------------------------------------
        # Fallback / Insufficient Evidence
        # -------------------------------------------------------------------
        if not raw_alg or raw_alg == "UNSPECIFIED":
            res["algorithm"] = "Unresolved Cryptographic Artifact"
            res["resolution_status"] = "insufficient-evidence"
            res["resolution_reason"] = "Scanner detected cryptographic evidence but algorithm details could not be statically parsed"
            res["purpose"] = "unknown"
            res["purpose_confidence"] = 0.0
            res["purpose_evidence"] = ["No algorithm name or literal arguments found"]
        else:
            res["algorithm"] = raw_alg
            res["resolution_status"] = "unsupported-format"
            res["resolution_reason"] = f"Algorithm format '{raw_alg}' not present in standard canonical map"
            self._enrich_purpose(res)

        return res

    def resolve_artifacts(self, artifacts: List[Dict[str, Any]], merge_evidence: bool = True) -> List[Dict[str, Any]]:
        """
        Resolves a list of artifacts, performs cross-source evidence correlation,
        and optionally merges duplicate findings across detectors for identical code locations.
        """
        resolved_list = [self.resolve_artifact(a) for a in artifacts]
        correlated_list = self.correlate_cross_source_evidence(resolved_list)
        if merge_evidence:
            return self.merge_correlated_evidence(correlated_list)
        return correlated_list

    # ---------------------------------------------------------------------------
    # Internal Helpers: Certificate Resolution
    # ---------------------------------------------------------------------------
    def _resolve_certificate(self, res: Dict[str, Any]) -> Dict[str, Any]:
        res["cbom_category"] = "Certificate"
        pub_key_alg = res.get("certificate_public_key_algorithm") or res.get("public_key_algorithm") or res.get("algorithm") or ""
        sig_alg = res.get("certificate_signature_algorithm") or res.get("signature_algorithm") or ""
        key_size = res.get("key_size") or res.get("certificate_key_size")
        curve = res.get("certificate_ec_curve") or res.get("ec_curve") or res.get("curve")

        # Public key resolution
        pub_canonical = self._canonicalize_algorithm(pub_key_alg)
        if not pub_canonical or pub_canonical == "UNSPECIFIED":
            if curve:
                pub_canonical = "ECC"
            elif key_size and key_size >= 1024:
                pub_canonical = "RSA"

        # Separate certificate details
        res["public_key_algorithm"] = pub_canonical or "RSA"
        res["signature_algorithm"] = sig_alg or "sha256WithRSAEncryption"
        res["algorithm"] = pub_canonical or "RSA"
        if key_size:
            res["key_size"] = key_size
        if curve:
            res["curve"] = curve

        res["certificate_details"] = {
            "public_key_algorithm": res["public_key_algorithm"],
            "key_size": res.get("key_size"),
            "curve": res.get("curve"),
            "signature_algorithm": res["signature_algorithm"],
            "issuer": res.get("issuer") or res.get("certificate_issuer"),
            "subject": res.get("subject") or res.get("certificate_subject"),
            "serial_number": res.get("serial_number"),
            "not_before": res.get("not_before"),
            "not_after": res.get("not_after") or res.get("certificate_expiry"),
            "san": res.get("subject_alternative_names"),
        }

        res["resolution_status"] = "resolved"
        res["resolution_reason"] = "Certificate public key and signature algorithm parsed and separated"
        res["purpose"] = "signature_verification"
        res["purpose_confidence"] = 0.95
        res["purpose_evidence"] = ["X.509 Certificate artifact with public key and signature details"]
        return res

    # ---------------------------------------------------------------------------
    # Internal Helpers: API Literal Parser
    # ---------------------------------------------------------------------------
    def _parse_api_literals(self, code: str) -> Tuple[Optional[str], Dict[str, Any]]:
        if not code:
            return None, {}

        params: Dict[str, Any] = {}

        # 1. Java Cipher.getInstance("AES/GCM/NoPadding") or Cipher.getInstance("RSA/ECB/PKCS1Padding")
        cipher_match = re.search(r'Cipher\.getInstance\s*\(\s*["\']([^"\']+)["\']', code, re.IGNORECASE)
        if cipher_match:
            parts = cipher_match.group(1).split("/")
            params["algorithm"] = parts[0]
            if len(parts) > 1:
                params["mode"] = parts[1]
            if len(parts) > 2:
                params["padding"] = parts[2]
            return parts[0], params

        # 2. Java KeyPairGenerator.getInstance("RSA") or Signature.getInstance("SHA256withRSA")
        sig_match = re.search(r'Signature\.getInstance\s*\(\s*["\']([^"\']+)["\']', code, re.IGNORECASE)
        if sig_match:
            sig_str = sig_match.group(1)
            params["signature_algorithm"] = sig_str
            if "with" in sig_str.lower():
                hash_p, alg_p = sig_str.lower().split("with", 1)
                params["hash_algorithm"] = hash_p.upper()
                return alg_p.upper(), params
            return sig_str, params

        kpg_match = re.search(r'KeyPairGenerator\.getInstance\s*\(\s*["\']([^"\']+)["\']', code, re.IGNORECASE)
        if kpg_match:
            return kpg_match.group(1), params

        # Key size in Java keyPairGen.initialize(2048) or KeyGenerator.init(256)
        ks_match = re.search(r'\.(?:initialize|init)\s*\(\s*(\d{3,4})\s*\)', code, re.IGNORECASE)
        if ks_match:
            params["key_size"] = int(ks_match.group(1))

        # 3. Python cryptography / PyCryptodome literals
        py_aes = re.search(r'AES\.new\s*\(.*?,?\s*AES\.MODE_([A-Z0-9]+)', code)
        if py_aes:
            params["mode"] = py_aes.group(1)
            return "AES", params

        # HMAC literals (Python / Node.js)
        py_hmac = re.search(r'(?:hmac\.HMAC|hmac\.new|Crypto\.Hash\.HMAC)\s*\(\s*.*?,?\s*(?:hashes\.|hashlib\.)?(SHA256|SHA384|SHA512|SHA1|sha256|sha384|sha512|sha1)', code, re.IGNORECASE)
        if py_hmac:
            hname = py_hmac.group(1).upper()
            if hname.startswith("SHA") and "-" not in hname:
                hname = "SHA-" + hname[3:]
            params["purpose"] = "mac"
            params["family"] = "MAC"
            return f"HMAC-{hname}", params

        js_hmac = re.search(r'crypto\.createHmac\s*\(\s*["\']([^"\']+)["\']', code, re.IGNORECASE)
        if js_hmac:
            hname = js_hmac.group(1).upper()
            if hname.startswith("SHA") and "-" not in hname:
                hname = "SHA-" + hname[3:]
            params["purpose"] = "mac"
            params["family"] = "MAC"
            return f"HMAC-{hname}", params

        py_hash = re.search(r'(?:hashes|hashlib)\.(SHA256|SHA384|SHA512|MD5|SHA1|sha256|sha384|sha512|md5|sha1)\s*\(', code)
        if py_hash:
            hname = py_hash.group(1).upper()
            if hname.startswith("SHA") and "-" not in hname:
                hname = "SHA-" + hname[3:]
            return hname, params

        py_rsa_gen = re.search(r'(?:RSA\.generate|generate_private_key)\s*\(\s*(?:.*key_size\s*=\s*)?(\d{3,4})', code)
        if py_rsa_gen:
            params["key_size"] = int(py_rsa_gen.group(1))
            return "RSA", params

        # 4. JS / TS crypto.createHash('sha256') / crypto.createCipheriv('aes-256-gcm', key, iv)
        js_hash = re.search(r'crypto\.createHash\s*\(\s*["\']([^"\']+)["\']', code, re.IGNORECASE)
        if js_hash:
            return js_hash.group(1), params

        js_cipher = re.search(r'crypto\.createCipheriv\s*\(\s*["\']([^"\']+)["\']', code, re.IGNORECASE)
        if js_cipher:
            c_str = js_cipher.group(1).upper()
            if "AES-256" in c_str:
                params["key_size"] = 256
            elif "AES-128" in c_str:
                params["key_size"] = 128
            if "GCM" in c_str:
                params["mode"] = "GCM"
            elif "CBC" in c_str:
                params["mode"] = "CBC"
            return "AES", params

        # 5. C / OpenSSL EVP_aes_256_gcm() / EVP_sha256() / EVP_RSA_gen(2048)
        evp_match = re.search(r'EVP_(aes_\d{3}_[a-z0-9]+|sha\d{3}|rsa_gen)', code, re.IGNORECASE)
        if evp_match:
            evp_str = evp_match.group(1).lower()
            if "aes_256" in evp_str:
                params["key_size"] = 256
                if "gcm" in evp_str:
                    params["mode"] = "GCM"
                elif "cbc" in evp_str:
                    params["mode"] = "CBC"
                return "AES", params
            elif "sha256" in evp_str:
                return "SHA-256", params
            elif "rsa_gen" in evp_str:
                return "RSA", params

        return None, params

    def _parse_docker_cli_commands(self, code: str) -> Tuple[Optional[str], Dict[str, Any]]:
        if not code:
            return None, {}

        code_lower = code.lower()
        params: Dict[str, Any] = {}

        # 1. openssl genrsa / rsa / req -newkey rsa:2048
        genrsa_m = re.search(r'openssl\s+(?:genrsa|rsa|req.*?rsa:)\s*.*?(\d{3,4})', code_lower)
        if genrsa_m:
            params["key_size"] = int(genrsa_m.group(1))
            params["purpose"] = "key_establishment" if "genrsa" in code_lower else "signature_verification"
            return "RSA", params
        if "openssl genrsa" in code_lower or "openssl rsa" in code_lower:
            params["key_size"] = 2048
            params["purpose"] = "key_establishment"
            return "RSA", params

        # 2. openssl req / openssl x509
        if "openssl req" in code_lower or "openssl x509" in code_lower:
            params["purpose"] = "signature_verification"
            return "RSA", params

        # 3. openssl dgst -sha256 / -sha384 / -sha512 / -sha1
        dgst_m = re.search(r'openssl\s+dgst.*?-sha(256|384|512|1)\b', code_lower)
        if dgst_m:
            sh_num = dgst_m.group(1)
            params["purpose"] = "hashing"
            return f"SHA-{sh_num}", params

        # 4. openssl enc -aes-256-gcm / -aes-128-cbc
        enc_m = re.search(r'openssl\s+enc.*?-aes-(128|256)-(gcm|cbc|ecb)\b', code_lower)
        if enc_m:
            params["key_size"] = int(enc_m.group(1))
            params["mode"] = enc_m.group(2).upper()
            params["purpose"] = "encryption"
            return "AES", params

        return None, params

    def correlate_cross_source_evidence(self, resolved_artifacts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Phase 2: Correlates library-only / container findings with resolved operational
        findings (from source code AST, binaries, configs, and certificates) across the scan batch.
        """
        if not resolved_artifacts:
            return []

        library_artifacts = []
        operational_artifacts = []

        # Propagate parameters (key_size, curve, mode) within the same file for the same algorithm family
        file_params: Dict[Tuple[str, str], Dict[str, Any]] = {}
        for a in resolved_artifacts:
            fp = str(a.get("file_path") or a.get("location") or "").replace("\\", "/").lower()
            alg = str(a.get("algorithm") or "").upper()
            if fp and alg:
                key = (fp, alg)
                if key not in file_params:
                    file_params[key] = {}
                for field in ("key_size", "curve", "mode"):
                    if a.get(field) and not file_params[key].get(field):
                        file_params[key][field] = a[field]

        # Correlate dynamic calls (resolution_status == "dynamic" or env_var_name) with config environment entries
        config_envs = {}
        for a in resolved_artifacts:
            if a.get("env_var_name") and a.get("config_value"):
                config_envs[a["env_var_name"].upper()] = a

        for a in resolved_artifacts:
            if a.get("resolution_status") == "dynamic" or a.get("algorithm") == "Runtime-configured":
                var_name = a.get("env_var_name") or "ECDAT_ALGORITHM"
                if var_name.upper() in config_envs:
                    cfg_match = config_envs[var_name.upper()]
                    val = str(cfg_match.get("config_value") or cfg_match.get("algorithm") or "")
                    cfg_fp = str(cfg_match.get("file_path") or cfg_match.get("location") or "")
                    cfg_line = cfg_match.get("line_number") or 1

                    a["algorithm"] = val
                    if "${" in val or "$" in val or val.startswith("$"):
                        a["resolution_status"] = "dynamic"
                        a["resolution_reason"] = f"Dynamic configuration template variable '{var_name}={val}' from {cfg_fp}:{cfg_line}"
                    else:
                        a["resolution_status"] = "resolved"
                        a["resolution_reason"] = f"Correlated dynamic call '{a.get('code_snippet')}' with environment variable '{var_name}={val}' from {cfg_fp}:{cfg_line}"
                    self._extract_embedded_params(val, a)
                    self._enrich_purpose(a)
                    
                    ev_list = list(a.get("purpose_evidence") or [])
                    ev_list.append(f"✓ Source evidence: {a.get('file_path')}:{a.get('line_number')} '{a.get('code_snippet')}'")
                    ev_list.append(f"✓ Configuration evidence: {cfg_fp}:{cfg_line} '{var_name}={val}'")
                    a["purpose_evidence"] = ev_list
                    a["correlation"] = "YES"
                else:
                    a["algorithm"] = "Runtime-configured"
                    a["resolution_status"] = "dynamic"
                    a["resolution_reason"] = f"Algorithm parameter passed dynamically via variable '{var_name}' without static environment match"
                    a["correlation"] = "NO"
                    ev_list = list(a.get("purpose_evidence") or [])
                    ev_list.append(f"✓ Source evidence: {a.get('file_path')}:{a.get('line_number')} '{a.get('code_snippet')}'")
                    ev_list.append(f"✗ Configuration evidence: No environment variable '{var_name}' found in configuration files")
                    a["purpose_evidence"] = ev_list

        for a in resolved_artifacts:
            res_status = str(a.get("resolution_status") or "").lower()
            art_type = str(a.get("artifact_type") or "").lower()
            alg = str(a.get("algorithm") or "")

            if res_status == "library-only" or "(library-only)" in alg.lower() or (art_type in ("library", "import_signal", "dependency") and res_status != "resolved"):
                library_artifacts.append(dict(a))
            else:
                operational_artifacts.append(dict(a))

        if not library_artifacts:
            return resolved_artifacts

        # If no operational artifacts exist in the scan, populate negative evidence on library findings
        if not operational_artifacts:
            for lib in library_artifacts:
                lib_fp = str(lib.get("file_path") or lib.get("location") or "Dockerfile")
                lib["purpose_evidence"] = [
                    f"✓ Dependency: {lib.get('algorithm', 'Library')} detected in {lib_fp}",
                    "✗ No source API usage detected",
                    "✗ No binary algorithm evidence detected",
                    "✗ No configuration algorithm detected",
                    "✗ No certificate correlation",
                ]
            return library_artifacts

        # Correlate library presence with operational findings ONLY when concrete evidence links them
        used_libraries = set()

        for lib in library_artifacts:
            lib_fp = str(lib.get("file_path") or lib.get("location") or "Dockerfile").replace("\\", "/").lower()
            lib_alg = str(lib.get("algorithm") or lib.get("library") or "Crypto Library")
            lib_ev = (str(lib.get("code_snippet") or "") + " " + str(lib.get("evidence") or "") + " " + str(lib.get("docker_instruction") or "")).lower()
            is_docker_lib = ("docker" in lib_fp or "dockerfile" in lib_fp)

            matched = False
            for op in operational_artifacts:
                op_fp = str(op.get("file_path") or op.get("location") or "").replace("\\", "/")
                op_fp_lower = op_fp.lower()
                op_basename = os.path.basename(op_fp_lower)

                is_related = False

                if is_docker_lib:
                    # Dockerfile correlation rules:
                    # 1. Op finding IS in the same Dockerfile
                    if op_fp_lower == lib_fp:
                        is_related = True
                    # 2. Dockerfile explicitly copies/references the operational finding file (e.g. COPY certs/rsa2048_cert.pem ...)
                    elif op_basename and len(op_basename) > 3 and op_basename in lib_ev:
                        is_related = True
                    # 3. Root project Dockerfile (or same directory Dockerfile) installing matching ecosystem crypto packages
                    elif (os.path.dirname(lib_fp) == "" or os.path.dirname(lib_fp) == os.path.dirname(op_fp_lower)) and not lib_fp.startswith("docker/"):
                        is_py = op_fp_lower.endswith(".py")
                        is_c_cpp = op_fp_lower.endswith((".c", ".cpp", ".h", ".hpp"))
                        is_java = op_fp_lower.endswith((".java", ".jar"))
                        is_bin = op_fp_lower.endswith((".exe", ".so", ".dll")) or "/bin/" in op_fp_lower or "\\bin\\" in op_fp_lower
                        is_cert = op_fp_lower.endswith((".pem", ".crt", ".der", ".p12", ".pfx"))

                        has_py_pkg = any(k in lib_ev for k in ("cryptography", "pycryptodome", "pynacl", "python"))
                        has_sys_pkg = any(k in lib_ev for k in ("openssl", "libssl", "bouncycastle", "crypto"))

                        if is_py and (has_py_pkg or has_sys_pkg):
                            is_related = True
                        elif (is_c_cpp or is_java or is_bin or is_cert) and has_sys_pkg:
                            is_related = True
                else:
                    # Dependency manifest / import signal correlation rules:
                    # 1. Op finding IS in the same file (e.g. import signal in same python file)
                    if op_fp_lower == lib_fp:
                        is_related = True
                    # 2. Op finding is in the same directory as the dependency manifest (e.g. requirements.txt)
                    elif self._is_manifest_file(lib_fp) and os.path.dirname(op_fp_lower) == os.path.dirname(lib_fp):
                        is_related = True

                if is_related:
                    sources = list(op.get("detection_sources") or [op.get("detection_method", "static_analysis")])
                    src_type = "dockerfile" if is_docker_lib else "dependency_manifest"
                    if src_type not in [s.lower() for s in sources]:
                        sources.append(src_type)

                    op["detection_sources"] = list(set(sources))
                    ev_list = list(op.get("purpose_evidence") or [])
                    msg = f"✓ Correlated with library dependency '{lib_alg}' from {lib.get('file_path')}"
                    if msg not in ev_list:
                        ev_list.append(msg)
                    op["purpose_evidence"] = ev_list
                    matched = True

            if matched:
                used_libraries.add(id(lib))
            else:
                lib["confidence"] = float(lib.get("confidence") if lib.get("confidence") is not None else 0.65)
                lib["purpose_evidence"] = [
                    f"✓ Dependency: {lib_alg} detected in {lib_fp}",
                    "✗ No source API usage detected",
                    "✗ No binary algorithm evidence detected",
                    "✗ No configuration algorithm detected",
                    "✗ No certificate correlation",
                ]

        # Combine operational findings and any un-correlated library findings
        output = list(operational_artifacts)
        for lib in library_artifacts:
            if id(lib) not in used_libraries:
                output.append(lib)

        return output

    # ---------------------------------------------------------------------------
    # Internal Helpers: Dynamic Calls & Canonicalization
    # ---------------------------------------------------------------------------
    def _is_dynamic_call(self, code: str, raw_alg: str) -> bool:
        if not code and not raw_alg:
            return False
        if raw_alg and (re.search(r'\$\{[^}]+\}|\$[A-Z0-9_]+', raw_alg) or raw_alg.startswith("${") or raw_alg.startswith("$")):
            return True
        if code and re.search(r'\$\{[^}]+\}|\$[A-Z0-9_]+', code):
            return True
        # Dynamic variable patterns: Cipher.getInstance(varName), createHash(req.body.algo), Signature.getInstance(config["algo"])
        dynamic_patterns = [
            r'Cipher\.getInstance\s*\(\s*[a-zA-Z_$][a-zA-Z0-9_$.\[\]"\'\-_]*\s*\)',
            r'createHash\s*\(\s*[a-zA-Z_$][a-zA-Z0-9_$.\[\]"\'\-_]*\s*\)',
            r'createCipheriv\s*\(\s*[a-zA-Z_$][a-zA-Z0-9_$.\[\]"\'\-_]*\s*,',
            r'Signature\.getInstance\s*\(\s*[a-zA-Z_$][a-zA-Z0-9_$.\[\]"\'\-_]*\s*\)',
            r'getattr\s*\(\s*hashlib\s*,\s*[a-zA-Z_$]',
        ]
        for pat in dynamic_patterns:
            if code and re.search(pat, code):
                return True
        return str(raw_alg).lower() in ("dynamic", "variable", "runtime", "runtime-configured")

    def _canonicalize_algorithm(self, alg: str) -> Optional[str]:
        if not alg:
            return None
        cleaned = alg.strip().upper()
        # Direct alias lookup
        if cleaned in ALIAS_MAP:
            return ALIAS_MAP[cleaned]
        # Composite signature algorithm strings (e.g. SHA256withRSA, SHA1withRSA, ECDSAwithSHA256)
        if "WITHRSA" in cleaned or "RSAWITH" in cleaned:
            return "RSA"
        if "WITHECDSA" in cleaned or "ECDSAWITH" in cleaned:
            return "ECDSA"
        if "WITHDSA" in cleaned or "DSAWITH" in cleaned:
            return "DSA"
        if cleaned.startswith("HMAC"):
            if "SHA512" in cleaned:
                return "HMAC-SHA512"
            if "SHA384" in cleaned:
                return "HMAC-SHA384"
            if "SHA1" in cleaned:
                return "HMAC-SHA1"
            return "HMAC-SHA256"
        if cleaned.startswith("RSA"):
            return "RSA"
        if cleaned.startswith("AES"):
            return "AES"
        if cleaned.startswith("ECDSA") or cleaned.startswith("SECP"):
            return "ECDSA"
        if cleaned.startswith("SHA256") or cleaned.startswith("SHA-256"):
            return "SHA-256"
        if cleaned.startswith("SHA512") or cleaned.startswith("SHA-512"):
            return "SHA-512"
        if cleaned.startswith("SHA384") or cleaned.startswith("SHA-384"):
            return "SHA-384"
        if cleaned.startswith("MD5"):
            return "MD5"
        if cleaned.startswith("SHA1") or cleaned.startswith("SHA-1"):
            return "SHA-1"
        if "CHACHA" in cleaned:
            return "ChaCha20"
        if "TRIPLEDES" in cleaned or "3DES" in cleaned:
            return "3DES"
        return None

    def _extract_embedded_params(self, raw_alg: str, res: Dict[str, Any]) -> None:
        u_alg = raw_alg.upper()
        alg_name = str(res.get("algorithm") or "").upper()
        # Key sizes
        if not res.get("key_size"):
            ks_m = re.search(r'[-_/\s](1024|2048|3072|4096|128|192|256|512)\b', u_alg)
            if ks_m:
                val = int(ks_m.group(1))
                if alg_name == "RSA" and val in (1024, 2048, 3072, 4096):
                    res["key_size"] = val
                elif alg_name == "AES" and val in (128, 192, 256):
                    res["key_size"] = val
                elif alg_name not in ("RSA", "AES"):
                    res["key_size"] = val

        # Modes
        if not res.get("mode"):
            for m in ("GCM", "CBC", "ECB", "CTR", "CCM", "CFB"):
                if m in u_alg:
                    res["mode"] = m
                    break

        # Curves
        if not res.get("curve"):
            for c in ("P-256", "P-384", "P-521", "SECP256R1", "SECP384R1", "SECP521R1", "CURVE25519", "ED25519"):
                if c in u_alg:
                    res["curve"] = c
                    break

    # ---------------------------------------------------------------------------
    # Internal Helpers: Cryptographic Purpose Resolution (10A, 10B, 10C)
    # ---------------------------------------------------------------------------
    def _enrich_purpose(self, res: Dict[str, Any]) -> None:
        code = str(res.get("code_snippet") or res.get("evidence") or "")
        purpose, confidence, evidence = self._resolve_purpose_with_evidence(res, code)
        res["purpose"] = purpose
        res["purpose_confidence"] = confidence
        res["purpose_evidence"] = evidence

    def _resolve_purpose_with_evidence(self, res: Dict[str, Any], code: str) -> Tuple[str, float, List[str]]:
        alg = str(res.get("algorithm") or "").upper()
        family = str(res.get("family") or "")
        art_type = str(res.get("artifact_type") or "").lower()
        code_u = code.upper()

        ev: List[str] = []

        # Rule 10B: RSA Handling — RSA is NOT automatically classified as KEM
        if alg == "RSA":
            if any(k in code_u for k in ("SIGNATURE.GETINSTANCE", "RSA.SIGN", "RSASSA", "PSS", "SIGN(")):
                ev.append("RSA signature API call detected in code")
                return "signing", 0.9, ev
            if any(k in code_u for k in ("VERIFY", "VERIFYSIGNATURE")):
                ev.append("RSA signature verification API call detected")
                return "signature_verification", 0.9, ev
            if any(k in code_u for k in ("CIPHER.GETINSTANCE", "ENCRYPT", "DECRYPT", "KEYEXCHANGE", "RSA/ECB", "RSA/OAEP")):
                ev.append("RSA encryption / key transport API call detected")
                return "key_establishment", 0.85, ev
            ev.append("RSA algorithm imported or declared without explicit operational API call context")
            return "unknown", 0.5, ev

        # ECDSA / Ed25519 / DSA
        if alg in ("ECDSA", "ED25519", "ED448", "DSA"):
            if "VERIFY" in code_u:
                ev.append(f"{alg} verification context detected")
                return "signature_verification", 0.9, ev
            ev.append(f"{alg} digital signature algorithm context")
            return "signing", 0.9, ev

        # ECDH / X25519 / DH
        if alg in ("ECDH", "X25519", "X448", "DH"):
            ev.append(f"{alg} key exchange algorithm context")
            return "key_establishment", 0.9, ev

        # Symmetric Ciphers
        if family == "Symmetric" or alg in ("AES", "DES", "3DES", "CHACHA20"):
            ev.append(f"{alg} symmetric encryption context")
            return "encryption", 0.9, ev

        # MAC
        if family == "MAC" or alg.startswith("HMAC") or art_type == "mac":
            ev.append(f"{alg} message authentication code context")
            return "mac", 0.95, ev

        # Hashes
        if family == "Hash" or alg in ("SHA-256", "SHA-384", "SHA-512", "SHA3-256", "SHA-1", "MD5"):
            ev.append(f"{alg} cryptographic hash function context")
            return "hashing", 0.95, ev

        # Protocols & Certs
        if art_type in ("certificate", "cert"):
            ev.append("X.509 Certificate public key signature verification context")
            return "signature_verification", 0.9, ev

        if art_type == "protocol" or family == "Protocol":
            ev.append("Secure transport protocol context")
            return "key_establishment", 0.85, ev

        ev.append("Unclear operational purpose from available code context")
        return "unknown", 0.4, ev

    def _resolve_purpose(self, res: Dict[str, Any], code: str) -> str:
        p, _, _ = self._resolve_purpose_with_evidence(res, code)
        return p

    # ---------------------------------------------------------------------------
    # Internal Helpers: AST/Tree-sitter/Semgrep Evidence Correlation & Merging
    # ---------------------------------------------------------------------------
    def merge_correlated_evidence(self, artifacts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Merges duplicate scanner signals for the exact same file & line operation.
        """
        groups: List[Tuple[str, int, str, List[Dict[str, Any]]]] = []

        for a in artifacts:
            fp = str(a.get("file_path") or a.get("location") or "").replace("\\", "/").lower()
            line = int(a.get("line_number") or 0)
            alg = str(a.get("algorithm") or "")
            
            # Check for existing adjacent line group in same file for same algorithm (or HMAC/SHA or ECDH/ECDSA correlation)
            matched_group = None
            for g_fp, g_line, g_alg, g_items in groups:
                same_alg = (g_alg == alg) or (g_alg in ("HMAC-SHA256", "SHA-256") and alg in ("HMAC-SHA256", "SHA-256")) or ({g_alg, alg} <= {"ECDH", "ECDSA", "ECC"}) or ({g_alg, alg} <= {"RSA", "RSA-2048"})
                if g_fp == fp and same_alg and abs(g_line - line) <= 5:
                    matched_group = g_items
                    break

            if matched_group is not None:
                matched_group.append(a)
            else:
                groups.append((fp, line, alg, [a]))

        merged: List[Dict[str, Any]] = []

        for g_fp, g_line, g_alg, group in groups:
            if len(group) == 1:
                primary = dict(group[0])
                if not primary.get("detection_sources"):
                    primary["detection_sources"] = [primary.get("detection_method", "static_analysis")]
                merged.append(primary)
            else:
                # Merge multiple detector signals (e.g. python_ast + treesitter + semgrep)
                # Prefer explicit ECDH or HMAC-SHA256 over generic ECDSA/SHA-256 if present on same line
                ecdh_items = [x for x in group if x.get("algorithm") == "ECDH"]
                hmac_items = [x for x in group if str(x.get("algorithm")).upper().startswith("HMAC") or x.get("artifact_type") == "mac"]
                purpose_items = [x for x in group if x.get("purpose") and x.get("purpose") != "unknown"]
                if ecdh_items:
                    primary = dict(ecdh_items[0])
                elif hmac_items:
                    primary = dict(hmac_items[0])
                elif purpose_items:
                    primary = dict(purpose_items[0])
                else:
                    primary = dict(max(group, key=lambda x: x.get("confidence", 0.5)))
                existing_sources = list(primary.get("detection_sources") or [])
                group_sources = [str(x.get("detection_method", "static_analysis")) for x in group]
                primary["detection_sources"] = list(set(existing_sources + group_sources))
                
                distinct_sources = set(group_sources)
                confs = [float(x.get("confidence", 0.5)) for x in group]
                base_conf = max(confs)
                if len(distinct_sources) > 1:
                    aggregated = base_conf
                    for c in sorted(confs, reverse=True)[1:]:
                        aggregated += (1.0 - aggregated) * 0.15 * c
                    primary["confidence"] = round(min(0.99, aggregated), 4)
                else:
                    primary["confidence"] = base_conf
                
                # Merge parameter fields from other items in group if primary is missing them
                cloud_items = [x for x in group if x.get("artifact_type") in ("cloud_kms_key", "cloud_service", "hardware_hsm", "key_reference") or x.get("provider")]
                if cloud_items and primary.get("artifact_type") not in ("cloud_kms_key", "cloud_service", "hardware_hsm"):
                    primary["artifact_type"] = cloud_items[0].get("artifact_type") or "cloud_kms_key"

                for field in ("provider", "service", "resource", "key_size", "mode", "curve", "family", "signature_hash", "variant", "certificate_details"):
                    if not primary.get(field):
                        for item in group:
                            if item.get(field):
                                primary[field] = item[field]
                                break

                # Combine evidence snippets
                snippets = [str(x.get("code_snippet") or x.get("evidence") or "") for x in group if x.get("code_snippet") or x.get("evidence")]
                if snippets:
                    primary["code_snippet"] = max(snippets, key=len)

                ev_list = []
                for x in group:
                    if isinstance(x.get("purpose_evidence"), list):
                        ev_list.extend(x["purpose_evidence"])
                if ev_list:
                    primary["purpose_evidence"] = list(set(ev_list))

                merged.append(primary)

        return merged

    # ---------------------------------------------------------------------------
    # Utilities
    # ---------------------------------------------------------------------------
    def _extract_oid(self, text: str) -> Optional[str]:
        m = re.search(r'\b(?:\d+\.){3,}\d+\b', text)
        return m.group(0) if m else None

    def _is_cert_file(self, file_path: str) -> bool:
        return file_path.lower().endswith((".crt", ".pem", ".cer", ".der", ".p12", ".pfx"))

    def _is_manifest_file(self, file_path: str) -> bool:
        fname = os.path.basename(file_path).lower()
        return fname in (
            "requirements.txt", "pyproject.toml", "package.json", "package-lock.json",
            "pom.xml", "build.gradle", "build.gradle.kts", "cmakelists.txt", "vcpkg.json",
            "dockerfile",
        ) or fname.startswith("dockerfile")

    def _infer_library_name(self, file_path: str, code: str) -> Optional[str]:
        if "pyproject" in file_path or "requirements" in file_path:
            m = re.search(r'(cryptography|pycryptodome|openssl|pynacl|bouncycastle)', code, re.IGNORECASE)
            if m:
                return m.group(1)
        if "package.json" in file_path:
            return "crypto"
        return None


# Global singleton helper
_resolver_instance = AlgorithmResolver()

def resolve_artifact(artifact: Dict[str, Any]) -> Dict[str, Any]:
    return _resolver_instance.resolve_artifact(artifact)

def resolve_artifacts(artifacts: List[Dict[str, Any]], merge_evidence: bool = True) -> List[Dict[str, Any]]:
    return _resolver_instance.resolve_artifacts(artifacts, merge_evidence=merge_evidence)
