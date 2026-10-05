"""
PQC Recommendation Engine Service
===================================
Matches discovered cryptographic finding to NIST-standardized Post-Quantum Cryptography (PQC)
replacements, hybrid algorithms, fallbacks, effort estimates, and code-level remediation diffs.
Uses operational purpose (signing vs key establishment vs unknown) to drive PQC recommendations.
"""

from typing import Any, Dict

class PQCRecommendationService:
    """Generates NIST PQC recommendations & remediation templates according to cryptographic purpose."""

    def generate_recommendation(self, artifact: Dict[str, Any], migration_info: Dict[str, Any]) -> Dict[str, Any]:
        alg = str(artifact.get("algorithm") or "").upper()
        artifact_type = str(artifact.get("artifact_type") or "").lower()
        purpose = str(artifact.get("purpose") or "").lower()
        family = str(artifact.get("family") or "").lower()
        resolution_status = str(artifact.get("resolution_status") or "").lower()

        is_shor = bool(artifact.get("shor_vulnerable")) or any(k in alg for k in ["RSA", "ECC", "ECDSA", "ECDH", "DH", "ED25519", "X25519", "DSA"])
        is_mac = (family == "mac") or (purpose in ("mac", "authentication")) or any(k in alg for k in ["HMAC", "POLY1305", "CMAC"])
        is_sym = not is_mac and ((family == "symmetric") or any(k in alg for k in ["AES", "CHACHA", "DES", "3DES", "RC4"]) or (purpose in ("encryption",) and not is_shor))
        is_hash = not is_mac and ((family == "hash") or (purpose in ("hashing", "hash")) or any(k in alg for k in ["MD5", "SHA1", "SHA-1", "SHA256", "SHA-256", "SHA384", "SHA-384", "SHA512", "SHA-512", "SHA3", "BLAKE"]))
        is_library_only = (resolution_status == "library-only") or (artifact_type == "library" and not is_shor and not is_sym and not is_hash and not is_mac) or ("library-only" in alg.lower())
        is_safe = (artifact.get("risk_band") == "safe") and not is_shor and not is_library_only

        # 0. Library-only findings (Dependency / Docker / Import-Signal)
        if is_library_only:
            primary = "Usage Not Detected"
            hybrid = "Not applicable — Usage Not Detected"
            fallback = "—"
            reason = "The scanner detected a cryptographic library or dependency, but no specific cryptographic algorithm usage was resolved."
            library_notes = "Inspect application source code to confirm whether cryptographic operations are invoked."
            after_code = f"# Dependency {alg} detected. Usage not confirmed."

        # 1. Safe / Grover-resistant non-asymmetric assets
        elif is_safe:
            primary = "No change needed"
            hybrid = "Not applicable — Quantum Safe"
            fallback = "—"
            reason = "This cryptographic asset is safe under classical and post-quantum threat models (Grover-resistant). No PQC migration required."
            library_notes = "No action required."
            after_code = f"# {alg} is quantum-safe or non-operational library. No change needed."

        # 2. Symmetric Ciphers
        elif is_sym:
            if "256" in alg:
                primary = "AES-256-GCM (Quantum Safe)"
                hybrid = "Not applicable — Symmetric cipher"
                fallback = "ChaCha20-Poly1305 (256-bit)"
                reason = "AES-256 provides 128-bit quantum security against Grover's algorithm search."
                library_notes = "Ensure GCM or AuthGCM mode is used rather than ECB/CBC."
            else:
                primary = "AES-256-GCM"
                hybrid = "Not applicable — Symmetric cipher"
                fallback = "ChaCha20-Poly1305"
                reason = "Upgrade key size from 128-bit to 256-bit to maintain 128-bit post-quantum security margin against Grover's speedup."
                library_notes = "Update symmetric key generation and storage parameters to 256 bits."
            
            after_code = (
                "# Quantum-Safe Symmetric Cipher Remediation (AES-256-GCM)\n"
                "from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n\n"
                "key = AESGCM.generate_key(bit_length=256)\n"
                "aesgcm = AESGCM(key)\n"
                "ciphertext = aesgcm.encrypt(nonce, data, associated_data=None)\n"
            )

        # 2.5 MAC (Message Authentication Code)
        elif is_mac:
            primary = "HMAC-SHA256 (Quantum Safe)"
            hybrid = "Not applicable — Message Authentication Code"
            fallback = "HMAC-SHA384 / HMAC-SHA512"
            reason = "HMAC-SHA256 relies on symmetric keying (256-bit secret key) and provides 128-bit post-quantum security against Grover's algorithm search."
            library_notes = "Ensure secret key size is at least 256 bits for post-quantum security."
            after_code = (
                "# Quantum-Safe MAC Remediation (HMAC-SHA256 / HMAC-SHA384)\n"
                "import hmac\n"
                "import hashlib\n\n"
                "secret_key = b\"\\x00\" * 32  # 256-bit secret key\n"
                "mac = hmac.new(secret_key, data, hashlib.sha256).hexdigest()\n"
            )

        # 3. Hash Functions
        elif is_hash:
            if any(k in alg for k in ["MD5", "SHA1", "SHA-1"]):
                primary = "SHA-256 / SHA-384"
                hybrid = "Not applicable — Hash function"
                fallback = "SHA3-256"
                reason = "MD5 and SHA-1 are classically broken (practical collision attacks exist). Upgrade immediately to SHA-256, SHA-384, or SHA-3 family for quantum collision resistance."
                library_notes = "Replace hashlib.md5()/sha1() with hashlib.sha256() or hashlib.sha384()."
            else:
                primary = "SHA-384 / SHA-512"
                hybrid = "Not applicable — Hash function"
                fallback = "SHA3-384"
                reason = "SHA-384 and SHA-512 provide robust post-quantum collision resistance against Grover's algorithm search."
                library_notes = "Standard hash function parameter update."

            after_code = (
                "# Post-Quantum Secure Hash Function Remediation (SHA-256 / SHA-384)\n"
                "import hashlib\n\n"
                "digest = hashlib.sha256(data).digest()\n"
            )

        # 4. Asymmetric / Shor-Vulnerable — Purpose-Driven Decision Logic
        elif purpose in ("signing", "signature_verification"):
            primary = "ML-DSA-65 (NIST FIPS 204)"
            hybrid = "ECDSA-P256 + ML-DSA-65"
            fallback = "SLH-DSA-SHA2-128f (NIST FIPS 205)"
            reason = "ML-DSA-65 is the primary NIST FIPS 204 lattice-based digital signature standard. SLH-DSA provides a conservative hash-based stateless fallback."
            library_notes = "Use OpenQuantumSafe (liboqs), Bouncy Castle 1.77+, or Python `oqspy` for ML-DSA-65."
            after_code = (
                "# PQC Migration Remediation (NIST FIPS 204 ML-DSA-65)\n"
                "from oqs import Signature\n\n"
                "with Signature('ML-DSA-65') as signer:\n"
                "    public_key = signer.generate_keypair()\n"
                "    signature = signer.sign(message)\n"
            )

        elif purpose in ("key_establishment", "key_exchange"):
            primary = "ML-KEM-768 (NIST FIPS 203)"
            hybrid = "X25519 + ML-KEM-768 (Hybrid KEM)"
            fallback = "ML-KEM-1024 (NIST FIPS 203 Category 5)"
            reason = "ML-KEM-768 is the primary NIST FIPS 203 Module-Lattice Key Encapsulation standard, protecting key exchange against Shor's algorithm and Harvest Now, Decrypt Later (HNDL)."
            library_notes = "Implement hybrid X25519+ML-KEM-768 for TLS 1.3 key exchange via OpenSSL 3.4+ or liboqs."
            after_code = (
                "# PQC Migration Remediation (NIST FIPS 203 ML-KEM-768)\n"
                "from oqs import KeyEncapsulation\n\n"
                "with KeyEncapsulation('ML-KEM-768') as kem:\n"
                "    public_key = kem.generate_keypair()\n"
                "    ciphertext, shared_secret_server = kem.encap_secret(public_key)\n"
            )

        else:
            # Unresolved, unknown, or ambiguous asymmetric algorithm purpose
            primary = "Manual Cryptographic Review Required"
            hybrid = "Manual Review Required (Purpose Ambiguous)"
            fallback = "ML-DSA-65 / ML-KEM-768 (Pending Purpose Review)"
            reason = f"Generic {alg or 'asymmetric'} algorithm detected without sufficient operational purpose evidence (signing vs key establishment). Manual review required before selecting ML-DSA-65 or ML-KEM-768."
            library_notes = "Inspect application call sites to determine whether key establishment (ML-KEM-768) or digital signing (ML-DSA-65) is intended."
            after_code = (
                f"# Manual Cryptographic Review Required for {alg or 'Asymmetric Asset'}\n"
                "# Purpose evidence insufficient to distinguish digital signature (ML-DSA-65) vs key encapsulation (ML-KEM-768).\n"
                "# Inspect operational call sites and update application code accordingly."
            )

        # Code Remediation Diffs Generation
        code_snippet = artifact.get("code_snippet") or ""
        file_path = str(artifact.get("file_path") or "")
        before_code = code_snippet if code_snippet else f"# Existing {alg} cryptographic usage in {file_path}"

        if not ("py" in file_path or file_path == "") and primary != "No change needed":
            if primary == "Manual Cryptographic Review Required":
                after_code = f"// PQC Migration Manual Review Required for {alg}\n// Operational purpose unresolved. Inspect call site."
            else:
                after_code = f"// Replace {alg} with {primary}\n// Refer to NIST FIPS 203/204 migration guidelines."

        return {
            "primary": primary,
            "hybrid": hybrid,
            "fallback": fallback,
            "reason": reason,
            "library_notes": library_notes,
            "confidence": 0.90 if primary != "Manual Cryptographic Review Required" else 0.50,
            "remediation_diff": {
                "before": before_code,
                "after": after_code,
                "effort_hours": migration_info.get("migration_effort_hours", 16.0),
                "breaking_change_risk": migration_info.get("breaking_change_risk", "medium"),
            }
        }
