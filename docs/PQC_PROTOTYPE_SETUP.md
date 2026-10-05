# Open Quantum Safe (liboqs) PQC Prototype Setup Guide

This guide describes how to configure the native **Open Quantum Safe (`liboqs`)** shared library and Python `oqs` bindings for ECDAT's Experimental Post-Quantum Cryptography (PQC) Prototype across **Windows**, **Linux**, and **macOS**.

---

## 1. Architectural Overview

ECDAT uses a unified, OS-independent architecture for PQC prototype execution:

```
[ ECDAT Prototype Service ]
          │
          ▼
   [ Python `oqs` Binding ]
          │
          ▼
   [ Native `liboqs` C Library ]
  ├── Windows:  oqs.dll / liboqs.dll
  ├── Linux:    liboqs.so
  └── macOS:    liboqs.dylib
```

- **In-Memory Cryptographic Execution**: All private keys, keypairs, signatures, and shared secrets remain exclusively in memory and are discarded immediately after prototype completion.
- **Scanned File Safety**: The prototype evaluates cryptographic performance without modifying scanned application source code, certificates, keys, or deployment configurations.
- **Authentic Status Reporting**:
  - `status: "success"` — Returned ONLY when live native `liboqs` code executes successfully.
  - `status: "unavailable"` — Returned when `liboqs` native shared libraries are missing in the environment.
  - `status: "needs_review"` — Returned for legacy or ambiguous findings requiring manual purpose resolution.

---

## 2. Platform Installation Guides

### A. Windows (10 / 11 64-bit AMD64)

#### Prerequisites
- **Git**: `git` installed on `PATH`
- **CMake**: `cmake` (version 3.18+)
- **Ninja Build Tool**: `ninja` (installed via `pip install ninja` or system PATH)
- **C Compiler**: MSVC Build Tools (`cl.exe`) or GCC 6.0+ (`mingw-w64`)

#### Step-by-Step Installation
1. Open PowerShell / Command Prompt in your development environment.
2. Clone and build `liboqs` shared library:
   ```cmd
   git clone --depth 1 --branch 0.16.0 https://github.com/open-quantum-safe/liboqs C:\Users\%USERNAME%\_oqs_src
   cd C:\Users\%USERNAME%\_oqs_src
   cmake -G Ninja -S . -B build -DBUILD_SHARED_LIBS=ON -DOQS_BUILD_ONLY_LIB=ON -DCMAKE_INSTALL_PREFIX=C:\Users\%USERNAME%\_oqs -DCMAKE_WINDOWS_EXPORT_ALL_SYMBOLS=TRUE
   cmake --build build --parallel 4
   cmake --build build --target install
   ```
3. Install Python `liboqs-python` binding into the FastAPI Python environment:
   ```cmd
   C:\Users\user\AppData\Local\Programs\Python\Python313\python.exe -m pip install liboqs-python
   ```
4. Verify loading:
   ```cmd
   python -c "import oqs; print('Enabled SIGs:', oqs.get_enabled_sig_mechanisms()[:3]); print('Enabled KEMs:', oqs.get_enabled_kem_mechanisms()[:3])"
   ```

---

### B. Linux (Ubuntu / Debian / RHEL / Fedora)

#### Prerequisites
```bash
# Ubuntu / Debian
sudo apt-get update && sudo apt-get install -y build-essential cmake ninja-build git libssl-dev python3-dev python3-pip

# RHEL / Fedora / CentOS
sudo dnf groupinstall -y "Development Tools"
sudo dnf install -y cmake ninja-build git openssl-devel python3-devel
```

#### Step-by-Step Installation
1. Clone and build `liboqs`:
   ```bash
   git clone --depth 1 --branch 0.16.0 https://github.com/open-quantum-safe/liboqs $HOME/_oqs_src
   cd $HOME/_oqs_src
   cmake -S . -B build -DBUILD_SHARED_LIBS=ON -DOQS_BUILD_ONLY_LIB=ON -DCMAKE_INSTALL_PREFIX=$HOME/_oqs
   cmake --build build --parallel 4
   cmake --build build --target install
   ```
2. Export shared library path:
   ```bash
   export LD_LIBRARY_PATH=$HOME/_oqs/lib:$HOME/_oqs/lib64:$LD_LIBRARY_PATH
   ```
3. Install Python binding:
   ```bash
   pip install liboqs-python
   ```
4. Verify loading:
   ```bash
   python3 -c "import oqs; print('ML-DSA-65 available:', 'ML-DSA-65' in oqs.get_enabled_sig_mechanisms()); print('ML-KEM-768 available:', 'ML-KEM-768' in oqs.get_enabled_kem_mechanisms())"
   ```

---

### C. macOS (Apple Silicon M1/M2/M3 & Intel x86_64)

#### Prerequisites
```bash
brew install cmake ninja git openssl@3 python@3.13
```

#### Step-by-Step Installation
1. Clone and build `liboqs`:
   ```bash
   git clone --depth 1 --branch 0.16.0 https://github.com/open-quantum-safe/liboqs $HOME/_oqs_src
   cd $HOME/_oqs_src
   cmake -S . -B build -DBUILD_SHARED_LIBS=ON -DOQS_BUILD_ONLY_LIB=ON -DCMAKE_INSTALL_PREFIX=$HOME/_oqs -DOPENSSL_ROOT_DIR=$(brew --prefix openssl@3)
   cmake --build build --parallel 4
   cmake --build build --target install
   ```
2. Export dynamic library path:
   ```bash
   export DYLD_LIBRARY_PATH=$HOME/_oqs/lib:$DYLD_LIBRARY_PATH
   ```
3. Install Python binding:
   ```bash
   pip3 install liboqs-python
   ```
4. Verify loading:
   ```bash
   python3 -c "import oqs; print('ML-DSA-65 available:', 'ML-DSA-65' in oqs.get_enabled_sig_mechanisms()); print('ML-KEM-768 available:', 'ML-KEM-768' in oqs.get_enabled_kem_mechanisms())"
   ```

---

## 3. Cryptographic Verification & Standalone Testing

### A. ML-DSA-65 Digital Signature Verification
```python
import oqs

# 1. Key Generation
with oqs.Signature("ML-DSA-65") as signer:
    public_key = signer.generate_keypair()
    
    # 2. Signing
    message = b"ECDAT PQC prototype verification message"
    signature = signer.sign(message)
    
    # 3. Verification (Original Message)
    valid_original = signer.verify(message, signature, public_key)
    assert valid_original is True, "Original signature verification failed"
    
    # 4. Negative Verification (Modified Message)
    modified_message = b"ECDAT PQC prototype verification message (TAMPERED)"
    valid_modified = signer.verify(modified_message, signature, public_key)
    assert valid_modified is False, "Modified message verification should have failed"
    
print("ML-DSA-65 Verification PASS: Original=True, Modified=False")
```

### B. ML-KEM-768 Key Encapsulation Verification
```python
import oqs

# 1. Key Generation
with oqs.KeyEncapsulation("ML-KEM-768") as client:
    public_key = client.generate_keypair()
    
    # 2. Encapsulation (Server)
    ciphertext, shared_secret_server = client.encap_secret(public_key)
    
    # 3. Decapsulation (Client)
    shared_secret_client = client.decap_secret(ciphertext)
    
    # 4. Shared Secret Match
    assert shared_secret_server == shared_secret_client, "Shared secret match failed"

print("ML-KEM-768 Encapsulation PASS: Shared secret match=True")
```

---

## 4. Environment Diagnostics API

The ECDAT backend provides runtime environment diagnostics at startup and via API inspection:

```python
from backend.app.services.pqc_prototype_service import get_pqc_environment_diagnostics

diag = get_pqc_environment_diagnostics()
print(diag)
```

**Diagnostic JSON Output Example**:
```json
{
  "operating_system": "Windows",
  "os_release": "11",
  "cpu_architecture": "64bit AMD64",
  "python_version": "3.13.7",
  "python_executable": "C:\\Users\\user\\AppData\\Local\\Programs\\Python\\Python313\\python.exe",
  "oqs_available": true,
  "library": "liboqs",
  "enabled_signature_mechanisms": ["ML-DSA-65", "ML-DSA-44", "ML-DSA-87", "Falcon-512"],
  "enabled_kem_mechanisms": ["ML-KEM-768", "ML-KEM-512", "ML-KEM-1024"],
  "ml_dsa_65_supported": true,
  "ml_kem_768_supported": true,
  "unavailability_reason": null
}
```

---

## 5. Troubleshooting Common Issues

1. **`RuntimeError: No oqs shared libraries found`**:
   - **Cause**: Native `liboqs` C shared library (`oqs.dll` on Windows, `liboqs.so` on Linux, `liboqs.dylib` on macOS) is not in `PATH`, `$HOME/_oqs/bin`, or `LD_LIBRARY_PATH`.
   - **Fix**: Set `OQS_INSTALL_PATH=$HOME/_oqs` environment variable or add directory containing shared library to your system search path.
2. **Architecture Mismatch (`[WinError 193]`)**:
   - **Cause**: Mixing 32-bit `oqs.dll` with 64-bit Python interpreter.
   - **Fix**: Ensure `cmake` compiles for 64-bit (`-A x64` or 64-bit GCC/Clang toolchain).
