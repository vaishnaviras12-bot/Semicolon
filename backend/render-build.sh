#!/usr/bin/env bash
# ==============================================================================
# ECDAT PQC CBOM Engine — Render Deployment Build Script
# ==============================================================================
# Compatible with Render Root Directory set to 'backend' OR repository root.
# Builds native liboqs (NIST FIPS 203/204) and installs liboqs-python bindings.
# ==============================================================================
set -euo pipefail

CURRENT_DIR="$(pwd)"

# 1. Locate requirements.txt dynamically
if [ -f "requirements.txt" ]; then
    SERVICE_DIR="${CURRENT_DIR}"
    REQ_FILE="requirements.txt"
elif [ -f "backend/requirements.txt" ]; then
    SERVICE_DIR="${CURRENT_DIR}/backend"
    REQ_FILE="backend/requirements.txt"
else
    echo "ERROR: requirements.txt not found in ${CURRENT_DIR} or ${CURRENT_DIR}/backend!"
    exit 1
fi

OQS_VERSION="0.16.0"
OQS_INSTALL_DIR="${SERVICE_DIR}/.oqs"

echo "=============================================================================="
echo "--> [1/4] Installing Python dependencies from ${REQ_FILE}..."
echo "=============================================================================="
python -m pip install --upgrade pip setuptools wheel
python -m pip install -r "${REQ_FILE}"

echo "=============================================================================="
echo "--> [2/4] Setting up native Open Quantum Safe (liboqs ${OQS_VERSION})..."
echo "=============================================================================="
# Check if liboqs is already built in the persistent project directory
if [ -f "${OQS_INSTALL_DIR}/lib/liboqs.so" ] || [ -f "${OQS_INSTALL_DIR}/lib64/liboqs.so" ]; then
    echo "Found existing cached liboqs in ${OQS_INSTALL_DIR}."
else
    echo "Building liboqs ${OQS_VERSION} from source into ${OQS_INSTALL_DIR}..."
    BUILD_DIR="$(mktemp -d)"
    git clone --depth 1 --branch "${OQS_VERSION}" https://github.com/open-quantum-safe/liboqs.git "${BUILD_DIR}/liboqs"

    cmake -S "${BUILD_DIR}/liboqs" -B "${BUILD_DIR}/liboqs/build" \
        -DBUILD_SHARED_LIBS=ON \
        -DOQS_BUILD_ONLY_LIB=ON \
        -DCMAKE_INSTALL_PREFIX="${OQS_INSTALL_DIR}"

    cmake --build "${BUILD_DIR}/liboqs/build" --parallel "$(nproc 2>/dev/null || echo 4)"
    cmake --build "${BUILD_DIR}/liboqs/build" --target install

    rm -rf "${BUILD_DIR}"
    echo "Native liboqs successfully compiled and installed."
fi

# Ensure both lib and lib64 directories resolve
if [ -d "${OQS_INSTALL_DIR}/lib64" ] && [ ! -d "${OQS_INSTALL_DIR}/lib" ]; then
    ln -s lib64 "${OQS_INSTALL_DIR}/lib"
elif [ -d "${OQS_INSTALL_DIR}/lib" ] && [ ! -d "${OQS_INSTALL_DIR}/lib64" ]; then
    ln -s lib "${OQS_INSTALL_DIR}/lib64"
fi

echo "=============================================================================="
echo "--> [3/4] Ensuring liboqs-python bindings are installed..."
echo "=============================================================================="
python -m pip install "liboqs-python==0.16.0.1"

echo "=============================================================================="
echo "--> [4/4] Validating PQC environment and NIST algorithm availability..."
echo "=============================================================================="
export OQS_INSTALL_PATH="${OQS_INSTALL_DIR}"
export LD_LIBRARY_PATH="${OQS_INSTALL_DIR}/lib:${OQS_INSTALL_DIR}/lib64:${LD_LIBRARY_PATH:-}"

python -c "
import oqs
print('SUCCESS: liboqs native version:', oqs.oqs_version())
sigs = oqs.get_enabled_sig_mechanisms()
kems = oqs.get_enabled_kem_mechanisms()
print('Available signature algorithms:', len(sigs), 'sample:', sigs[:3])
print('Available KEM algorithms:', len(kems), 'sample:', kems[:3])
assert any(m in sigs for m in ('ML-DSA-65', 'Dilithium3')), 'ML-DSA-65 not found'
assert any(m in kems for m in ('ML-KEM-768', 'Kyber768')), 'ML-KEM-768 not found'
print('NIST FIPS 203 (ML-KEM-768) and FIPS 204 (ML-DSA-65) verified!')
"

echo "=============================================================================="
echo "Build completed successfully! Native liboqs is ready for production."
echo "=============================================================================="
