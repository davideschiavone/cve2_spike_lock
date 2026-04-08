#!/bin/bash
# ============================================================================
# compile_cve2_py.sh  –  Build the cve2_py Python extension module
# ============================================================================
#
# Produces:  cve2_py.cpython-*.so   (importable as `import cve2_py`)
#
# All Verilator-generated libraries (libverilated.a, V*__ALL.a) and the
# testbench library (libcve2_tb.a) are already compiled with -fPIC because
# the makefile passes -CFLAGS -fPIC to Verilator's --build and includes
# -fPIC in CXXFLAGS.  This script therefore just compiles the thin pybind11
# binding and links everything together — no recompilation needed.
#
# Prerequisites:
#   make verilate cve2_lib    (in cve2/)
#   pip install pybind11
#
# Usage:
#   sh compile_cve2_py.sh           (called by `make cve2_py`)
#
# ============================================================================

set -e

echo "=========================================================================="
echo "CVE2 Python Module - Compilation"
echo "=========================================================================="
echo ""

# ── Paths ──────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/build_cve2"
TOP="${TOP_MODULE:-cve2_top}"
VERILATOR_ROOT="${VERILATOR_ROOT:-$(verilator --getenv VERILATOR_ROOT 2>/dev/null)}"
VROOT_INC="${VERILATOR_ROOT}/include"

echo "[*] Script dir     : ${SCRIPT_DIR}"
echo "[*] Build dir      : ${BUILD_DIR}"
echo "[*] Top module     : ${TOP}"
echo "[*] Verilator root : ${VERILATOR_ROOT}"
echo ""

# ── Sanity checks ──────────────────────────────────────────────────────────
if [ ! -f "${BUILD_DIR}/V${TOP}.h" ]; then
    echo "[ERROR] Verilated headers not found: ${BUILD_DIR}/V${TOP}.h"
    echo "        Please run:  make verilate   (in cve2/)"
    exit 1
fi

if [ ! -f "${BUILD_DIR}/libcve2_tb.a" ]; then
    echo "[ERROR] ${BUILD_DIR}/libcve2_tb.a not found."
    echo "        Please run:  make cve2_lib   (in cve2/)"
    exit 1
fi

# ── Python / pybind11 ──────────────────────────────────────────────────────
PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}' | cut -d. -f1,2)
PYBIND11_INCLUDES=$(python3 -m pybind11 --includes)
PYTHON_CONFIG_SUFFIX=$(python3-config --extension-suffix)

echo "[*] Python         : ${PYTHON_VERSION}"
echo "[*] pybind11       : ${PYBIND11_INCLUDES}"
echo "[*] Extension      : ${PYTHON_CONFIG_SUFFIX}"
echo ""

OUTPUT="${SCRIPT_DIR}/cve2_py${PYTHON_CONFIG_SUFFIX}"

echo "[*] Cleaning old module..."
rm -f "${SCRIPT_DIR}"/cve2_py.cpython-*.so
echo "    Done"
echo ""

echo "[*] Compiling cve2_pybind.cpp and linking → $(basename ${OUTPUT}) ..."
echo ""

g++ -shared -std=c++20 -O2 -Wall -fPIC \
    -DCVE2_WITH_PYBIND11 \
    -DTRACE \
    ${PYBIND11_INCLUDES} \
    -I"${SCRIPT_DIR}" \
    -I"${BUILD_DIR}" \
    -I"${VROOT_INC}" \
    -I"${VROOT_INC}/vltstd" \
    "${SCRIPT_DIR}/cve2_pybind.cpp" \
    "${BUILD_DIR}/libcve2_tb.a" \
    "${BUILD_DIR}/V${TOP}__ALL.a" \
    "${BUILD_DIR}/libverilated.a" \
    -lpthread -lm -ldl \
    -o "${OUTPUT}"

echo ""
echo "=========================================================================="
echo "[OK] Python module: ${OUTPUT}"
echo "=========================================================================="
echo ""
echo "Usage:"
echo "  python3 trace_cve2.py tests/build/test.hex"
echo ""
