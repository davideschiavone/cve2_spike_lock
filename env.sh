# ============================================================================
# env.sh — source this file to set up the build/run environment.
#
#   $ source env.sh
#
# What it does:
#   1. Exports Spike paths (PATH, LD_LIBRARY_PATH, CPATH, LIBRARY_PATH).
#   2. Exports RISCV_COMPILER (RISC-V RV32 GCC toolchain).
#   3. Detects Verilator and warns if the version is not 5.040.
#   4. Activates .venv/ if it exists.
#   5. Prints a summary of detected tools.
#
# Customize paths before sourcing (all optional):
#   $ SPIKE_PREFIX=/opt/spike RISCV_COMPILER=/opt/riscv32 source env.sh
#   $ VERILATOR_PREFIX=/opt/verilator source env.sh  # if not on system PATH
#
# Everything in this file is idempotent — safe to re-source.
# ============================================================================

# --- Resolve the repo root ---------------------------------------------------
# Works whether the file is sourced in bash or zsh.
if [ -n "${BASH_SOURCE[0]:-}" ]; then
    _ENV_SH_PATH="${BASH_SOURCE[0]}"
elif [ -n "${ZSH_VERSION:-}" ]; then
    _ENV_SH_PATH="${(%):-%x}"
else
    _ENV_SH_PATH="$0"
fi
REPO_ROOT="$(cd "$(dirname "$_ENV_SH_PATH")" && pwd)"
export REPO_ROOT

# --- Tool paths ---------------------------------------------------------------
# Override any of these before sourcing to use non-default install paths.
: "${SPIKE_PREFIX:=$HOME/tools/spike}"
: "${RISCV_COMPILER:=$HOME/tools/riscv32-embecosm}"
: "${VERILATOR_PREFIX:=}"          # optional — leave empty if verilator is on system PATH
export SPIKE_PREFIX RISCV_COMPILER VERILATOR_PREFIX

# --- Idempotent PATH-like prepend -------------------------------------------
_prepend_path () {
    # $1 = var name, $2 = dir
    local var="$1" dir="$2"
    local cur
    eval "cur=\${$var:-}"
    case ":$cur:" in
        *":$dir:"*) ;;
        *) eval "export $var=\"$dir\${$var:+:\$$var}\"" ;;
    esac
}

# --- Spike -------------------------------------------------------------------
# Always prepend — binary check happens later; MISS only if truly absent.
_prepend_path PATH            "$SPIKE_PREFIX/bin"
_prepend_path LD_LIBRARY_PATH "$SPIKE_PREFIX/lib"
_prepend_path CPATH           "$SPIKE_PREFIX/include"
_prepend_path LIBRARY_PATH    "$SPIKE_PREFIX/lib"

# --- Verilator (optional prefix) ---------------------------------------------
if [ -n "$VERILATOR_PREFIX" ]; then
    _prepend_path PATH "$VERILATOR_PREFIX/bin"
fi

# --- RISC-V toolchain --------------------------------------------------------
_prepend_path PATH "$RISCV_COMPILER/bin"

# --- Python virtualenv -------------------------------------------------------
if [ -f "$REPO_ROOT/.venv/bin/activate" ]; then
    # shellcheck disable=SC1091
    . "$REPO_ROOT/.venv/bin/activate"
fi

# ============================================================================
# Sanity checks — warn, never abort.
# ============================================================================

_warn ()   { printf '  \033[33m[WARN]\033[0m  %s\n' "$*"; }
_ok ()     { printf '  \033[32m[ OK ]\033[0m  %s\n' "$*"; }
_miss ()   { printf '  \033[31m[MISS]\033[0m  %s\n' "$*"; }

echo "cve2_spike_lock environment"
echo "  REPO_ROOT        = $REPO_ROOT"
echo "  SPIKE_PREFIX     = $SPIKE_PREFIX"
echo "  RISCV_COMPILER   = $RISCV_COMPILER"
echo "  VERILATOR_PREFIX = ${VERILATOR_PREFIX:-(system PATH)}"
echo ""
echo "Tool check:"

# g++
if command -v g++ >/dev/null 2>&1; then
    _GPP_VER=$(g++ -dumpfullversion 2>/dev/null || g++ -dumpversion)
    _GPP_MAJOR=${_GPP_VER%%.*}
    if [ "${_GPP_MAJOR:-0}" -ge 10 ]; then
        _ok  "g++ $_GPP_VER (C++20 capable)"
    else
        _warn "g++ $_GPP_VER — C++20 needs g++ >= 10"
    fi
else
    _miss "g++ not found"
fi

# Spike
if command -v spike >/dev/null 2>&1; then
    _ok "spike  ($(command -v spike))"
else
    _miss "spike not found (expected in $SPIKE_PREFIX/bin)"
fi

# Verilator
if command -v verilator >/dev/null 2>&1; then
    _VL_VER=$(verilator --version 2>/dev/null | head -1 | awk '{print $2}')
    case "$_VL_VER" in
        5.040|5.040*) _ok   "verilator $_VL_VER" ;;
        *)            _warn "verilator $_VL_VER — repo pinned to 5.040" ;;
    esac
else
    _miss "verilator not found"
fi

# RISC-V GCC
_RV_GCC=$(ls "$RISCV_COMPILER"/bin/*-elf-gcc 2>/dev/null | head -1)
if [ -n "$_RV_GCC" ]; then
    _ok "risc-v gcc  ($_RV_GCC)"
else
    _miss "no *-elf-gcc in $RISCV_COMPILER/bin (set RISCV_COMPILER or install toolchain)"
fi

# Python
if command -v python3 >/dev/null 2>&1; then
    _PY_VER=$(python3 --version 2>&1 | awk '{print $2}')
    if [ -n "${VIRTUAL_ENV:-}" ]; then
        _ok "python $_PY_VER  (venv: $VIRTUAL_ENV)"
    else
        _warn "python $_PY_VER — no venv active (run: make venv && source env.sh)"
    fi
else
    _miss "python3 not found"
fi

# pybind11 (only if a venv is active — otherwise we don't care yet)
if [ -n "${VIRTUAL_ENV:-}" ]; then
    if python3 -c 'import pybind11' 2>/dev/null; then
        _ok "pybind11 ($(python3 -c 'import pybind11; print(pybind11.__version__)'))"
    else
        _warn "pybind11 not installed in venv (run: make venv)"
    fi
fi

echo ""
echo "Ready. Try: make help"

unset _ENV_SH_PATH _GPP_VER _GPP_MAJOR _VL_VER _RV_GCC _PY_VER
unset -f _prepend_path _warn _ok _miss
# NOTE: SPIKE_PREFIX, RISCV_COMPILER, VERILATOR_PREFIX stay exported for sub-processes.
