# ============================================================================
# cve2_spike_lock — top-level orchestrator
# ============================================================================
#
# This Makefile is a thin wrapper that calls the sub-directory makefiles in
# the right order.  Each sub-makefile remains usable on its own.
#
#   cve2/           — Verilator build of CVE2 RTL + C++/Python testbench
#   spike_wrapper/  — C++ wrapper around Spike ISS (Python module + static lib)
#   cosim/          — lock-step co-simulator binary (links cve2 + spike_wrapper)
#   tests/          — RISC-V assembly test programs
#
# Environment:
#   Source env.sh first — it exports Spike paths, RVA23_COMPILER, and activates
#   the Python venv.  Type `make help` for a target list.
# ============================================================================

SHELL := /bin/bash

# --- Python venv -------------------------------------------------------------
VENV      := .venv
VENV_PY   := $(VENV)/bin/python
VENV_PIP  := $(VENV)/bin/pip
PYTHON    ?= python3

# --- Test program defaults (overridable on CLI) ------------------------------
MARCH            ?= -march=rv32imc -mabi=ilp32
PROGRAM          ?= tests/build/test
ISA              ?= rv32imc
HEX              ?= tests/build/test.hex
MAX_INSTRUCTIONS ?=
MAX_CYCLES       ?=
TRACE            ?= 1

# --- Flag forwarding ---------------------------------------------------------
_TRACE_ARG := TRACE=$(TRACE)

# ============================================================================
# Phony targets
# ============================================================================

.PHONY: help all venv tests \
        spike-wrapper spike-lib \
        cve2 cve2-py cve2-sim cve2-sim-trace \
        cosim \
        run-trace-spike run-trace-cve2 run-cosim run-cosim-verbose \
        view-vcd \
        clean distclean

# ============================================================================
# Help — default target
# ============================================================================

help:
	@echo "=========================================================================="
	@echo "cve2_spike_lock — top-level Makefile"
	@echo "=========================================================================="
	@echo ""
	@echo "Prerequisite:  source env.sh   (sets Spike, RVA23_COMPILER, venv)"
	@echo ""
	@echo "SETUP"
	@echo "  venv              Create .venv and install Python deps"
	@echo ""
	@echo "BUILD"
	@echo "  tests             Compile tests/test.S  (override MARCH=..., default: $(MARCH))"
	@echo "  spike-wrapper     Build spike_py Python module"
	@echo "  spike-lib         Build libspike_wrapper.a (for cosim)"
	@echo "  cve2              Clone + verilate CVE2 + build libcve2_tb.a"
	@echo "  cve2-py           Build cve2_py Python module"
	@echo "  cve2-sim          Build standalone CVE2 simulator binary"
	@echo "  cve2-sim-trace    Build CVE2 simulator binary with VCD trace"
	@echo "  cosim             Build lock-step co-sim binary (cosim_tb)"
	@echo "  all               venv + tests + spike-wrapper + spike-lib + cve2 + cve2-py + cosim"
	@echo ""
	@echo "RUN"
	@echo "  run-trace-spike   python3 trace_spike.py PROGRAM ISA [MAX_INSTRUCTIONS]"
	@echo "  run-trace-cve2    python3 trace_cve2.py HEX [MAX_CYCLES]"
	@echo "  run-cosim         ./cosim/cosim_tb PROGRAM ISA [MAX_INSTRUCTIONS]"
	@echo "  run-cosim-verbose same, with per-instruction trace"
	@echo "  view-vcd          Open cve2/cve2_wave.vcd in GTKWave"
	@echo ""
	@echo "CLEAN"
	@echo "  clean             Remove build artefacts (keeps cloned CVE2 RTL)"
	@echo "  distclean         Also remove cloned CVE2 RTL and .venv"
	@echo ""
	@echo "VARIABLES (override on command line)"
	@echo "  MARCH=...              (tests)          e.g. -march=rv32imc -mabi=ilp32"
	@echo "  TRACE=0|1              (cve2, cosim)    VCD support in libcve2_tb.a; default 1"
	@echo "  PROGRAM=path/to/elf    (run-*)          ELF without extension"
	@echo "  ISA=rv32imc            (run-*-spike, run-cosim)"
	@echo "  HEX=path/to/hex        (run-trace-cve2)"
	@echo "  MAX_INSTRUCTIONS=N     (cosim, spike tracer)"
	@echo "  MAX_CYCLES=N           (cve2 tracer)"
	@echo ""
	@echo "EXAMPLES"
	@echo "  source env.sh"
	@echo "  make venv"
	@echo "  make tests MARCH='-march=rv32imc -mabi=ilp32'"
	@echo "  make all"
	@echo "  make run-trace-spike PROGRAM=tests/build/test ISA=rv32imc"
	@echo "  make run-trace-cve2  HEX=tests/build/test.hex MAX_CYCLES=2000"
	@echo "  make run-cosim       PROGRAM=tests/build/test ISA=rv32imc"
	@echo "=========================================================================="

# ============================================================================
# Python venv
# ============================================================================

venv: $(VENV)/.stamp

$(VENV)/.stamp: requirements.txt
	@echo "[VENV] creating $(VENV) with $(PYTHON)"
	@test -d $(VENV) || $(PYTHON) -m venv $(VENV)
	$(VENV_PIP) install --upgrade pip
	$(VENV_PIP) install -r requirements.txt
	@touch $@
	@echo "[OK]   venv ready.  Re-source env.sh to activate it."

# ============================================================================
# Build targets — each delegates to its sub-makefile
# ============================================================================

tests:
	$(MAKE) -C tests test MARCH="$(MARCH)"

spike-wrapper:
	$(MAKE) -C spike_wrapper spike_wrapper

spike-lib:
	$(MAKE) -C spike_wrapper spike_wrapper_lib

cve2:
	$(MAKE) -C cve2 setup verilate cve2_lib $(_TRACE_ARG)

cve2-py: cve2
	$(MAKE) -C cve2 cve2_py $(_TRACE_ARG)

cve2-sim: cve2
	$(MAKE) -C cve2 cve2_sim $(_TRACE_ARG)

cve2-sim-trace: cve2
	$(MAKE) -C cve2 cve2_sim_trace

cosim: cve2 spike-lib
	$(MAKE) -C cosim cosim_tb

all: venv tests spike-wrapper spike-lib cve2 cve2-py cosim
	@echo "[OK] all targets built."

# ============================================================================
# Run targets
# ============================================================================

run-trace-spike: spike-wrapper
	cd $(CURDIR) && $(VENV_PY) trace_spike.py $(PROGRAM) $(ISA) $(MAX_INSTRUCTIONS)

run-trace-cve2: cve2-py
	cd $(CURDIR) && $(VENV_PY) trace_cve2.py $(HEX) $(MAX_CYCLES)

run-cosim: cosim
	$(MAKE) -C cosim cosim_run PROGRAM=../$(PROGRAM) ISA=$(ISA) MAX_INSTRUCTIONS=$(MAX_INSTRUCTIONS)

run-cosim-verbose: cosim
	$(MAKE) -C cosim cosim_run_verbose PROGRAM=../$(PROGRAM) ISA=$(ISA) MAX_INSTRUCTIONS=$(MAX_INSTRUCTIONS)

view-vcd:
	$(MAKE) -C cve2 view_trace

# ============================================================================
# Clean
# ============================================================================

clean:
	-$(MAKE) -C tests clean
	-$(MAKE) -C spike_wrapper clean
	-$(MAKE) -C cve2 clean
	-$(MAKE) -C cosim clean
	@rm -f pipeline*.html cve2_wave.vcd
	@echo "[OK] clean."

distclean: clean
	-$(MAKE) -C cve2 distclean
	@rm -rf $(VENV)
	@echo "[OK] distclean — cloned RTL and venv removed."
