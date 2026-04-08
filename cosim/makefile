# ============================================================================
# cosim/makefile
# ============================================================================
#
# Builds the lock-step co-simulation binary (cosim_tb / cosim_tb_trace).
#
# Directory layout assumed:
#
#   <root>/
#     cve2/
#       build_cve2/          ← Verilated static libraries
#       cve2_tb.h
#       cve2_tb.cpp
#     spike_wrapper/
#       spike_wrapper.h
#       spike_wrapper.cpp
#     cosim/
#       cosim.h
#       cosim.cpp
#       cosim_main.cpp       ← this makefile lives here
#
# Prerequisites:
#   1. Run `make verilate` (or `make build_lib`) in ../cve2/   first
#   2. Spike installed at ~/tools/spike  (override with SPIKE_INCLUDE / SPIKE_LIB)
# ============================================================================

# --- Sibling directories ------------------------------------------------------
CVE2_DIR          := ../cve2
SPIKE_WRAPPER_DIR := ../spike_wrapper

# --- CVE2 build artefacts -----------------------------------------------------
CVE2_BUILD_DIR := $(CVE2_DIR)/build_cve2
TOP_MODULE     := cve2_top

CVE2_LIBS := \
    $(CVE2_BUILD_DIR)/libV$(TOP_MODULE).a \
    $(CVE2_BUILD_DIR)/libverilated.a \
    $(CVE2_BUILD_DIR)/V$(TOP_MODULE)__ALL.a

# --- Verilator runtime headers (needed for cve2_tb.h) -------------------------
VERILATOR_ROOT ?= $(shell verilator --getenv VERILATOR_ROOT 2>/dev/null)
VROOT_INC       = $(VERILATOR_ROOT)/include

# --- Spike installation --------------------------------------------------------
SPIKE_INCLUDE ?= /home/$(USER)/tools/spike/include
SPIKE_LIB     ?= /home/$(USER)/tools/spike/lib

# --- Compiler ------------------------------------------------------------------
CXX      ?= g++
CXXFLAGS  = -std=c++20 -O2 -Wall \
            -I$(CVE2_BUILD_DIR) \
            -I$(CVE2_DIR) \
            -I$(SPIKE_WRAPPER_DIR) \
            -I$(VROOT_INC) \
            -I$(VROOT_INC)/vltstd \
            -I$(SPIKE_INCLUDE) \
            -DCOSIM_HAS_READ_MEM

LDFLAGS = \
    -L$(SPIKE_LIB) \
    -Wl,-rpath,$(SPIKE_LIB) \
    -lriscv -lfesvr \
    -lpthread -lm -ldl

TRACE_SRC := $(VROOT_INC)/verilated_vcd_c.cpp

# --- Source files --------------------------------------------------------------
#   cosim.cpp            – CoSim engine (no main)
#   cosim_main.cpp       – main()
#   spike_wrapper.cpp    – SpikeBridge implementation (no main)
#   cve2_tb.cpp          – Cve2Tb implementation (no main)

COSIM_SRCS := \
    cosim.cpp \
    cosim_main.cpp \
    $(SPIKE_WRAPPER_DIR)/spike_wrapper.cpp \
    $(CVE2_DIR)/cve2_tb.cpp

COSIM_HDRS := \
    cosim.h \
    $(CVE2_DIR)/cve2_tb.h \
    $(SPIKE_WRAPPER_DIR)/spike_wrapper.h

# ============================================================================
# Phony targets
# ============================================================================

.PHONY: all clean cosim_run cosim_run_verbose help

all: cosim_tb

help:
	@echo "=========================================================================="
	@echo "Spike × CVE2 Lock-Step Co-Simulation"
	@echo "=========================================================================="
	@echo ""
	@echo "TARGETS:"
	@echo "  cosim_tb        - Build co-simulation binary (no waveform)"
	@echo "  cosim_tb_trace  - Build co-simulation binary (VCD waveform)"
	@echo "  cosim_run       - Build and run  (set PROGRAM=, ISA=)"
	@echo "  cosim_run_verbose - Build and run with verbose trace"
	@echo "  clean           - Remove build artefacts"
	@echo ""
	@echo "EXAMPLES:"
	@echo "  make cosim_tb"
	@echo "  make cosim_run PROGRAM=../tests/build/test ISA=rv32imc"
	@echo "  make cosim_run_verbose PROGRAM=../tests/build/test ISA=rv32imc"
	@echo "=========================================================================="

# ============================================================================
# cosim_tb  –  no waveform
# ============================================================================

cosim_tb: $(COSIM_SRCS) $(COSIM_HDRS) $(CVE2_LIBS)
	@echo "[BUILD] cosim_tb  (lock-step co-simulation, no trace)"
	$(CXX) $(CXXFLAGS) \
	    $(COSIM_SRCS) \
	    -o cosim_tb \
	    $(CVE2_LIBS) $(LDFLAGS)
	@echo "[OK]    cosim_tb"

# ============================================================================
# cosim_tb_trace  –  VCD waveform enabled
# ============================================================================

cosim_tb_trace: $(COSIM_SRCS) $(COSIM_HDRS) $(CVE2_LIBS)
	@echo "[BUILD] cosim_tb_trace  (lock-step co-simulation + VCD trace)"
	$(CXX) $(CXXFLAGS) -g -DTRACE \
	    $(COSIM_SRCS) \
	    $(TRACE_SRC) \
	    -o cosim_tb_trace \
	    $(CVE2_LIBS) $(LDFLAGS)
	@echo "[OK]    cosim_tb_trace"
	@echo "        Run it, then open cve2_wave.vcd in GTKWave"

# ============================================================================
# Convenience run targets
# ============================================================================

cosim_run: cosim_tb
	./cosim_tb $(PROGRAM) $(ISA)

cosim_run_verbose: cosim_tb
	./cosim_tb $(PROGRAM) $(ISA) --verbose

# ============================================================================
# Clean
# ============================================================================

clean:
	rm -f cosim_tb cosim_tb_trace
	@echo "[OK] cosim artefacts cleaned."
