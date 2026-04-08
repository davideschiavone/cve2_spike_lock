# ============================================================================
# cve2/makefile
# ============================================================================

# --- Repository / branch -------------------------------------------------------
CVE2_REPO   := git@github.com:openhwgroup/cve2.git
CVE2_BRANCH := e35390a7754f4e9acbce22840835a7a0f045ddc7

# --- Verilator -----------------------------------------------------------------
VERILATOR_ROOT ?= $(shell verilator --getenv VERILATOR_ROOT 2>/dev/null)
VROOT_INC       = $(VERILATOR_ROOT)/include

# --- Directories ---------------------------------------------------------------
EXT_DIR   := external
CVE2_DIR  := $(EXT_DIR)/cv32e20
BUILD_DIR := build_cve2
VC_FILE   := cve2.vc

# --- Verilator flags -----------------------------------------------------------
VERILATOR  := verilator
TOP_MODULE := cve2_top

# -fPIC is essentially free on x86-64 (no register pressure unlike 32-bit).
# Building everything with -fPIC from the start means the same .a libraries
# can be linked into both regular executables (cve2_sim, cosim_tb) and the
# Python shared object (cve2_py.so) without recompiling anything twice.
#
# VM_USER_CFLAGS propagates -fPIC into the Verilator-generated model build
# (Verilator's --build invokes its own make internally and honours this var).
V_FLAGS := -Wall -cc --trace --trace-structs --trace-underscore \
           --trace-max-array 1024 \
           -CFLAGS -fPIC

TRACE_SRC  := $(VROOT_INC)/verilated_vcd_c.cpp

# --- Verilated library outputs -------------------------------------------------
VERILATED_LIBS := \
    $(BUILD_DIR)/V$(TOP_MODULE)__ALL.a \
    $(BUILD_DIR)/libverilated.a

# --- C++ compiler --------------------------------------------------------------
CXX      ?= g++
AR       ?= ar

# -fPIC included here so cve2_tb.o and every other object we compile
# can be linked into either an executable or a .so without issue.
CXXFLAGS  = -std=c++20 -O2 -Wall -fPIC \
            -I$(BUILD_DIR) \
            -I./ \
            -I$(VROOT_INC) \
            -I$(VROOT_INC)/vltstd \
            -I$(VROOT_INC)/gtkwave

# --- Collect all RTL sources so that verilate reruns when they change ----------
RTL_SRCS := $(wildcard $(CVE2_DIR)/rtl/*.sv) \
            $(wildcard $(CVE2_DIR)/vendor/lowrisc_ip/ip/prim/rtl/*.sv)

# ============================================================================
# Phony targets
# ============================================================================

.PHONY: all clean setup verilate cve2_lib cve2_py help

all: verilate cve2_lib

# --- 1. Clone CVE2 if needed --------------------------------------------------
setup:
	@mkdir -p $(EXT_DIR)
	@if [ ! -d "$(CVE2_DIR)" ]; then \
		echo "--- Cloning CVE2 into $(CVE2_DIR) ---"; \
		git clone $(CVE2_REPO) $(CVE2_DIR); \
		git -C $(CVE2_DIR) checkout $(CVE2_BRANCH); \
		echo "--- CVE2 setup complete ---"; \
	else \
		echo "--- CVE2 already exists ---"; \
	fi

# --- 2. Verilate ---------------------------------------------------------------
# -CFLAGS -fPIC inside V_FLAGS passes -fPIC to every source Verilator
# compiles during --build (generated model + verilated runtime).
# The stamp file tracks freshness; any RTL change forces re-verilaton.

$(BUILD_DIR)/.verilate_stamp: $(VC_FILE) $(RTL_SRCS) | setup
	@echo "--- Verilating $(TOP_MODULE) ---"
	@mkdir -p $(BUILD_DIR)
	$(VERILATOR) $(V_FLAGS) \
		--Mdir $(BUILD_DIR) \
		-f $(VC_FILE) \
		--top-module $(TOP_MODULE) \
		--build
	@touch $@
	@echo "--- Verilation complete ---"

verilate: $(BUILD_DIR)/.verilate_stamp

# --- 3. libcve2_tb.a -----------------------------------------------------------
# CXXFLAGS already includes -fPIC, so this library is safe to link into
# both executables and shared objects.

$(BUILD_DIR)/libcve2_tb.a: cve2_tb.cpp cve2_tb.h $(BUILD_DIR)/.verilate_stamp
	@echo "[AR]  libcve2_tb.a"
	$(CXX) $(CXXFLAGS) -c -DTRACE cve2_tb.cpp -o $(BUILD_DIR)/cve2_tb.o
	$(AR) rcs $@ $(BUILD_DIR)/cve2_tb.o
	@echo "[OK]  $(BUILD_DIR)/libcve2_tb.a"

cve2_lib: $(BUILD_DIR)/libcve2_tb.a

# --- 4. cve2_py  –  Python extension module -----------------------------------
# All libraries are already PIC-compiled, so this is a straightforward link.

cve2_py: cve2_pybind.cpp cve2_tb.h compile_cve2_py.sh \
         $(BUILD_DIR)/libcve2_tb.a $(VERILATED_LIBS)
	@echo "[BUILD] cve2_py Python module"
	TOP_MODULE=$(TOP_MODULE) sh ./compile_cve2_py.sh
	@echo "[OK]    cve2_py Python module ready"

# ============================================================================
# Standalone CVE2 simulation binary (developer convenience)
# ============================================================================

cve2_sim: cve2_sim.cpp cve2_tb.h $(BUILD_DIR)/libcve2_tb.a $(VERILATED_LIBS)
	@echo "[BUILD] cve2_sim  (no trace)"
	$(CXX) $(CXXFLAGS) \
	    cve2_sim.cpp \
	    -o cve2_sim \
	    $(BUILD_DIR)/libcve2_tb.a \
	    $(VERILATED_LIBS) \
	    -lpthread -lm -ldl
	@echo "[OK]    cve2_sim"

cve2_sim_trace: cve2_sim.cpp cve2_tb.h $(BUILD_DIR)/libcve2_tb.a $(VERILATED_LIBS)
	@echo "[BUILD] cve2_sim_trace  (VCD trace enabled)"
	$(CXX) $(CXXFLAGS) -g \
	    cve2_sim.cpp \
	    $(TRACE_SRC) \
	    -o cve2_sim_trace \
	    $(BUILD_DIR)/libcve2_tb.a \
	    $(VERILATED_LIBS) \
	    -lpthread -lm -ldl
	@echo "[OK]    cve2_sim_trace"
	@echo "        Run it, then open cve2_wave.vcd in GTKWave"

# --- Run targets --------------------------------------------------------------
run: cve2_sim
	./cve2_sim $(HEX) $(MAX_CYCLES)

run_trace: cve2_sim_trace
	./cve2_sim_trace $(HEX) $(MAX_CYCLES)

view_trace:
	gtkwave cve2_wave.vcd cve2.gtkw

# --- Help ---------------------------------------------------------------------
help:
	@echo "=========================================================================="
	@echo "CVE2 Verilator Build"
	@echo "=========================================================================="
	@echo ""
	@echo "TARGETS:"
	@echo "  setup            - Clone CVE2 RTL into external/"
	@echo "  verilate         - Run Verilator on the CVE2 RTL (-fPIC, one build)"
	@echo "  cve2_lib         - Build libcve2_tb.a"
	@echo "  cve2_sim         - Build standalone simulation binary (no trace)"
	@echo "  cve2_sim_trace   - Build standalone simulation binary (VCD trace)"
	@echo "  cve2_py          - Build Python extension module"
	@echo "  run              - Run cve2_sim  (HEX=, MAX_CYCLES=)"
	@echo "  run_trace        - Run cve2_sim_trace (HEX=, MAX_CYCLES=)"
	@echo "  view_trace       - Open cve2_wave.vcd in GTKWave"
	@echo "  clean            - Remove build artefacts"
	@echo ""
	@echo "QUICK START (Python pipeline viewer):"
	@echo "  make setup verilate cve2_lib cve2_py"
	@echo "  python3 trace_cve2.py tests/build/test.hex"
	@echo "=========================================================================="

# --- Clean --------------------------------------------------------------------
clean:
	rm -rf $(BUILD_DIR) cve2_sim cve2_sim_trace cve2_py.cpython-*.so
	@echo "Build directory cleaned."

distclean: clean
	rm -rf $(EXT_DIR)
	@echo "External sources removed."
