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
V_FLAGS    := -Wall -cc --trace --trace-structs --trace-underscore \
              --trace-max-array 1024

TRACE_SRC  := $(VROOT_INC)/verilated_vcd_c.cpp

# --- Verilated library outputs -------------------------------------------------
LIBS := $(BUILD_DIR)/libV$(TOP_MODULE).a \
        $(BUILD_DIR)/libverilated.a \
        $(BUILD_DIR)/V$(TOP_MODULE)__ALL.a

# --- C++ compiler --------------------------------------------------------------
CXX      ?= g++
CXXFLAGS  = -std=c++20 -O2 -Wall \
            -I$(BUILD_DIR) \
            -I./ \
            -I$(VROOT_INC) \
            -I$(VROOT_INC)/vltstd \
            -I$(VROOT_INC)/gtkwave

# ============================================================================
# Phony targets
# ============================================================================

.PHONY: all clean setup verilate build_lib help

all: build_lib

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
verilate: setup
	@echo "--- Verilating $(TOP_MODULE) ---"
	@mkdir -p $(BUILD_DIR)
	$(VERILATOR) $(V_FLAGS) \
		--Mdir $(BUILD_DIR) \
		-f $(VC_FILE) \
		--top-module $(TOP_MODULE) \
		--build
	@echo "--- Veriltion complete ---"

# --- 3. Build Verilated static libraries (alias) ------------------------------
build_lib: verilate
	@echo "--- Libraries ready in $(BUILD_DIR) ---"

# ============================================================================
# Standalone CVE2 simulation binary
#   Source files:
#     cve2_tb.cpp  – Cve2Memory / SlowBus / Cve2Tb implementations
#     cve2_sim.cpp – main()
# ============================================================================

CVE2_SIM_SRCS := cve2_tb.cpp cve2_sim.cpp

cve2_sim: $(CVE2_SIM_SRCS) cve2_tb.h $(LIBS)
	@echo "[BUILD] cve2_sim  (no trace)"
	$(CXX) $(CXXFLAGS) \
	    $(CVE2_SIM_SRCS) \
	    -o cve2_sim \
	    $(LIBS) \
	    -lpthread -lm -ldl
	@echo "[OK]    cve2_sim"

cve2_sim_trace: $(CVE2_SIM_SRCS) cve2_tb.h $(LIBS)
	@echo "[BUILD] cve2_sim_trace  (VCD trace enabled)"
	$(CXX) $(CXXFLAGS) -g -DTRACE \
	    $(CVE2_SIM_SRCS) \
	    $(TRACE_SRC) \
	    -o cve2_sim_trace \
	    $(LIBS) \
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

# --- Clean --------------------------------------------------------------------
clean:
	rm -rf $(BUILD_DIR) cve2_sim cve2_sim_trace cve2_wave.vcd
	@echo "Build directory cleaned."

distclean: clean
	rm -rf $(EXT_DIR)
	@echo "External sources removed."
