# ============================================================================
# Add these rules to cve2/makefile  (or include this file from it)
# ============================================================================
#
# Prerequisites already in cve2/makefile:
#   LIBS     = $(BUILD_DIR)/libV$(TOP_MODULE).a ...
#   CXXFLAGS = ...
#   CXX      = g++
#
# New variables required (set in your environment or before including):
#   SPIKE_INCLUDE  e.g. /home/$(USER)/tools/spike/include
#   SPIKE_LIB      e.g. /home/$(USER)/tools/spike/lib
# ============================================================================

CVE2_DIR     	  := ../cve2/  # Adjust this path if your cve2 directory is located elsewhere
SPIKE_WRAPPER_DIR := ../spike_wrapper/  # Adjust this path if your spike_wrapper directory is located elsewhere

SPIKE_INCLUDE ?= /home/$(USER)/tools/spike/include
SPIKE_LIB     ?= /home/$(USER)/tools/spike/lib

COSIM_FLAGS = \
    -I$(SPIKE_INCLUDE) \
    -DCOSIM_HAS_READ_MEM

COSIM_LDFLAGS = \
    -L$(SPIKE_LIB) \
    -Wl,-rpath,$(SPIKE_LIB) \
    -lriscv -lfesvr

# Outputs
TOP_MODULE      := cve2_top
CVE2_BUILD_DIR  := $(CVE2_DIR)build_cve2
CVE2_LIBS = $(CVE2_BUILD_DIR)/libV$(TOP_MODULE).a \
                $(CVE2_BUILD_DIR)/libverilated.a \
		        $(CVE2_BUILD_DIR)/V$(TOP_MODULE)__ALL.a

# ─── cosim_tb  (no waveform) ─────────────────────────────────────────────────
cosim_tb: cosim.cpp cosim.h $(CVE2_DIR)cve2_tb.h $(CVE2_LIBS)
	@echo "[BUILD] cosim_tb  (lock-step co-simulation, no trace)"
	$(CXX) $(CXXFLAGS) $(COSIM_FLAGS) \
	    cosim.cpp \
	    -o cosim_tb \
	    $(CVE2_LIBS) $(COSIM_LDFLAGS) \
	    -lpthread -lm -ldl
	@echo "[OK]    cosim_tb"

# ─── cosim_tb_trace  (VCD waveform enabled) ───────────────────────────────────
cosim_tb_trace: cosim.cpp cosim.h $(CVE2_DIR)cve2_tb.h $(CVE2_LIBS)
	@echo "[BUILD] cosim_tb_trace  (lock-step co-simulation + VCD trace)"
	$(CXX) $(CXXFLAGS) $(COSIM_FLAGS) -g -DTRACE \
	    cosim.cpp \
	    $(TRACE_SRC) \
	    -o cosim_tb_trace \
	    $(CVE2_LIBS) $(COSIM_LDFLAGS) \
	    -lpthread -lm -ldl
	@echo "[OK]    cosim_tb_trace"

# ─── Convenience run targets ──────────────────────────────────────────────────
cosim_run: cosim_tb
	./cosim_tb $(HEX) $(ELF) $(ISA)

cosim_run_verbose: cosim_tb
	./cosim_tb $(HEX) $(ELF) $(ISA) --verbose

# Example:
#   make cosim_run HEX=../test.hex ELF=../test ISA=rv32imc
#   make cosim_run_verbose HEX=../test.hex ELF=../test ISA=rv32imc
