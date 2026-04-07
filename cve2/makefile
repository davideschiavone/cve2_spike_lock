# --- Configuration ---
# Repo and Branch
CVE2_REPO    := git@github.com:openhwgroup/cve2.git
CVE2_BRANCH  := e35390a7754f4e9acbce22840835a7a0f045ddc7

# Directories
EXT_DIR      := external
CVE2_DIR     := $(EXT_DIR)/cv32e20
BUILD_DIR    := build_cve2
VC_FILE      := cve2.vc  # Assumes this file is in your root

# Verilator Settings
VERILATOR    := verilator
TOP_MODULE   := cve2_top
V_FLAGS      := -Wall -cc --trace --trace-structs --trace-underscore --trace-max-array 1024

# Outputs
LIB_A        := $(BUILD_DIR)/V$(TOP_MODULE)__ALL.a

.PHONY: all clean setup verilate build_lib

all: build_lib

# 1. Setup: Clone the repo if it doesn't exist
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

# 2. Verilate: Convert SystemVerilog to C++
# We use --Mdir to force Verilator to put everything in build_cve2
verilate: setup
	@echo "--- Verilating $(TOP_MODULE) ---"
	@mkdir -p $(BUILD_DIR)
	$(VERILATOR) $(V_FLAGS) \
		--Mdir $(BUILD_DIR) \
		-f $(VC_FILE) \
		--top-module $(TOP_MODULE) \
		--build

# 3. Build Lib: Just a wrapper for the build (Verilator --build handles the make)
build_lib: verilate
	@echo "--- Library created at $(LIB_A) ---"

clean:
	rm -rf $(BUILD_DIR)
	@echo "Build directory cleaned."

distclean: clean
	rm -rf $(EXT_DIR)
	@echo "External sources removed."