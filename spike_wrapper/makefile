# ============================================================================
# spike_wrapper/makefile
# ============================================================================

.PHONY: all clean spike_wrapper help

all: spike_wrapper

help:
	@echo "=========================================================================="
	@echo "RISC-V Spike Wrapper - Pybind11 Python Module"
	@echo "=========================================================================="
	@echo ""
	@echo "TARGETS:"
	@echo "  spike_wrapper  - Compile spike_wrapper.cpp into a Python .so module"
	@echo "  clean          - Remove generated .so files"
	@echo "  help           - Show this message"
	@echo ""
	@echo "PREREQUISITES:"
	@echo "  - Spike headers/libs installed at ~/tools/spike"
	@echo "  - pip install pybind11"
	@echo "  - g++ with C++20 support"
	@echo "=========================================================================="

# ============================================================================
# Build the Pybind11 Python extension module
#   Sources:
#     spike_wrapper.h   – SpikeBridge declaration
#     spike_wrapper.cpp – SpikeBridge implementation + PYBIND11_MODULE
# ============================================================================

spike_wrapper: spike_wrapper.h spike_wrapper.cpp
	@echo "[BUILD] Spike Pybind11 wrapper (spike_wrapper.h + spike_wrapper.cpp)"
	sh ./compile_wrapper.sh
	@echo "[OK] Output: spike_py.cpython-*.so"

# ============================================================================
# Clean
# ============================================================================

clean:
	@echo "[CLEAN] Removing generated files..."
	rm -f spike_py.cpython-*.so
	@echo "[OK] Clean complete"
