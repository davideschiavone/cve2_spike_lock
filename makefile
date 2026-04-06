RISCV_BIN     := $(RVA23_COMPILER)/bin/
CROSS_COMPILE := $(RISCV_BIN)riscv64-unknown-elf-

AS      := $(CROSS_COMPILE)as
CC      := $(CROSS_COMPILE)gcc
LD      := $(CROSS_COMPILE)ld
OBJCOPY := $(CROSS_COMPILE)objcopy
OBJDUMP := $(CROSS_COMPILE)objdump

MARCH := -march=rv64gcv_zba_zbb_zbs -mabi=lp64d

LDFLAGS := -T link.ld -nostdlib -nostartfiles -static

.PHONY: all clean wrapper test

all: test spike_wrapper

# --- test (test.S -> .elf -> .bin -> .dis) ---

test: test.elf test.bin test.dis test.hex

test.elf: test.S
	@echo "cross compilation $<..."
	$(CC) $(MARCH) $(LDFLAGS) $< -o $@

test.bin: test.elf
	@echo "[BIN] binary..."
	$(OBJCOPY) -O binary $< $@

test.dis: test.elf
	@echo "[DUMP] disassembly..."
	$(OBJDUMP) -D $< > $@

test.hex: test.elf
	@echo "[HEX] Generating Verilog hex file..."
	$(OBJCOPY) -O verilog $< $@

# --- spike_wrapper C++ ---

spike_wrapper:
	rm -rf spike_py.cpython-39-x86_64-linux-gnu.so
	sh ./compile_wrapper.sh

# --- Utility ---

clean:
	rm -f test.hex test.elf test.bin test.dis
