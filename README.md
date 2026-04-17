# cve2_spike_lock

Lock-step co-simulation of the **OpenHW CVE2** RISC-V core (Verilator) against
the **Spike** ISA simulator, plus Python bindings for both so you can drive
them from a script and render **Konata-style** pipeline diagrams as HTML.

## What this repo is

```
 +-------------------+           +-------------------+
 |  tests/test.S     |--(gcc)--> | test.elf/.hex/.bin|
 +-------------------+           +-------------------+
                                         |
             +---------------------------+---------------------------+
             |                           |                           |
             v                           v                           v
   +-------------------+       +-------------------+       +--------------------+
   |   CVE2 RTL        |       |  Spike ISS        |       |  Lock-step cosim   |
   |   (Verilator)     |       |  (riscv-isa-sim)  |       |  CVE2 <-> Spike    |
   |                   |       |                   |       |  per-retirement    |
   |  cve2_py (.so)    |       |  spike_py (.so)   |       |  PC/regs/mem diff  |
   +--------+----------+       +--------+----------+       +----------+---------+
            |                           |                             |
            v                           v                             v
    trace_cve2.py               trace_spike.py                    cosim_tb
    -> pipeline_cve2.html       -> pipeline_spike.html            (CLI binary)
    (+ cve2_wave.vcd)
```

Components:

| Path              | Purpose                                                                 |
|-------------------|-------------------------------------------------------------------------|
| `cve2/`           | Clones OpenHW CVE2 RTL, runs Verilator, builds `libcve2_tb.a` + `cve2_py` + `cve2_sim` |
| `spike_wrapper/`  | C++ wrapper over Spike; builds `spike_py.so` (Python) **and** `libspike_wrapper.a` (for cosim) |
| `cosim/`          | Lock-step comparator binary `cosim_tb`                                  |
| `tests/`          | `test.S` + linker script + makefile -> `test.elf/.bin/.dis/.hex`         |
| `trace_spike.py`  | Runs Spike via `spike_py`, emits Konata HTML                             |
| `trace_cve2.py`   | Runs CVE2 via `cve2_py`, emits Konata HTML + optional VCD                |
| `env.sh`          | Sources tool paths + Python venv                                         |
| `Makefile`        | Top-level orchestrator (delegates to sub-makefiles)                      |
| `requirements.txt`| Python deps (`pybind11`)                                                 |

## Prerequisites

Pinned versions (repo is tested against these exactly):

| Tool                  | Version / commit                                        | Install prefix             |
|-----------------------|---------------------------------------------------------|----------------------------|
| Verilator             | **5.040**                                               | system / `$PATH`           |
| Spike (riscv-isa-sim) | commit `0ad45926ac6f42d0d39e936abf4ab1cb9bdc5086`       | `$TOOLS_ROOT/spike`        |
| riscv-gnu-toolchain   | commit `f27c68dd632102a1eab85d97a90f3cdc4e90350c`       | `$TOOLS_ROOT/riscv_rva23`  |
| OpenHW CVE2 RTL       | commit `e35390a7754f4e9acbce22840835a7a0f045ddc7`       | cloned by `make cve2`      |
| g++                   | **>= 10** (C++20)                                       | system                     |
| Python                | >= 3.8                                                  | system                     |
| pybind11              | >= 2.11                                                 | installed into `.venv`     |

`TOOLS_ROOT` defaults to `$HOME/tools`.  Override before sourcing `env.sh`:
`TOOLS_ROOT=/opt/riscv source env.sh`.

### OS packages (Ubuntu/Debian)

```bash
sudo apt install build-essential git \
                 autoconf automake autotools-dev curl libmpc-dev libmpfr-dev \
                 libgmp-dev gawk bison flex texinfo gperf libtool patchutils \
                 bc zlib1g-dev libexpat-dev \
                 libfl-dev help2man \
                 python3 python3-venv python3-pip \
                 gtkwave
```

### Install Verilator 5.040

```bash
git clone https://github.com/verilator/verilator.git
cd verilator
git checkout v5.040
autoconf && ./configure && make -j$(nproc)
sudo make install
# or to keep it under $TOOLS_ROOT:
#   ./configure --prefix=$HOME/tools/verilator && make install
```

Check: `verilator --version` should print `Verilator 5.040 ...`.

### Install Spike (riscv-isa-sim)

```bash
git clone https://github.com/riscv-software-src/riscv-isa-sim.git
cd riscv-isa-sim
git checkout 0ad45926ac6f42d0d39e936abf4ab1cb9bdc5086
mkdir build && cd build
../configure --prefix=$HOME/tools/spike
make -j$(nproc)
make install
```

### Install RISC-V GNU Toolchain (RVA23 profile)

```bash
git clone https://github.com/riscv/riscv-gnu-toolchain
cd riscv-gnu-toolchain
git checkout f27c68dd632102a1eab85d97a90f3cdc4e90350c
./configure --prefix=$HOME/tools/riscv_rva23 \
            --with-arch=rv64gc_zba_zbb_zbs_v_zicond_zcb_zfa \
            --with-abi=lp64d
make -j$(nproc)
```

> The toolchain is built RV64 but still produces RV32 code when you pass
> `-march=rv32imc -mabi=ilp32` to `gcc`. This repo's default test build is
> RV32 because CVE2 is a 32-bit core.

## Quick start

```bash
git clone <this repo>
cd cve2_spike_lock

# 1. tell the shell where the tools live
source env.sh                   # sets PATH/LD_LIBRARY_PATH/RVA23_COMPILER, checks versions

# 2. create the Python venv (one-time)
make venv
source env.sh                   # re-source so .venv is auto-activated

# 3. build everything
make all                        # tests + spike_py + cve2_py + cosim_tb

# 4. run something
make run-cosim       PROGRAM=tests/build/test ISA=rv32imc
make run-trace-spike PROGRAM=tests/build/test ISA=rv32imc   # -> pipeline_spike.html
make run-trace-cve2  HEX=tests/build/test.hex               # -> pipeline_cve2.html
```

## How to

### Build the test program

```bash
make tests                                             # default rv32imc
make tests MARCH='-march=rv32imc_zicsr -mabi=ilp32'    # custom ISA
make tests MARCH='-march=rv64gc -mabi=lp64d'           # RV64 (for Spike-only runs)
```

Outputs in `tests/build/`: `test.elf`, `test.bin`, `test.dis`, `test.hex`.

### Spike-only trace

```bash
make run-trace-spike PROGRAM=tests/build/test ISA=rv32imc MAX_INSTRUCTIONS=200
```

Opens `pipeline_spike.html` in a browser.  Pass `--no-browser` via direct
`python3 trace_spike.py ...` to skip opening it.

### CVE2-only trace (with VCD)

```bash
make run-trace-cve2 HEX=tests/build/test.hex MAX_CYCLES=2000
```

Produces `pipeline_cve2.html` and `cve2/cve2_wave.vcd`.  View the VCD with:

```bash
make view-vcd                                 # gtkwave cve2_wave.vcd cve2.gtkw
```

### Lock-step co-simulation

```bash
make run-cosim         PROGRAM=tests/build/test ISA=rv32imc
make run-cosim-verbose PROGRAM=tests/build/test ISA=rv32imc MAX_INSTRUCTIONS=50
```

At each CVE2 retirement (RVFI), cosim steps Spike once and compares PC,
register writes, and memory writes.  Any divergence prints a diff and aborts.

### Build a single component

```bash
make spike-wrapper       # -> spike_wrapper/spike_py.cpython-*.so
make spike-lib           # -> spike_wrapper/libspike_wrapper.a
make cve2                # clone + verilate + libcve2_tb.a
make cve2-py             # -> cve2/cve2_py.cpython-*.so
make cve2-sim            # -> cve2/cve2_sim  (standalone, no VCD)
make cve2-sim-trace      # -> cve2/cve2_sim_trace (VCD enabled)
make cosim               # -> cosim/cosim_tb
```

Sub-makefiles remain usable on their own, e.g. `cd cve2 && make help`.

## The `TRACE` flag (important)

`cve2_tb.h` changes its struct layout depending on whether `-DTRACE` is set.
All consumers of `libcve2_tb.a` (the library itself, `cve2_py`, `cosim_tb`)
**must** be built with the same setting or you get silent memory corruption.

The `cve2/` makefile writes the flag it used into
`cve2/build_cve2/cve2_tb_trace_flag.txt`.  The `cosim/` makefile reads it back
at link time, so rebuilding through the top-level Makefile keeps them in sync.

Override with `make TRACE=0 all` (disables VCD support everywhere).

## Reproducing results

1. Install Verilator 5.040, Spike at the pinned commit, toolchain at the pinned commit.
2. `TOOLS_ROOT=$HOME/tools source env.sh`.
3. `make venv && source env.sh && make all`.
4. `make run-cosim PROGRAM=tests/build/test ISA=rv32imc` — exit code 0 means RTL
   and Spike retired the same stream.

Pinned commits live in:

- `cve2/makefile` (`CVE2_BRANCH` for CVE2 RTL).
- this README (Spike + toolchain).

## Troubleshooting

### `ImportError: ... GLIBCXX_3.4.XX not found` when running `trace_*.py`

Anaconda ships an older `libstdc++.so.6` than the one `cve2_py`/`spike_py`
were compiled against.  Both `trace_*.py` scripts preload the system
`libstdc++` automatically before importing (`_preload_system_libstdcxx`).
If you still see the error, run outside conda or remove `$CONDA_PREFIX/lib`
from `LD_LIBRARY_PATH`.

### `No RISC-V toolchain found in ...`

`env.sh` did not find `*-elf-gcc` under `$RVA23_COMPILER/bin`.  Either install
the toolchain at `$TOOLS_ROOT/riscv_rva23`, or `export
RVA23_COMPILER=/path/to/your/toolchain` before `make tests`.

### `verilator: command not found` / wrong version

`make cve2` needs Verilator on `$PATH`.  Repo is pinned to 5.040; other
versions may compile but are untested.  `env.sh` warns on mismatch.

### CVE2 clone fails with SSH auth

`cve2/makefile` uses `git@github.com:openhwgroup/cve2.git` (SSH).  Switch
to HTTPS:

```bash
make cve2 CVE2_REPO=https://github.com/openhwgroup/cve2.git
```

(or edit `cve2/makefile` once).

### `pybind11` not found during build

`make venv` installs it into `.venv`.  Make sure the venv is active
(`source env.sh` auto-activates it if `.venv/` exists).

### Segfault in cosim / wrong RVFI offsets

Usually a `TRACE` flag mismatch.  Rebuild clean:

```bash
make clean
make all
```

## Layout recap

```
cve2_spike_lock/
|-- env.sh                       source this first
|-- Makefile                     top-level orchestrator
|-- requirements.txt             pybind11
|-- trace_spike.py               Spike   -> Konata HTML
|-- trace_cve2.py                CVE2    -> Konata HTML (+ VCD)
|-- tests/
|   |-- test.S  link.ld  makefile
|   `-- build/                   generated: test.elf/.bin/.dis/.hex
|-- spike_wrapper/
|   |-- spike_wrapper.{h,cpp}    C++ wrapper over Spike API
|   |-- compile_wrapper.sh       single source of truth for flags
|   `-- makefile                 -> spike_py.so / libspike_wrapper.a
|-- cve2/
|   |-- cve2_tb.{h,cpp}          Verilator testbench (bus, memory, RVFI)
|   |-- cve2_sim.cpp             standalone simulator main
|   |-- cve2_pybind.cpp          Python bindings
|   |-- compile_cve2_py.sh
|   |-- cve2.vc  cve2.gtkw
|   |-- makefile
|   `-- external/cv32e20/        cloned OpenHW CVE2 (gitignored)
`-- cosim/
    |-- cosim.{h,cpp}            lock-step comparator
    |-- cosim_main.cpp           CLI entry
    `-- makefile                 -> cosim_tb
```

## Credits

- OpenHW Group — [CVE2](https://github.com/openhwgroup/cve2)
- RISC-V International — [Spike / riscv-isa-sim](https://github.com/riscv-software-src/riscv-isa-sim)
- Verilator — [verilator.org](https://www.veripool.org/verilator/)
- Konata pipeline viewer — HTML re-rendering in `trace_*.py`
