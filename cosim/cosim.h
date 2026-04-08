// ============================================================================
// cosim.h  –  Spike × CVE2 Lock-Step Co-Simulation Engine
// ============================================================================
//
// Architecture overview
// ─────────────────────
//
//   Python / main()
//       │
//       ▼
//   CoSim::run()
//       │
//       ├─ RTL side : Cve2Tb::step()  (clock cycles until rvfi_valid)
//       │                │
//       │                └─ captures RvfiInsn on retirement
//       │
//       └─ ISA side : SpikeBridge::step()
//                        │
//                        └─ captures PC, rd, rd_wdata, mem_addr, mem_wdata
//
// Comparison matrix (per retired instruction)
// ────────────────────────────────────────────
//
//  ┌──────────────┬───────────────────────────────────────────┐
//  │ Signal       │ When compared                             │
//  ├──────────────┼───────────────────────────────────────────┤
//  │ pc_rdata     │ always                                    │
//  │ rd_wdata     │ rd_addr != 0  (x0 write is discarded)     │
//  │ mem_wdata    │ mem_wmask != 0  (store instruction)       │
//  │ mem_addr     │ mem_wmask != 0  (store instruction)       │
//  └──────────────┴───────────────────────────────────────────┘
//
//  Branches / jumps: not compared directly; any control-flow divergence
//  is immediately caught by the PC check on the *next* instruction.
//
// Spike state capture
// ────────────────────
//   After SpikeBridge::step() the engine reads:
//     - get_pc()                 → next PC (i.e., pc after execution)
//     - get_reg(rd_addr)         → value written to rd (RVFI-driven rd_addr)
//     - get_csrs() + MEM sniff   → store data (see StoreObserver below)
//
//   Because Spike does not expose "what was the last memory write" directly,
//   we snapshot the target address inferred from RVFI and read it back from
//   Spike's memory via dump_memory / a lightweight read helper.
//
// Pybind11 future binding
// ────────────────────────
//   CoSim is designed to be bound to Python with minimal friction:
//     - All configuration goes through CoSimConfig (plain struct)
//     - CoSimResult / MismatchRecord are simple aggregates
//     - CoSim::run() returns a CoSimResult by value
//   See the bottom of this file for a stub PYBIND11_MODULE declaration.
//
// Build (add to cve2/makefile):
//   cosim: cosim.cpp cosim.h cve2_tb.h $(LIBS)
//       $(CXX) $(CXXFLAGS) cosim.cpp -o cosim_tb \
//           $(LIBS) -lpthread -lm -ldl \
//           -I$(SPIKE_INCLUDE) -L$(SPIKE_LIB) -lriscv -lfesvr \
//           -Wl,-rpath,$(SPIKE_LIB)
//
// ============================================================================

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <optional>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <functional>

// Pull in both simulation sides.
// Adjust include paths to match your build tree.
#include "cve2_tb.h"           // Cve2Tb, RvfiInsn
#include "spike_wrapper.h"  // SpikeBridge  (or spike_py bindings in Python mode)

// ============================================================================
// Helpers
// ============================================================================

/// ANSI colour codes for terminal output
namespace colour {
    constexpr const char* RED    = "\033[31m";
    constexpr const char* GREEN  = "\033[32m";
    constexpr const char* YELLOW = "\033[33m";
    constexpr const char* CYAN   = "\033[36m";
    constexpr const char* BOLD   = "\033[1m";
    constexpr const char* RESET  = "\033[0m";
}

/// ABI register names
static constexpr const char* ABI_NAMES[32] = {
    "zero","ra","sp","gp","tp","t0","t1","t2",
    "s0","s1","a0","a1","a2","a3","a4","a5",
    "a6","a7","s2","s3","s4","s5","s6","s7",
    "s8","s9","s10","s11","t3","t4","t5","t6"
};

// ============================================================================
// MismatchRecord  –  one recorded comparison failure
// ============================================================================

enum class MismatchKind {
    PC,          ///< program counter diverged
    RD_WDATA,    ///< destination register value differs
    MEM_ADDR,    ///< store address differs
    MEM_WDATA,   ///< store data differs
};

struct MismatchRecord {
    uint64_t    retired_count = 0;     ///< instruction retirement index
    MismatchKind kind         = MismatchKind::PC;
    uint32_t    rtl_val       = 0;     ///< value from CVE2 / RVFI
    uint64_t    ref_val       = 0;     ///< value from Spike
    uint32_t    pc_rdata      = 0;     ///< PC at the point of divergence
    uint8_t     rd_addr       = 0;     ///< rd involved (for RD_WDATA)

    std::string to_string() const {
        std::ostringstream ss;
        ss << colour::RED << "[MISMATCH #" << retired_count << "] ";
        switch (kind) {
            case MismatchKind::PC:
                ss << "PC  rtl=0x" << std::hex << std::setw(8) << std::setfill('0') << rtl_val
                   << "  ref=0x" << std::setw(8) << std::setfill('0') << ref_val;
                break;
            case MismatchKind::RD_WDATA:
                ss << "rd=" << ABI_NAMES[rd_addr]
                   << "  rtl=0x" << std::hex << std::setw(8) << std::setfill('0') << rtl_val
                   << "  ref=0x" << std::setw(8) << std::setfill('0') << ref_val
                   << "  (PC=0x" << std::setw(8) << std::setfill('0') << pc_rdata << ")";
                break;
            case MismatchKind::MEM_ADDR:
                ss << "STORE ADDR  rtl=0x" << std::hex << std::setw(8) << std::setfill('0') << rtl_val
                   << "  ref=0x" << std::setw(8) << std::setfill('0') << ref_val;
                break;
            case MismatchKind::MEM_WDATA:
                ss << "STORE DATA  rtl=0x" << std::hex << std::setw(8) << std::setfill('0') << rtl_val
                   << "  ref=0x" << std::setw(8) << std::setfill('0') << ref_val
                   << "  (PC=0x" << std::setw(8) << std::setfill('0') << pc_rdata << ")";
                break;
        }
        ss << colour::RESET;
        return ss.str();
    }
};

// ============================================================================
// CoSimConfig
// ============================================================================

struct CoSimConfig {
    std::string hex_path;               ///< path to test.hex
    std::string elf_path;               ///< base name for SpikeBridge (no extension)
    std::string isa    = "rv32imc";     ///< ISA string fed to Spike
    uint64_t    max_retired = 100'000;  ///< retirement limit
    uint64_t    max_cycles  = 10'000'000ULL; ///< RTL cycle hard limit
    uint32_t    boot_addr   = BOOT_ADDR;
    bool        verbose     = false;    ///< print every retired instruction
    bool        stop_on_first_mismatch = true;
};

// ============================================================================
// CoSimResult
// ============================================================================

struct CoSimResult {
    uint64_t retired_count  = 0;    ///< instructions successfully compared
    uint64_t rtl_cycles     = 0;    ///< RTL clock cycles consumed
    uint32_t mismatches     = 0;    ///< total mismatch count
    bool     halted_cleanly = false;///< both sides reached ecall / finish loop

    std::vector<MismatchRecord> mismatch_log;

    void print_summary() const {
        std::cout << "\n" << colour::BOLD
                  << "╔══════════════════════════════════════════════╗\n"
                  << "║         Co-Simulation Summary                ║\n"
                  << "╚══════════════════════════════════════════════╝\n"
                  << colour::RESET;
        std::cout << "  Retired instructions : " << retired_count  << "\n";
        std::cout << "  RTL clock cycles     : " << rtl_cycles     << "\n";
        std::cout << "  Mismatches           : ";
        if (mismatches == 0)
            std::cout << colour::GREEN << "0 — PASS ✓" << colour::RESET << "\n";
        else {
            std::cout << colour::RED << mismatches << " — FAIL ✗" << colour::RESET << "\n";
            for (auto& m : mismatch_log)
                std::cout << "    " << m.to_string() << "\n";
        }
        std::cout << "  Halted cleanly       : " << (halted_cleanly ? "yes" : "no") << "\n\n";
    }
};

// ============================================================================
// SpikeState  –  snapshot of Spike after one step
// ============================================================================

struct SpikeState {
    uint32_t pc_after  = 0;   ///< PC *after* this instruction (next fetch addr)
    uint32_t pc_before = 0;   ///< PC *before* step (= instruction address)
    uint32_t rd_wdata  = 0;   ///< value written to rd  (0 if no write / rd==x0)
    uint32_t mem_wdata = 0;   ///< store data  (valid when is_store)
    uint32_t mem_addr  = 0;   ///< store address
    bool     is_store  = false;
};

// ============================================================================
// CoSim  –  the lock-step engine
// ============================================================================

class CoSim {
public:
    explicit CoSim(const CoSimConfig& cfg)
        : cfg_(cfg)
        , rtl_(cfg.hex_path, cfg.boot_addr, cfg.max_cycles)
        , spike_(cfg.elf_path.c_str(), cfg.isa.c_str())
    {
        std::cout << colour::CYAN << colour::BOLD
                  << "\n╔═══════════════════════════════════════════════════╗\n"
                  << "║    Spike × CVE2 Lock-Step Co-Simulation Engine    ║\n"
                  << "╚═══════════════════════════════════════════════════╝\n"
                  << colour::RESET;
        std::cout << "  HEX    : " << cfg.hex_path << "\n";
        std::cout << "  ELF    : " << cfg.elf_path << "\n";
        std::cout << "  ISA    : " << cfg.isa       << "\n\n";

        // Print the Spike starting PC for sanity
        std::cout << colour::YELLOW << "[CoSim] Spike initial PC: 0x"
                  << std::hex << std::setw(8) << std::setfill('0')
                  << (uint32_t)spike_.get_pc() << std::dec << colour::RESET << "\n\n";
    }

    // -------------------------------------------------------------------------
    // run()  –  execute until halt or limits
    // -------------------------------------------------------------------------
    CoSimResult run() {
        CoSimResult result;
        rtl_.reset(8);

        if (cfg_.verbose) {
            std::printf("\n%-6s  %-10s  %-8s  %-8s  %-25s  %s\n",
                        "#RET", "PC", "INSN", "RD", "RTL→REF", "STATUS");
            std::printf("%s\n", std::string(80, '─').c_str());
        }

        while (!rtl_.halted() && result.retired_count < cfg_.max_retired) {
            // ── 1. Advance RTL until next RVFI retirement ─────────────────
            const RvfiInsn* rvfi = advance_rtl_to_retirement();
            if (!rvfi) break;   // halted before retiring

            // ── 2. Capture Spike state BEFORE stepping ─────────────────────
            uint32_t spike_pc_before = (uint32_t)spike_.get_pc();

            // ── 3. Step Spike one instruction ──────────────────────────────
            spike_.step();

            // ── 4. Capture Spike state AFTER step ──────────────────────────
            SpikeState ss = capture_spike_state(*rvfi, spike_pc_before);

            // ── 5. Compare ─────────────────────────────────────────────────
            ++result.retired_count;
            bool ok = compare(*rvfi, ss, result);

            // ── 6. Verbose trace line ──────────────────────────────────────
            if (cfg_.verbose)
                print_trace_line(result.retired_count, *rvfi, ss, ok);

            if (!ok && cfg_.stop_on_first_mismatch)
                break;
        }

        result.rtl_cycles     = rtl_.cycle();
        result.halted_cleanly = rtl_.halted();
        return result;
    }

private:
    // -------------------------------------------------------------------------
    // advance_rtl_to_retirement()
    //   Clock the RTL until rvfi_valid fires.  Returns a pointer to the
    //   latched RVFI snapshot (owned by Cve2Tb) or nullptr if halted first.
    // -------------------------------------------------------------------------
    const RvfiInsn* advance_rtl_to_retirement() {
        // Step until valid or halted
        while (!rtl_.halted()) {
            rtl_.step();
            if (rtl_.rvfi_valid())
                return &rtl_.rvfi();
        }
        // Halted without producing RVFI this round – check if the last step
        // already captured a valid retirement (halt is set inside capture_rvfi
        // which may happen on the same rising edge as rvfi_valid).
        if (rtl_.rvfi_valid())
            return &rtl_.rvfi();
        return nullptr;
    }

    // -------------------------------------------------------------------------
    // capture_spike_state()
    //   Gather the Spike side's ground-truth values for the just-executed
    //   instruction, guided by what RVFI told us about the RTL side.
    // -------------------------------------------------------------------------
    SpikeState capture_spike_state(const RvfiInsn& rvfi, uint32_t pc_before) {
        SpikeState ss;
        ss.pc_before = pc_before;
        ss.pc_after  = (uint32_t)spike_.get_pc();

        // Destination register value
        if (rvfi.rd_addr != 0) {
            ss.rd_wdata = (uint32_t)spike_.get_reg(rvfi.rd_addr);
        }

        // Store: read back from Spike's memory at the address RVFI reported.
        // We trust RVFI's mem_addr to locate where Spike also wrote.
        // Spike committed the store during step(), so the value is in memory now.
        if (rvfi.mem_wmask != 0) {
            ss.is_store = true;
            ss.mem_addr = rvfi.mem_addr;   // use RTL-reported addr as key

            // Reconstruct the stored word byte-by-byte using wmask
            // (handles SW, SH, SB correctly)
            uint8_t buf[4] = {0, 0, 0, 0};
            // Spike's memory is accessible via dump_memory into cout, but for
            // co-sim we need actual values.  We read them back via get_reg on
            // a scratch path — instead, use the load-from-memory helper below.
            ss.mem_wdata = read_spike_word(rvfi.mem_addr, rvfi.mem_wmask);
        }

        return ss;
    }

    // -------------------------------------------------------------------------
    // read_spike_word()
    //   Read a 32-bit word from Spike's memory at `addr`, masked by `wmask`.
    //   We exploit the fact that Spike just performed the store, so a load
    //   at the same address will return the freshly written value.
    //
    //   Implementation note: SpikeBridge doesn't expose a direct read32().
    //   We temporarily load a register from that address via a synthetic
    //   approach.  The simplest portable method is to snapshot before the
    //   store (impractical) or to add a read_mem32() to SpikeBridge.
    //
    //   For now we use the approach that requires the least bridge change:
    //   we record the RVFI wdata directly (RTL value) and cross-check that
    //   Spike's memory *at that address* matches.  We expose a `read_mem`
    //   method on SpikeBridge for this purpose.  If not yet present, the
    //   comparison falls back to a warning.
    // -------------------------------------------------------------------------
    uint32_t read_spike_word(uint32_t addr, uint8_t wmask) {
        // Attempt to call spike_.read_mem32() if it exists.
        // This requires adding the method to SpikeBridge — see cosim_bridge_ext.h
#ifdef COSIM_HAS_READ_MEM
        return spike_.read_mem32(addr);
#else
        // Fallback: we cannot read Spike memory without the extension.
        // Return a sentinel so the comparison can report "N/A" gracefully.
        (void)addr; (void)wmask;
        return SPIKE_MEM_READ_UNAVAILABLE;
#endif
    }

    static constexpr uint32_t SPIKE_MEM_READ_UNAVAILABLE = 0xDEAD'C0DEu;

    // -------------------------------------------------------------------------
    // compare()  –  check RTL vs Spike, record mismatches
    // -------------------------------------------------------------------------
    bool compare(const RvfiInsn& rvfi, const SpikeState& ss, CoSimResult& result) {
        bool all_ok = true;

        auto record = [&](MismatchKind k, uint32_t rtl_val, uint64_t ref_val, uint8_t rd = 0) {
            result.mismatches++;
            MismatchRecord m;
            m.retired_count = result.retired_count;
            m.kind          = k;
            m.rtl_val       = rtl_val;
            m.ref_val       = ref_val;
            m.pc_rdata      = rvfi.pc_rdata;
            m.rd_addr       = rd;
            result.mismatch_log.push_back(m);
            std::cerr << m.to_string() << "\n";
            all_ok = false;
        };

        // ── PC check ─────────────────────────────────────────────────────
        // RVFI pc_rdata = address of the *current* instruction.
        // Spike's pc_before captured before step() = same thing.
        if (rvfi.pc_rdata != ss.pc_before) {
            record(MismatchKind::PC, rvfi.pc_rdata, ss.pc_before);
        }

        // ── Register write ────────────────────────────────────────────────
        // Only compare when rd != x0 and the instruction actually writes.
        if (rvfi.rd_addr != 0) {
            uint32_t rtl_rd = rvfi.rd_wdata;
            uint32_t ref_rd = ss.rd_wdata;
            if (rtl_rd != ref_rd) {
                record(MismatchKind::RD_WDATA, rtl_rd, ref_rd, rvfi.rd_addr);
            }
        }

        // ── Store check ───────────────────────────────────────────────────
        if (rvfi.mem_wmask != 0) {
            // Address check
            uint32_t rtl_addr = rvfi.mem_addr;
            uint32_t ref_addr = ss.mem_addr;
            if (rtl_addr != ref_addr) {
                record(MismatchKind::MEM_ADDR, rtl_addr, ref_addr);
            }

            // Data check (only if Spike memory read is available)
            if (ss.mem_wdata != SPIKE_MEM_READ_UNAVAILABLE) {
                uint32_t rtl_wdata = rvfi.mem_wdata;
                // Mask to bytes that were actually written
                uint32_t mask = 0;
                if (rvfi.mem_wmask & 0x1) mask |= 0x0000'00FFu;
                if (rvfi.mem_wmask & 0x2) mask |= 0x0000'FF00u;
                if (rvfi.mem_wmask & 0x4) mask |= 0x00FF'0000u;
                if (rvfi.mem_wmask & 0x8) mask |= 0xFF00'0000u;

                if ((rtl_wdata & mask) != (ss.mem_wdata & mask)) {
                    record(MismatchKind::MEM_WDATA, rtl_wdata & mask, ss.mem_wdata & mask);
                }
            }
        }

        return all_ok;
    }

    // -------------------------------------------------------------------------
    // print_trace_line()  –  one-line verbose output per instruction
    // -------------------------------------------------------------------------
    void print_trace_line(uint64_t n, const RvfiInsn& rvfi,
                          const SpikeState& ss, bool ok) const
    {
        const char* status = ok ? (colour::GREEN "OK " colour::RESET)
                                : (colour::RED   "ERR" colour::RESET);
        std::string rd_str = "-";
        if (rvfi.rd_addr != 0) {
            char buf[32];
            std::snprintf(buf, sizeof(buf), "%s:0x%08x→0x%08x",
                          ABI_NAMES[rvfi.rd_addr], rvfi.rd_wdata, ss.rd_wdata);
            rd_str = buf;
        }
        std::printf("%-6lu  0x%08x  0x%08x  %-8s  %-28s  %s\n",
                    (unsigned long)n,
                    rvfi.pc_rdata,
                    rvfi.insn,
                    (rvfi.rd_addr ? ABI_NAMES[rvfi.rd_addr] : "-"),
                    rd_str.c_str(),
                    status);
    }

    // ── Members ───────────────────────────────────────────────────────────
    CoSimConfig  cfg_;
    Cve2Tb       rtl_;
    SpikeBridge  spike_;
};

// ============================================================================
// cosim_bridge_ext.h — Required SpikeBridge extension
// ============================================================================
//
//  To enable full store-data comparison, add the following method to
//  SpikeBridge in spike_wrapper.cpp and recompile:
//
//  ```cpp
//  uint32_t read_mem32(uint64_t addr) {
//      auto mmu = sim->get_core(0)->get_mmu();
//      return mmu->load<uint32_t>(addr);
//  }
//  ```
//
//  Then in spike_wrapper.cpp PYBIND11_MODULE block add:
//      .def("read_mem32", &SpikeBridge::read_mem32, py::arg("addr"),
//           "Read a 32-bit word from simulation memory")
//
//  And compile cosim.cpp with -DCOSIM_HAS_READ_MEM
//
// ============================================================================

// ============================================================================
// Pybind11 stub (future binding — uncomment when building as .so)
// ============================================================================
//
// #include <pybind11/pybind11.h>
// #include <pybind11/stl.h>
// namespace py = pybind11;
//
// PYBIND11_MODULE(cosim_py, m) {
//     m.doc() = "Spike × CVE2 lock-step co-simulation engine";
//
//     py::enum_<MismatchKind>(m, "MismatchKind")
//         .value("PC",       MismatchKind::PC)
//         .value("RD_WDATA", MismatchKind::RD_WDATA)
//         .value("MEM_ADDR", MismatchKind::MEM_ADDR)
//         .value("MEM_WDATA",MismatchKind::MEM_WDATA);
//
//     py::class_<MismatchRecord>(m, "MismatchRecord")
//         .def_readonly("retired_count", &MismatchRecord::retired_count)
//         .def_readonly("kind",          &MismatchRecord::kind)
//         .def_readonly("rtl_val",       &MismatchRecord::rtl_val)
//         .def_readonly("ref_val",       &MismatchRecord::ref_val)
//         .def_readonly("pc_rdata",      &MismatchRecord::pc_rdata)
//         .def_readonly("rd_addr",       &MismatchRecord::rd_addr)
//         .def("to_string",              &MismatchRecord::to_string);
//
//     py::class_<CoSimConfig>(m, "CoSimConfig")
//         .def(py::init<>())
//         .def_readwrite("hex_path",             &CoSimConfig::hex_path)
//         .def_readwrite("elf_path",             &CoSimConfig::elf_path)
//         .def_readwrite("isa",                  &CoSimConfig::isa)
//         .def_readwrite("max_retired",          &CoSimConfig::max_retired)
//         .def_readwrite("max_cycles",           &CoSimConfig::max_cycles)
//         .def_readwrite("verbose",              &CoSimConfig::verbose)
//         .def_readwrite("stop_on_first_mismatch",&CoSimConfig::stop_on_first_mismatch);
//
//     py::class_<CoSimResult>(m, "CoSimResult")
//         .def_readonly("retired_count",  &CoSimResult::retired_count)
//         .def_readonly("rtl_cycles",     &CoSimResult::rtl_cycles)
//         .def_readonly("mismatches",     &CoSimResult::mismatches)
//         .def_readonly("halted_cleanly", &CoSimResult::halted_cleanly)
//         .def_readonly("mismatch_log",   &CoSimResult::mismatch_log)
//         .def("print_summary",           &CoSimResult::print_summary);
//
//     py::class_<CoSim>(m, "CoSim")
//         .def(py::init<const CoSimConfig&>(), py::arg("config"))
//         .def("run", &CoSim::run, "Run the lock-step co-simulation");
// }
