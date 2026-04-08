// ============================================================================
// spike_wrapper.h  –  Declaration of SpikeBridge
// ============================================================================
//
// Included by:
//   - spike_wrapper.cpp  (implementation + Pybind11 module)
//   - cosim/cosim.h      (lock-step co-simulation engine)
//
// ============================================================================

#pragma once

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include <riscv/sim.h>
#include <riscv/processor.h>
#include <riscv/devices.h>
#include <riscv/cfg.h>
#include <riscv/disasm.h>
#include <riscv/decode.h>
#include <riscv/mmu.h>
#include <riscv/vector_unit.h>

// ============================================================================
// XLen  –  register width of the simulated target
// ============================================================================

enum class XLen {
    XLEN_32 = 32,
    XLEN_64 = 64
};

// ============================================================================
// SpikeBridge  –  high-performance wrapper around the Spike ISA simulator
// ============================================================================

class SpikeBridge {
public:
    /**
     * @param program  Base name of the program (no extension).
     *                 SpikeBridge appends .elf (for HTIF) and .hex (for memory load).
     * @param isa      RISC-V ISA string, e.g. "rv32imc", "rv64gcv_zba_zbb_zbs_zicond_zfa_zcb"
     */
    SpikeBridge(const char* program,
                const char* isa = "rv64gcv_zba_zbb_zbs_zicond_zfa_zcb");

    ~SpikeBridge();

    // Disallow copy
    SpikeBridge(const SpikeBridge&)            = delete;
    SpikeBridge& operator=(const SpikeBridge&) = delete;

    // ── Configuration ─────────────────────────────────────────────────────
    int         get_xlen() const;
    std::string get_isa()  const;

    // ── Execution ─────────────────────────────────────────────────────────
    void step();

    // ── Register access ───────────────────────────────────────────────────
    uint64_t get_pc();
    uint64_t get_reg(int i);
    uint64_t get_fp_reg(int i);

    // ── Vector register access ────────────────────────────────────────────
    std::vector<uint8_t> get_vec_reg(int i);
    size_t get_vlen();
    size_t get_elen();

    // ── CSR access ────────────────────────────────────────────────────────
    std::map<int, uint64_t> get_csrs();

    // ── Memory access ─────────────────────────────────────────────────────
    void     dump_memory(reg_t start_addr, size_t count);
    uint32_t read_mem32(uint64_t addr);

    // ── Interrupts ────────────────────────────────────────────────────────
    void set_interrupt(bool high);

    // ── Disassembly ───────────────────────────────────────────────────────
    std::string get_disasm();

private:
    XLen        xlen_;
    std::string isa_string_;

    std::unique_ptr<cfg_t> cfg_;
    sim_t*       sim_ = nullptr;
    processor_t* cpu_ = nullptr;

    XLen   detect_xlen(const std::string& isa) const;
    bool   detect_vector_extension(const std::string& isa) const;
    void   configure_memory_layout();
    void   load_hex(const std::string& path);
};
