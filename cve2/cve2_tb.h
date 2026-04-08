// ============================================================================
// cve2_tb.h  –  Declarations for Cve2Memory, SlowBus, Cve2Tb
// ============================================================================
//
// This header exposes the public interface of the CVE2 Verilator testbench.
// All method implementations live in cve2_tb.cpp.
//
// Memory map (must match linker script / Spike config)
// ─────────────────────────────────────────────────────
//   0x0000_1000  Boot ROM   4 KB
//   0x8000_0000  RAM       16 MB
//
// Bus protocol tuning knobs
// ─────────────────────────────────────────────────────
//   gnt_prob_num / gnt_prob_den   probability of granting each cycle
//                                 (default 1/1 → always grant immediately)
//   max_rvalid_delay               max extra cycles between GNT and RVALID
//                                 (default 0 → RVALID exactly 1 cycle after GNT)
//
// The legacy compile-time constants GNT_PROB_NUM, GNT_PROB_DEN and
// MAX_RVALID_DELAY are kept as fallback defaults when no runtime value
// is supplied.
//
// ============================================================================

#pragma once

#include <cstdint>
#include <memory>
#include <queue>
#include <random>
#include <string>

#include "Vcve2_top.h"
#include "verilated.h"

#ifdef TRACE
#  include "verilated_vcd_c.h"
#endif

// ============================================================================
// Memory configuration constants
// ============================================================================

constexpr uint32_t BOOT_BASE = 0x0000'1000u;
constexpr uint32_t BOOT_SIZE = 0x0000'1000u;   //  4 KB
constexpr uint32_t RAM_BASE  = 0x8000'0000u;
constexpr uint32_t RAM_SIZE  = 0x0100'0000u;   // 16 MB
constexpr uint32_t BOOT_ADDR = BOOT_BASE;

constexpr uint8_t FETCH_ENABLE_ON = 0x1u;

// Default bus timing constants (used only when runtime values are not provided)
constexpr int DEFAULT_GNT_PROB_NUM     = 1;    // always grant
constexpr int DEFAULT_GNT_PROB_DEN     = 1;    // (1/1 = 100%)
constexpr int DEFAULT_MAX_RVALID_DELAY = 0;    // RVALID 1 cycle after GNT (minimum)

// Legacy aliases kept for backward compatibility (cosim overrides these at runtime)
constexpr int GNT_PROB_NUM     = DEFAULT_GNT_PROB_NUM;
constexpr int GNT_PROB_DEN     = DEFAULT_GNT_PROB_DEN;
constexpr int MAX_RVALID_DELAY = DEFAULT_MAX_RVALID_DELAY;

// ============================================================================
// vlwide_zero  –  zero a Verilator VlWide<N> packed-struct signal
// ============================================================================

template <std::size_t N>
inline void vlwide_zero(VlWide<N>& w) {
    for (std::size_t i = 0; i < N; ++i)
        w[i] = 0;
}

// ============================================================================
// Cve2Memory  –  flat byte-addressed memory (Boot ROM + RAM)
// ============================================================================

class Cve2Memory {
public:
    Cve2Memory();

    Cve2Memory(const Cve2Memory&)            = delete;
    Cve2Memory& operator=(const Cve2Memory&) = delete;
    Cve2Memory(Cve2Memory&&) noexcept            = default;
    Cve2Memory& operator=(Cve2Memory&&) noexcept = default;
    ~Cve2Memory() = default;

    void     load_hex(const std::string& path);
    uint32_t read32(uint32_t addr) const;
    void     write32(uint32_t addr, uint32_t data, uint8_t be);
    uint8_t  read8(uint32_t addr) const;
    void     write8(uint32_t addr, uint8_t val);
    void     dump(uint32_t addr, uint32_t n_words) const;

    uint8_t*       boot_data();
    uint8_t*       ram_data();
    const uint8_t* boot_data() const;
    const uint8_t* ram_data()  const;

    static constexpr uint32_t boot_size() { return BOOT_SIZE; }
    static constexpr uint32_t ram_size()  { return RAM_SIZE;  }

private:
    std::unique_ptr<uint8_t[]> boot_;
    std::unique_ptr<uint8_t[]> ram_;
};

// ============================================================================
// RvfiInsn  –  snapshot of one retired instruction's RVFI outputs
// ============================================================================

struct RvfiInsn {
    uint64_t order      = 0;
    uint32_t insn       = 0;
    uint8_t  trap       = 0;
    uint8_t  halt       = 0;
    uint8_t  intr       = 0;
    uint8_t  mode       = 0;
    uint8_t  ixl        = 0;
    uint32_t pc_rdata   = 0;
    uint32_t pc_wdata   = 0;
    uint8_t  rs1_addr   = 0;
    uint8_t  rs2_addr   = 0;
    uint8_t  rd_addr    = 0;
    uint32_t rs1_rdata  = 0;
    uint32_t rs2_rdata  = 0;
    uint32_t rd_wdata   = 0;
    uint32_t mem_addr   = 0;
    uint8_t  mem_rmask  = 0;
    uint8_t  mem_wmask  = 0;
    uint32_t mem_rdata  = 0;
    uint32_t mem_wdata  = 0;
};

// ============================================================================
// RvalidEntry  –  one pending RVALID event in the bus pipeline
// ============================================================================

struct RvalidEntry {
    int      countdown = 1;
    uint32_t rdata     = 0;
};

// ============================================================================
// SlowBus  –  randomised GNT / RVALID OBI-like bus model
//
// gnt_prob_num / gnt_prob_den  – probability that GNT is asserted each cycle.
//   Setting both to the same value (e.g. 1/1) means always grant immediately.
// max_rvalid_delay – extra cycles added on top of the mandatory 1-cycle
//   GNT→RVALID gap.  0 means RVALID arrives exactly 1 cycle after GNT.
// ============================================================================

class SlowBus {
public:
    SlowBus(const std::string& name,
            Cve2Memory&        mem,
            std::mt19937&      rng,
            int                gnt_prob_num     = DEFAULT_GNT_PROB_NUM,
            int                gnt_prob_den     = DEFAULT_GNT_PROB_DEN,
            int                max_rvalid_delay = DEFAULT_MAX_RVALID_DELAY);

    void tick(uint8_t   req_i,
              uint32_t  addr_i,
              uint8_t   we_i,
              uint8_t   be_i,
              uint32_t  wdata_i,
              uint8_t&  gnt_o,
              uint8_t&  rvalid_o,
              uint32_t& rdata_o,
              uint8_t&  err_o);

    void reset();

private:
    std::string    name_;
    Cve2Memory&    mem_;
    std::mt19937&  rng_;

    int gnt_prob_num_;
    int gnt_prob_den_;
    int max_rvalid_delay_;

    std::uniform_int_distribution<int> gnt_dist_;
    std::uniform_int_distribution<int> delay_dist_;

    std::queue<RvalidEntry> rvalid_fifo_;

    bool     req_pending_   = false;
    uint32_t pending_addr_  = 0;
    bool     pending_we_    = false;
    uint8_t  pending_be_    = 0;
    uint32_t pending_wdata_ = 0;
};

// ============================================================================
// RetiredInsn  –  record of one retired instruction with cycle timestamp
// ============================================================================

struct RetiredInsn {
    uint64_t cycle      = 0;   // cycle at which this instruction retired
    RvfiInsn rvfi       = {};
};

// ============================================================================
// Cve2Tb  –  testbench wrapper around the Verilated CVE2 model
//
// gnt_prob_num / gnt_prob_den  – bus grant probability (default 1/1 = 100%)
// max_rvalid_delay             – max extra cycles GNT→RVALID (default 0)
// ============================================================================

class Cve2Tb {
public:
    explicit Cve2Tb(const std::string& hex_path,
                    uint32_t           boot_addr        = BOOT_ADDR,
                    uint64_t           max_cycles       = 1'000'000ULL,
                    uint32_t           rng_seed         = 42,
                    int                gnt_prob_num     = DEFAULT_GNT_PROB_NUM,
                    int                gnt_prob_den     = DEFAULT_GNT_PROB_DEN,
                    int                max_rvalid_delay = DEFAULT_MAX_RVALID_DELAY);

    ~Cve2Tb();

    // Disallow copy
    Cve2Tb(const Cve2Tb&)            = delete;
    Cve2Tb& operator=(const Cve2Tb&) = delete;

    void reset(uint32_t cycles = 8);
    void step();

    bool              halted()     const;
    uint64_t          cycle()      const;
    bool              rvfi_valid() const;
    const RvfiInsn&   rvfi()       const;
    Cve2Memory&       memory();
    const Cve2Memory& memory()     const;

    // Retirement log (populated automatically during step())
    const std::vector<RetiredInsn>& retired_log() const;

    void print_rvfi() const;

private:
    void init_inputs();
    void raw_tick();
    void capture_rvfi();

    std::unique_ptr<VerilatedContext> ctx_;
    std::unique_ptr<Vcve2_top>        dut_;
#ifdef TRACE
    std::unique_ptr<VerilatedVcdC>    tfp_;
#endif
    Cve2Memory   mem_;
    uint32_t     boot_addr_;
    uint64_t     max_cycles_;
    uint64_t     cycle_      = 0;
    bool         halted_     = false;
    bool         rvfi_valid_ = false;
    RvfiInsn     rvfi_       = {};

    std::mt19937 rng_;
    SlowBus      instr_bus_;
    SlowBus      data_bus_;

    std::vector<RetiredInsn> retired_log_;
};
