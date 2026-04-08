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
// Bus protocol tuning knobs (see cve2_tb.cpp)
// ─────────────────────────────────────────────
//   GNT_PROB_NUM / GNT_PROB_DEN   probability of granting each cycle
//   MAX_RVALID_DELAY               max extra cycles between GNT and RVALID
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

// GNT probability per cycle = GNT_PROB_NUM / GNT_PROB_DEN
constexpr int GNT_PROB_NUM     = 1;
constexpr int GNT_PROB_DEN     = 2;

// Extra cycles on top of the mandatory 1-cycle GNT→RVALID gap
constexpr int MAX_RVALID_DELAY = 3;

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
// ============================================================================

class SlowBus {
public:
    SlowBus(const std::string& name, Cve2Memory& mem, std::mt19937& rng);

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
// Cve2Tb  –  testbench wrapper around the Verilated CVE2 model
// ============================================================================

class Cve2Tb {
public:
    explicit Cve2Tb(const std::string& hex_path,
                    uint32_t           boot_addr  = BOOT_ADDR,
                    uint64_t           max_cycles = 1'000'000ULL,
                    uint32_t           rng_seed   = 42);

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
};
