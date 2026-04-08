// ============================================================================
// cve2_tb.cpp  –  Implementations for Cve2Memory, SlowBus, Cve2Tb
// ============================================================================
//
// Build without waveforms:
//   see makefile → `make cve2_tb`
//
// Build with VCD waveform output:
//   see makefile → `make cve2_tb_trace`
//
// The simulation entry point (main) lives in cve2_sim.cpp.
// ============================================================================

#include "cve2_tb.h"

#include <cstring>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <cstdio>
#include <string>

// ============================================================================
// Cve2Memory
// ============================================================================

Cve2Memory::Cve2Memory()
    : boot_(std::make_unique<uint8_t[]>(BOOT_SIZE)),
      ram_ (std::make_unique<uint8_t[]>(RAM_SIZE))
{
    std::memset(boot_.get(), 0, BOOT_SIZE);
    std::memset(ram_.get(),  0, RAM_SIZE);
}

void Cve2Memory::load_hex(const std::string& path) {
    std::ifstream f(path);
    if (!f.is_open())
        throw std::runtime_error("[Cve2Memory] Cannot open: " + path);
    std::string tok;
    uint64_t addr = 0;
    while (f >> tok) {
        if (tok[0] == '@')
            addr = std::stoull(tok.substr(1), nullptr, 16);
        else
            write8(static_cast<uint32_t>(addr++),
                   static_cast<uint8_t>(std::stoul(tok, nullptr, 16)));
    }
    std::cout << "[Cve2Memory] Loaded: " << path << "\n";
}

uint32_t Cve2Memory::read32(uint32_t addr) const {
    return  static_cast<uint32_t>(read8(addr + 0))        |
           (static_cast<uint32_t>(read8(addr + 1)) <<  8) |
           (static_cast<uint32_t>(read8(addr + 2)) << 16) |
           (static_cast<uint32_t>(read8(addr + 3)) << 24);
}

void Cve2Memory::write32(uint32_t addr, uint32_t data, uint8_t be) {
    if (be & 0x1) write8(addr + 0, (data >>  0) & 0xFF);
    if (be & 0x2) write8(addr + 1, (data >>  8) & 0xFF);
    if (be & 0x4) write8(addr + 2, (data >> 16) & 0xFF);
    if (be & 0x8) write8(addr + 3, (data >> 24) & 0xFF);
}

uint8_t Cve2Memory::read8(uint32_t addr) const {
    if (addr >= BOOT_BASE && addr < BOOT_BASE + BOOT_SIZE)
        return boot_[addr - BOOT_BASE];
    if (addr >= RAM_BASE  && addr < RAM_BASE  + RAM_SIZE)
        return ram_[addr - RAM_BASE];
    return 0x00;
}

void Cve2Memory::write8(uint32_t addr, uint8_t val) {
    if (addr >= BOOT_BASE && addr < BOOT_BASE + BOOT_SIZE)
        boot_[addr - BOOT_BASE] = val;
    else if (addr >= RAM_BASE && addr < RAM_BASE + RAM_SIZE)
        ram_[addr - RAM_BASE] = val;
}

void Cve2Memory::dump(uint32_t addr, uint32_t n_words) const {
    for (uint32_t i = 0; i < n_words; ++i)
        std::printf("  0x%08x : 0x%08x\n", addr + i*4, read32(addr + i*4));
}

uint8_t*       Cve2Memory::boot_data()       { return boot_.get(); }
uint8_t*       Cve2Memory::ram_data()        { return ram_.get();  }
const uint8_t* Cve2Memory::boot_data() const { return boot_.get(); }
const uint8_t* Cve2Memory::ram_data()  const { return ram_.get();  }

// ============================================================================
// SlowBus
// ============================================================================

SlowBus::SlowBus(const std::string& name,
                 Cve2Memory&        mem,
                 std::mt19937&      rng,
                 int                gnt_prob_num,
                 int                gnt_prob_den,
                 int                max_rvalid_delay)
    : name_            (name)
    , mem_             (mem)
    , rng_             (rng)
    , gnt_prob_num_    (gnt_prob_num)
    , gnt_prob_den_    (gnt_prob_den)
    , max_rvalid_delay_(max_rvalid_delay)
    , gnt_dist_        (0, std::max(1, gnt_prob_den) - 1)
    , delay_dist_      (0, std::max(0, max_rvalid_delay))
{}

void SlowBus::tick(uint8_t   req_i,
                   uint32_t  addr_i,
                   uint8_t   we_i,
                   uint8_t   be_i,
                   uint32_t  wdata_i,
                   uint8_t&  gnt_o,
                   uint8_t&  rvalid_o,
                   uint32_t& rdata_o,
                   uint8_t&  err_o)
{
    // ── A: advance the RVALID pipeline ──────────────────────────────
    rvalid_o = 0;
    rdata_o  = 0;
    err_o    = 0;

    if (!rvalid_fifo_.empty()) {
        auto& head = rvalid_fifo_.front();
        head.countdown--;
        if (head.countdown == 0) {
            rvalid_o = 1;
            rdata_o  = head.rdata;
            rvalid_fifo_.pop();
        }
    }

    // ── B: capture new request ───────────────────────────────────────
    if (req_i && !req_pending_) {
        req_pending_   = true;
        pending_addr_  = addr_i;
        pending_we_    = static_cast<bool>(we_i);
        pending_be_    = be_i;
        pending_wdata_ = wdata_i;
    }

    // ── C: attempt to grant ──────────────────────────────────────────
    gnt_o = 0;

    // When gnt_prob_num_ >= gnt_prob_den_ always grant (handles 0-delay case)
    bool do_grant = (gnt_prob_num_ >= gnt_prob_den_) ||
                    (gnt_dist_(rng_) < gnt_prob_num_);

    if (req_pending_ && do_grant) {
        if (pending_we_)
            mem_.write32(pending_addr_, pending_wdata_, pending_be_);

        uint32_t rdata = pending_we_ ? 0u : mem_.read32(pending_addr_);

        // extra_delay = 0 when max_rvalid_delay_ == 0 (no randomness needed)
        int extra_delay = (max_rvalid_delay_ > 0) ? delay_dist_(rng_) : 0;
        rvalid_fifo_.push({ 1 + extra_delay, rdata });

        gnt_o        = 1;
        req_pending_ = false;
    }
}

void SlowBus::reset() {
    rvalid_fifo_   = {};
    req_pending_   = false;
    pending_addr_  = 0;
    pending_we_    = false;
    pending_be_    = 0;
    pending_wdata_ = 0;
}

// ============================================================================
// Cve2Tb
// ============================================================================

Cve2Tb::Cve2Tb(const std::string& hex_path,
               uint32_t           boot_addr,
               uint64_t           max_cycles,
               uint32_t           rng_seed,
               int                gnt_prob_num,
               int                gnt_prob_den,
               int                max_rvalid_delay)
    : boot_addr_ (boot_addr)
    , max_cycles_(max_cycles)
    , rng_       (rng_seed)
    , instr_bus_ ("INSTR", mem_, rng_, gnt_prob_num, gnt_prob_den, max_rvalid_delay)
    , data_bus_  ("DATA",  mem_, rng_, gnt_prob_num, gnt_prob_den, max_rvalid_delay)
{
    ctx_ = std::make_unique<VerilatedContext>();
    dut_ = std::make_unique<Vcve2_top>(ctx_.get(), "TOP");

#ifdef TRACE
    ctx_->traceEverOn(true);
    tfp_ = std::make_unique<VerilatedVcdC>();
    dut_->trace(tfp_.get(), 99);
    tfp_->open("cve2_wave.vcd");
    std::cout << "[Cve2Tb] VCD tracing → cve2_wave.vcd\n";
#endif

    mem_.load_hex(hex_path);
    init_inputs();

    std::cout << "[Cve2Tb] Boot addr        : 0x"
              << std::hex << boot_addr_ << std::dec << "\n";
    std::cout << "[Cve2Tb] RNG seed          : " << rng_seed          << "\n";
    std::cout << "[Cve2Tb] GNT probability   : "
              << gnt_prob_num << "/" << gnt_prob_den << "\n";
    std::cout << "[Cve2Tb] Max RVALID delay  : +"
              << max_rvalid_delay << " cycles (on top of mandatory 1)\n";
}

Cve2Tb::~Cve2Tb() {
    dut_->final();
#ifdef TRACE
    if (tfp_) tfp_->close();
#endif
}

void Cve2Tb::reset(uint32_t cycles) {
    dut_->rst_ni = 0;
    for (uint32_t i = 0; i < cycles; ++i)
        raw_tick();
    dut_->rst_ni = 1;
    instr_bus_.reset();
    data_bus_.reset();
    std::cout << "[Cve2Tb] Reset released after " << cycles << " cycles.\n";
}

void Cve2Tb::step() {
    if (halted_) return;

    // ── Rising edge ───────────────────────────────────────────────────
    dut_->clk_i = 1;
    dut_->eval();
    ctx_->timeInc(1);
#ifdef TRACE
    tfp_->dump(ctx_->time());
#endif
    capture_rvfi();

    // ── Falling edge ──────────────────────────────────────────────────
    dut_->clk_i = 0;

    {
        uint8_t gnt, rvalid, err;
        uint32_t rdata;
        instr_bus_.tick(
            dut_->instr_req_o, dut_->instr_addr_o,
            /*we=*/0, /*be=*/0xF, /*wdata=*/0,
            gnt, rvalid, rdata, err);
        dut_->instr_gnt_i    = gnt;
        dut_->instr_rvalid_i = rvalid;
        dut_->instr_rdata_i  = rdata;
        dut_->instr_err_i    = err;
    }
    {
        uint8_t gnt, rvalid, err;
        uint32_t rdata;
        data_bus_.tick(
            dut_->data_req_o,  dut_->data_addr_o,
            dut_->data_we_o,   dut_->data_be_o,  dut_->data_wdata_o,
            gnt, rvalid, rdata, err);
        dut_->data_gnt_i    = gnt;
        dut_->data_rvalid_i = rvalid;
        dut_->data_rdata_i  = rdata;
        dut_->data_err_i    = err;
    }

    dut_->eval();
    ctx_->timeInc(1);
#ifdef TRACE
    tfp_->dump(ctx_->time());
#endif

    ++cycle_;
    if (cycle_ >= max_cycles_) {
        std::cerr << "[Cve2Tb] Max cycles reached.\n";
        halted_ = true;
    }
}

bool              Cve2Tb::halted()     const { return halted_;     }
uint64_t          Cve2Tb::cycle()      const { return cycle_;      }
bool              Cve2Tb::rvfi_valid() const { return rvfi_valid_; }
const RvfiInsn&   Cve2Tb::rvfi()       const { return rvfi_;       }
Cve2Memory&       Cve2Tb::memory()           { return mem_;        }
const Cve2Memory& Cve2Tb::memory()     const { return mem_;        }

const std::vector<RetiredInsn>& Cve2Tb::retired_log() const {
    return retired_log_;
}

void Cve2Tb::print_rvfi() const {
    if (!rvfi_valid_) return;
    const auto& r = rvfi_;
    std::printf(
        "[RVFI] #%-6lu  PC=0x%08x  insn=0x%08x"
        "  rd=x%02u:0x%08x"
        "  rs1=x%02u:0x%08x  rs2=x%02u:0x%08x%s\n",
        (unsigned long)r.order,
        r.pc_rdata, r.insn,
        r.rd_addr,  r.rd_wdata,
        r.rs1_addr, r.rs1_rdata,
        r.rs2_addr, r.rs2_rdata,
        r.trap ? "  [TRAP]" : "");
    if (r.mem_rmask || r.mem_wmask)
        std::printf(
            "               MEM[0x%08x]"
            "  rmask=0x%x wmask=0x%x"
            "  rdata=0x%08x wdata=0x%08x\n",
            r.mem_addr,
            r.mem_rmask, r.mem_wmask,
            r.mem_rdata, r.mem_wdata);
}

// ── Private helpers ────────────────────────────────────────────────────────

void Cve2Tb::init_inputs() {
    dut_->clk_i       = 0;
    dut_->rst_ni      = 0;
    dut_->test_en_i   = 0;
    dut_->ram_cfg_i   = 0;
    dut_->hart_id_i   = 0;
    dut_->boot_addr_i = boot_addr_;

    dut_->instr_gnt_i    = 0;
    dut_->instr_rvalid_i = 0;
    dut_->instr_rdata_i  = 0;
    dut_->instr_err_i    = 0;

    dut_->data_gnt_i    = 0;
    dut_->data_rvalid_i = 0;
    dut_->data_rdata_i  = 0;
    dut_->data_err_i    = 0;

    dut_->x_issue_ready_i  = 0;
    dut_->x_issue_resp_i   = 0;
    dut_->x_result_valid_i = 0;
    vlwide_zero(dut_->x_result_i);

    dut_->irq_software_i = 0;
    dut_->irq_timer_i    = 0;
    dut_->irq_external_i = 0;
    dut_->irq_fast_i     = 0;
    dut_->irq_nm_i       = 0;

    dut_->debug_req_i         = 0;
    dut_->dm_halt_addr_i      = 0;
    dut_->dm_exception_addr_i = 0;

    dut_->fetch_enable_i = FETCH_ENABLE_ON;

    dut_->eval();
}

void Cve2Tb::raw_tick() {
    dut_->clk_i = 1; dut_->eval(); ctx_->timeInc(1);
#ifdef TRACE
    tfp_->dump(ctx_->time());
#endif
    dut_->clk_i = 0; dut_->eval(); ctx_->timeInc(1);
#ifdef TRACE
    tfp_->dump(ctx_->time());
#endif
    ++cycle_;
}

void Cve2Tb::capture_rvfi() {
    rvfi_valid_ = static_cast<bool>(dut_->rvfi_valid);
    if (!rvfi_valid_) return;

    rvfi_.order     = dut_->rvfi_order;
    rvfi_.insn      = dut_->rvfi_insn;
    rvfi_.trap      = dut_->rvfi_trap;
    rvfi_.halt      = dut_->rvfi_halt;
    rvfi_.intr      = dut_->rvfi_intr;
    rvfi_.mode      = dut_->rvfi_mode;
    rvfi_.ixl       = dut_->rvfi_ixl;
    rvfi_.pc_rdata  = dut_->rvfi_pc_rdata;
    rvfi_.pc_wdata  = dut_->rvfi_pc_wdata;
    rvfi_.rs1_addr  = dut_->rvfi_rs1_addr;
    rvfi_.rs2_addr  = dut_->rvfi_rs2_addr;
    rvfi_.rs1_rdata = dut_->rvfi_rs1_rdata;
    rvfi_.rs2_rdata = dut_->rvfi_rs2_rdata;
    rvfi_.rd_addr   = dut_->rvfi_rd_addr;
    rvfi_.rd_wdata  = dut_->rvfi_rd_wdata;
    rvfi_.mem_addr  = dut_->rvfi_mem_addr;
    rvfi_.mem_rmask = dut_->rvfi_mem_rmask;
    rvfi_.mem_wmask = dut_->rvfi_mem_wmask;
    rvfi_.mem_rdata = dut_->rvfi_mem_rdata;
    rvfi_.mem_wdata = dut_->rvfi_mem_wdata;

    // Record in the retirement log with current cycle timestamp
    retired_log_.push_back({ cycle_, rvfi_ });

    if (rvfi_.trap || rvfi_.halt ||
        rvfi_.pc_wdata == rvfi_.pc_rdata)
        halted_ = true;
}
