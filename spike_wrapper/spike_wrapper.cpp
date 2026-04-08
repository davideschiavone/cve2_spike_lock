// ============================================================================
// spike_wrapper.cpp  –  SpikeBridge implementation
// ============================================================================
//
// Compiled in two modes:
//
//   C++ static library (cosim):
//     g++ -c spike_wrapper.cpp -o spike_wrapper.o
//     → pybind11 is NOT required, PYBIND11_MODULE is NOT emitted
//
//   Python extension module:
//     g++ -DSPIKE_WITH_PYBIND11 -shared ... spike_wrapper.cpp -o spike_py*.so
//     → pybind11 headers included, PYBIND11_MODULE emitted
//     (compile_wrapper.sh passes -DSPIKE_WITH_PYBIND11 automatically)
//
// ============================================================================

#include "spike_wrapper.h"

#ifdef SPIKE_WITH_PYBIND11
    #include <pybind11/pybind11.h>
    #include <pybind11/stl.h>
    namespace py = pybind11;
#endif

#include <iostream>
#include <iomanip>
#include <fstream>
#include <stdexcept>
#include <cstdint>

// ============================================================================
// Private helpers
// ============================================================================

XLen SpikeBridge::detect_xlen(const std::string& isa) const {
    if (isa.find("rv32") != std::string::npos || isa.find("RV32") != std::string::npos)
        return XLen::XLEN_32;
    if (isa.find("rv64") != std::string::npos || isa.find("RV64") != std::string::npos)
        return XLen::XLEN_64;
    throw std::invalid_argument(
        "[ERROR] ISA string must contain 'rv32' or 'rv64'. Got: " + isa);
}

bool SpikeBridge::detect_vector_extension(const std::string& isa) const {
    if (isa.length() < 4) return false;

    std::string lower = isa;
    for (char& c : lower) c = std::tolower(c);

    size_t pos = 0;
    if (lower.compare(0, 4, "rv32") == 0 || lower.compare(0, 4, "rv64") == 0)
        pos = 4;
    else
        return false;

    while (pos < lower.length()) {
        if (lower[pos] == '_') { ++pos; continue; }

        if (lower[pos] == 'z' || lower[pos] == 'x' || lower[pos] == 's') {
            size_t next = lower.find('_', pos);
            std::string ext = lower.substr(pos, next - pos);
            if (ext.compare(0, 3, "zve") == 0 || ext.compare(0, 3, "zvl") == 0)
                return true;
            pos = (next == std::string::npos) ? lower.length() : next;
        } else {
            if (lower[pos] == 'v') return true;
            ++pos;
        }
    }
    return false;
}

void SpikeBridge::configure_memory_layout() {
    cfg_->mem_layout = {
        mem_cfg_t(0x00001000, 0x1000),    // BootROM (4 KB)
        mem_cfg_t(0x80000000, 0x1000000)  // RAM (16 MB)
    };
}

void SpikeBridge::load_hex(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open())
        throw std::runtime_error("[ERROR] Hex file not found: " + path);

    std::string word;
    uint64_t current_addr = 0;
    auto mmu = sim_->get_core(0)->get_mmu();

    while (file >> word) {
        if (word[0] == '@') {
            current_addr = std::stoull(word.substr(1), nullptr, 16);
        } else {
            uint8_t byte_val = (uint8_t)std::stoul(word, nullptr, 16);
            mmu->store<uint8_t>(current_addr, byte_val);
            current_addr++;
        }
    }
    std::cout << "[C++] Loaded HEX: " << path << " into simulation memory.\n";
}

// ============================================================================
// Constructor / Destructor
// ============================================================================

SpikeBridge::SpikeBridge(const char* program, const char* isa) {
    try {
        std::string program_str(program);
        isa_string_ = std::string(isa);

        xlen_ = detect_xlen(isa_string_);
        std::cout << "[C++] Detected XLEN: " << static_cast<int>(xlen_) << " bits\n";
        std::cout << "[C++] ISA: " << isa_string_ << "\n";

        cfg_ = std::make_unique<cfg_t>();
        cfg_->isa = isa_string_.c_str();
        configure_memory_layout();

        auto boot_mem = std::make_shared<mem_t>(0x1000);
        auto ram_mem  = std::make_shared<mem_t>(0x1000000);

        std::vector<std::pair<reg_t, abstract_mem_t*>> mems;
        mems.push_back({ reg_t(0x00001000), boot_mem.get() });
        mems.push_back({ reg_t(0x80000000), ram_mem.get()  });

        std::string elf_path = program_str + ".elf";
        std::vector<std::string> htif_args = { elf_path };
        std::vector<std::pair<const device_factory_t*, std::vector<std::string>>> plugin_devices;

        std::cout << "[C++] Initializing sim_t with: " << elf_path << "\n";

        sim_ = new sim_t(
            cfg_.get(),
            false,
            mems,
            plugin_devices,
            false,
            htif_args,
            debug_module_config_t(),
            nullptr,
            false,
            nullptr,
            false,
            stdout,
            std::nullopt
        );

        sim_->add_device(0x00001000, boot_mem);
        sim_->add_device(0x80000000, ram_mem);

        if (detect_vector_extension(isa_string_)) {
            std::cout << "[C++] Configuring vector unit for ISA: " << isa_string_ << "\n";
            for (size_t i = 0; i < sim_->nprocs(); i++) {
                sim_->get_core(i)->VU.VLEN = 256;
                sim_->get_core(i)->VU.ELEN = 64;
            }
        }

        std::string hex_path = program_str + ".hex";
        load_hex(hex_path);

        cpu_ = sim_->get_core(0);
        auto state = cpu_->get_state();

        std::cout << "\n" << std::string(58, '=') << "\n";
        std::cout << "[DEBUG C++] Privilege CSR PMP/MMU Configuration:\n";
        std::cout << "  Privilege Mode: " << (int)state->prv << " (3=M, 1=S, 0=U)\n";

        if (state->csrmap.count(0x3A0)) {
            uint64_t cfg0 = state->csrmap[0x3A0]->read();
            std::cout << "  CSR pmpcfg0 (0x3A0): 0x" << std::hex << cfg0 << std::dec << "\n";
        }
        for (int i = 0; i < 4; i++) {
            uint64_t addr_val = state->pmpaddr[i]->read();
            std::cout << "  CSR pmpaddr" << i << ": 0x" << std::hex << addr_val << std::dec << "\n";
        }
        if (state->csrmap.count(0x180)) {
            uint64_t satp = state->csrmap[0x180]->read();
            std::cout << "  CSR satp (0x180): 0x" << std::hex << satp << std::dec
                     << " (0=Bare Mode)\n";
        }
        std::cout << std::string(58, '=') << "\n\n";

        std::cout << "[C++] Core starts at PC: 0x"
                  << std::hex << cpu_->get_state()->pc << std::dec << "\n";

    } catch (std::exception& e) {
        std::cerr << "[C++ CRITICAL ERROR]: " << e.what() << "\n";
        throw;
    } catch (...) {
        std::cerr << "[C++ CRITICAL ERROR]: Unknown error in SpikeBridge constructor!\n";
        throw;
    }
}

SpikeBridge::~SpikeBridge() {
    delete sim_;
}

// ============================================================================
// Public API
// ============================================================================

int SpikeBridge::get_xlen() const {
    return static_cast<int>(xlen_);
}

std::string SpikeBridge::get_isa() const {
    return isa_string_;
}

void SpikeBridge::step() {
    try {
        cpu_->step(1);
    } catch (trap_t& t) {
        throw std::runtime_error("Trap ID: " + std::to_string(t.cause()));
    } catch (std::exception& e) {
        throw std::runtime_error(e.what());
    }
}

std::string SpikeBridge::get_disasm() {
    uint64_t pc = cpu_->get_state()->pc;
    try {
        auto fetch = cpu_->get_mmu()->load_insn(pc);
        return cpu_->get_disassembler()->disassemble(fetch.insn);
    } catch (trap_instruction_access_fault&) {
        return "ERROR: Instruction Access Fault (PMP/MMU block)";
    } catch (...) {
        return "ERROR: Unknown Fetch Error";
    }
}

uint64_t SpikeBridge::get_pc() {
    return cpu_->get_state()->pc;
}

uint64_t SpikeBridge::get_reg(int i) {
    if (i < 0 || i >= 32) return 0;
    uint64_t val = cpu_->get_state()->XPR[i];
    if (xlen_ == XLen::XLEN_32)
        val = (int32_t)val;
    return val;
}

uint64_t SpikeBridge::get_fp_reg(int i) {
    if (i < 0 || i >= 32) return 0;
    return cpu_->get_state()->FPR[i].v[0];
}

std::vector<uint8_t> SpikeBridge::get_vec_reg(int i) {
    if (!detect_vector_extension(isa_string_))
        throw std::runtime_error("Vector extension not enabled in ISA: " + isa_string_);
    std::vector<uint8_t> reg_data;
    if (i < 0 || i >= 32 || !sim_->get_core(0)) return reg_data;

    size_t vlenb = sim_->get_core(0)->VU.vlenb;
    reg_data.resize(vlenb);
    uint8_t* ptr = (uint8_t*)sim_->get_core(0)->VU.reg_file + (i * vlenb);
    std::copy(ptr, ptr + vlenb, reg_data.begin());
    return reg_data;
}

size_t SpikeBridge::get_vlen() {
    if (!detect_vector_extension(isa_string_))
        throw std::runtime_error("Vector extension not enabled in ISA: " + isa_string_);
    if (sim_ && sim_->get_core(0))
        return sim_->get_core(0)->VU.get_vlen();
    return 0;
}

size_t SpikeBridge::get_elen() {
    if (sim_ && sim_->get_core(0))
        return sim_->get_core(0)->VU.get_elen();
    return 0;
}

void SpikeBridge::set_interrupt(bool high) {
    if (high)
        cpu_->get_state()->mip->write_with_mask(MIP_MEIP, MIP_MEIP);
    else
        cpu_->get_state()->mip->write_with_mask(MIP_MEIP, 0);
}

std::map<int, uint64_t> SpikeBridge::get_csrs() {
    std::map<int, uint64_t> snapshot;
    auto& csrmap = cpu_->get_state()->csrmap;
    for (auto const& [addr, csr_ptr] : csrmap) {
        try {
            uint64_t val = csr_ptr->read();
            if (xlen_ == XLen::XLEN_32)
                val = (uint32_t)val;
            snapshot[addr] = val;
        } catch (...) {}
    }
    return snapshot;
}

void SpikeBridge::dump_memory(reg_t start_addr, size_t count) {
    auto mmu = sim_->get_core(0)->get_mmu();
    std::cout << std::string(58, '=') << "\n";
    std::cout << "[DEBUG C++] Dump memory from 0x" << std::hex << start_addr
              << " (" << std::dec << count << " 32-bit words):\n";
    for (size_t i = 0; i < count; i++) {
        reg_t addr = start_addr + (i * 4);
        try {
            uint32_t val = mmu->load<uint32_t>(addr);
            printf("  0x%08lx:  %08x\n", (unsigned long)addr, val);
        } catch (trap_t& t) {
            printf("  0x%08lx:  [ERROR] Trap: %s\n", (unsigned long)addr, t.name());
        } catch (...) {
            printf("  0x%08lx:  [ERROR] Access failed\n", (unsigned long)addr);
        }
    }
    std::cout << std::string(58, '=') << "\n\n";
}

uint32_t SpikeBridge::read_mem32(uint64_t addr) {
    try {
        return sim_->get_core(0)->get_mmu()->load<uint32_t>(addr);
    } catch (trap_t& t) {
        throw std::runtime_error(
            "[SpikeBridge::read_mem32] MMU trap at 0x" +
            std::to_string(addr) + " — " + t.name());
    } catch (...) {
        throw std::runtime_error(
            "[SpikeBridge::read_mem32] Unknown access fault at 0x" +
            std::to_string(addr));
    }
}

// ============================================================================
// Pybind11 module  –  only compiled when -DSPIKE_WITH_PYBIND11 is set
// ============================================================================

#ifdef SPIKE_WITH_PYBIND11

PYBIND11_MODULE(spike_py, m) {
    m.doc() = "RISC-V Spike Simulator Python Wrapper (32-bit and 64-bit support)";

    py::enum_<XLen>(m, "XLen")
        .value("XLEN_32", XLen::XLEN_32)
        .value("XLEN_64", XLen::XLEN_64);

    py::class_<SpikeBridge>(m, "SpikeBridge")
        .def(py::init<const char*, const char*>(),
             py::arg("program"),
             py::arg("isa") = "rv64gcv_zba_zbb_zbs_zicond_zfa_zcb",
             "Construct SpikeBridge for a given program and ISA")

        // Configuration queries
        .def("get_xlen",    &SpikeBridge::get_xlen,  "Get register width (32 or 64 bits)")
        .def("get_isa",     &SpikeBridge::get_isa,   "Get ISA configuration string")

        // Execution control
        .def("step",        &SpikeBridge::step,      "Execute one instruction")

        // Register access (XLEN-aware)
        .def("get_pc",      &SpikeBridge::get_pc,    "Get Program Counter")
        .def("get_reg",     &SpikeBridge::get_reg,    py::arg("index"), "Get General Purpose Register")
        .def("get_fp_reg",  &SpikeBridge::get_fp_reg, py::arg("index"), "Get Floating Point Register")

        // Vector register access
        .def("get_vec_reg", &SpikeBridge::get_vec_reg, py::arg("index"), "Get Vector Register as byte array")
        .def("get_vlen",    &SpikeBridge::get_vlen,    "Get Vector Length in bits")
        .def("get_elen",    &SpikeBridge::get_elen,    "Get Element Length in bits")

        // Disassembly and CSR state
        .def("get_disasm",  &SpikeBridge::get_disasm, "Get disassembly of instruction at current PC")
        .def("get_csrs",    &SpikeBridge::get_csrs,   "Get all active Control and Status Registers")

        // Debugging utilities
        .def("dump_memory", &SpikeBridge::dump_memory,
             py::arg("addr"), py::arg("count"),
             "Dump n 32-bit words starting from addr")
        .def("set_interrupt", &SpikeBridge::set_interrupt, py::arg("high"),
             "Set/clear machine external interrupt")

        // Co-simulation memory access
        .def("read_mem32",  &SpikeBridge::read_mem32, py::arg("addr"),
             "Read a 32-bit word from Spike simulation memory (used by cosim)");
}

#endif // SPIKE_WITH_PYBIND11
