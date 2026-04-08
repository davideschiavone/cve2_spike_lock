// ============================================================================
// cve2_pybind.cpp  –  Python bindings for Cve2Tb via Pybind11
// ============================================================================
//
// Compiled in two modes:
//
//   C++ object only (no Python):
//     g++ -c cve2_pybind.cpp ...
//     → CVE2_WITH_PYBIND11 is NOT defined, PYBIND11_MODULE is NOT emitted
//
//   Python extension module:
//     g++ -DCVE2_WITH_PYBIND11 -shared ... cve2_pybind.cpp -o cve2_py*.so
//     → pybind11 headers included, PYBIND11_MODULE emitted
//     (compile_cve2_py.sh passes -DCVE2_WITH_PYBIND11 automatically)
//
// Exposed Python API
// ──────────────────
//   cve2_py.RvfiInsn       – snapshot of one retired instruction
//   cve2_py.RetiredInsn    – RvfiInsn + retirement cycle timestamp
//   cve2_py.Cve2Tb         – testbench wrapper
//     ctor(hex_path, boot_addr, max_cycles, rng_seed,
//          gnt_prob_num, gnt_prob_den, max_rvalid_delay)
//     reset(cycles=8)
//     step()
//     halted()       → bool
//     cycle()        → int
//     rvfi_valid()   → bool
//     rvfi()         → RvfiInsn
//     retired_log()  → list[RetiredInsn]
//     run_to_halt()  → list[RetiredInsn]   convenience: steps until halted
//
// ============================================================================

#ifdef CVE2_WITH_PYBIND11

#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
namespace py = pybind11;

#include "cve2_tb.h"

PYBIND11_MODULE(cve2_py, m) {
    m.doc() = "CVE2 Verilated RISC-V Core Python Wrapper";

    // ── RvfiInsn ─────────────────────────────────────────────────────
    py::class_<RvfiInsn>(m, "RvfiInsn")
        .def(py::init<>())
        .def_readwrite("order",     &RvfiInsn::order)
        .def_readwrite("insn",      &RvfiInsn::insn)
        .def_readwrite("trap",      &RvfiInsn::trap)
        .def_readwrite("halt",      &RvfiInsn::halt)
        .def_readwrite("intr",      &RvfiInsn::intr)
        .def_readwrite("mode",      &RvfiInsn::mode)
        .def_readwrite("ixl",       &RvfiInsn::ixl)
        .def_readwrite("pc_rdata",  &RvfiInsn::pc_rdata)
        .def_readwrite("pc_wdata",  &RvfiInsn::pc_wdata)
        .def_readwrite("rs1_addr",  &RvfiInsn::rs1_addr)
        .def_readwrite("rs2_addr",  &RvfiInsn::rs2_addr)
        .def_readwrite("rd_addr",   &RvfiInsn::rd_addr)
        .def_readwrite("rs1_rdata", &RvfiInsn::rs1_rdata)
        .def_readwrite("rs2_rdata", &RvfiInsn::rs2_rdata)
        .def_readwrite("rd_wdata",  &RvfiInsn::rd_wdata)
        .def_readwrite("mem_addr",  &RvfiInsn::mem_addr)
        .def_readwrite("mem_rmask", &RvfiInsn::mem_rmask)
        .def_readwrite("mem_wmask", &RvfiInsn::mem_wmask)
        .def_readwrite("mem_rdata", &RvfiInsn::mem_rdata)
        .def_readwrite("mem_wdata", &RvfiInsn::mem_wdata)
        .def("__repr__", [](const RvfiInsn& r) {
            char buf[128];
            std::snprintf(buf, sizeof(buf),
                "RvfiInsn(order=%lu, pc=0x%08x, insn=0x%08x, rd=x%u:0x%08x%s)",
                (unsigned long)r.order, r.pc_rdata, r.insn,
                r.rd_addr, r.rd_wdata,
                r.trap ? ", TRAP" : "");
            return std::string(buf);
        });

    // ── RetiredInsn ──────────────────────────────────────────────────
    py::class_<RetiredInsn>(m, "RetiredInsn")
        .def(py::init<>())
        .def_readwrite("cycle", &RetiredInsn::cycle)
        .def_readwrite("rvfi",  &RetiredInsn::rvfi)
        .def("__repr__", [](const RetiredInsn& r) {
            char buf[160];
            std::snprintf(buf, sizeof(buf),
                "RetiredInsn(cycle=%lu, pc=0x%08x, insn=0x%08x, rd=x%u:0x%08x%s)",
                (unsigned long)r.cycle,
                r.rvfi.pc_rdata, r.rvfi.insn,
                r.rvfi.rd_addr, r.rvfi.rd_wdata,
                r.rvfi.trap ? ", TRAP" : "");
            return std::string(buf);
        });

    // ── Cve2Tb ───────────────────────────────────────────────────────
    py::class_<Cve2Tb>(m, "Cve2Tb")
        .def(py::init<const std::string&, uint32_t, uint64_t, uint32_t, int, int, int>(),
             py::arg("hex_path"),
             py::arg("boot_addr")        = BOOT_ADDR,
             py::arg("max_cycles")       = 1'000'000ULL,
             py::arg("rng_seed")         = 42,
             py::arg("gnt_prob_num")     = DEFAULT_GNT_PROB_NUM,
             py::arg("gnt_prob_den")     = DEFAULT_GNT_PROB_DEN,
             py::arg("max_rvalid_delay") = DEFAULT_MAX_RVALID_DELAY,
             "Construct Cve2Tb from a Verilog hex file.\n\n"
             "  gnt_prob_num/gnt_prob_den : bus grant probability (default 1/1 = always)\n"
             "  max_rvalid_delay          : extra cycles GNT→RVALID (default 0 = minimum)\n"
             "Use defaults for maximum performance; set delays to stress-test back-pressure.")

        // Simulation control
        .def("reset", &Cve2Tb::reset,
             py::arg("cycles") = 8,
             "Assert reset for `cycles` cycles then release.")
        .def("step",  &Cve2Tb::step,
             "Clock the DUT by one clock cycle (rising + falling edge).")

        // State queries
        .def("halted",     &Cve2Tb::halted,
             "True once the simulation has stopped (trap/halt/PC loop or max_cycles).")
        .def("cycle",      &Cve2Tb::cycle,
             "Current simulation cycle count.")
        .def("rvfi_valid", &Cve2Tb::rvfi_valid,
             "True if an instruction retired this cycle.")
        .def("rvfi",       &Cve2Tb::rvfi,
             py::return_value_policy::copy,
             "RVFI snapshot of the most recently retired instruction.")

        // Retirement log
        .def("retired_log", &Cve2Tb::retired_log,
             py::return_value_policy::copy,
             "List of all RetiredInsn records accumulated so far.")

        // Convenience: run until halt
        .def("run_to_halt", [](Cve2Tb& tb, uint32_t reset_cycles) {
                tb.reset(reset_cycles);
                while (!tb.halted())
                    tb.step();
                return tb.retired_log();
             },
             py::arg("reset_cycles") = 8,
             "Reset and step until halted. Returns the full retirement log.");
}

#endif // CVE2_WITH_PYBIND11
