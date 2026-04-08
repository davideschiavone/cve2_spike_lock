// ============================================================================
// cve2_sim.cpp  –  Standalone CVE2 simulation entry point
// ============================================================================
//
// Run:
//   ./cve2_sim test.hex [max_cycles]
//
// Build without waveforms : make cve2_sim
// Build with VCD output   : make cve2_sim_trace
// ============================================================================

#include "cve2_tb.h"
#include <cstdlib>
#include <iostream>

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <hex_file> [max_cycles]\n";
        return 1;
    }

    const std::string hex_path   = argv[1];
    const uint64_t    max_cycles = (argc >= 3)
                                   ? std::stoull(argv[2])
                                   : 100'000ULL;

    std::cout << "==============================================\n"
              << " CVE2 Verilator Simulation\n"
              << " Program   : " << hex_path   << "\n"
              << " Max cycles: " << max_cycles << "\n"
#ifdef TRACE
              << " Trace     : cve2_wave.vcd\n"
#else
              << " Trace     : disabled (rebuild with -DTRACE)\n"
#endif
              << "==============================================\n\n";

    Cve2Tb tb(hex_path, BOOT_ADDR, max_cycles);

    std::cout << "[SIM] First 8 words at RAM base:\n";
    tb.memory().dump(RAM_BASE, 8);
    std::cout << "\n";

    tb.reset(8);

    std::printf("\n%-8s %-12s %-10s %-10s %-25s\n",
                "CYCLE", "PC", "INSN", "RD:WDATA", "FLAGS");
    std::printf("%s\n", std::string(72, '-').c_str());

    uint64_t retired = 0;

    while (!tb.halted()) {
        tb.step();

        if (tb.rvfi_valid()) {
            ++retired;
            tb.print_rvfi();
        }
    }

    std::cout << "\n==============================================\n"
              << " Simulation complete\n"
              << " Cycles  : " << tb.cycle()  << "\n"
              << " Retired : " << retired      << "\n"
              << "==============================================\n";

    return 0;
}
