// ============================================================================
// cosim.cpp  –  Co-simulation entry point
// ============================================================================
//
// Usage:
//   ./cosim_tb <hex_file> <elf_base> [isa] [max_retired] [--verbose]
//
// Examples:
//   ./cosim_tb ../test.hex ../test rv32imc
//   ./cosim_tb ../test.hex ../test rv32imc 500 --verbose
//
// ============================================================================

#include "cosim.h"
#include <iostream>
#include <string>
#include <cstdlib>

int main(int argc, char** argv) {
    if (argc < 3) {
        std::cerr << "\nUsage: " << argv[0]
                  << " <hex_file> <elf_base> [isa] [max_retired] [--verbose]\n\n"
                  << "  hex_file     path to test.hex\n"
                  << "  elf_base     path prefix for SpikeBridge, e.g. '../test'\n"
                  << "               (SpikeBridge appends .elf/.hex automatically)\n"
                  << "  isa          RISC-V ISA string  (default: rv32imc)\n"
                  << "  max_retired  instruction limit  (default: 100000)\n"
                  << "  --verbose    print every retired instruction\n\n";
        return 1;
    }

    CoSimConfig cfg;
    cfg.hex_path = argv[1];
    cfg.elf_path = argv[2];
    cfg.isa      = (argc >= 4) ? argv[3] : "rv32imc";

    for (int i = 4; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--verbose")
            cfg.verbose = true;
        else {
            try { cfg.max_retired = std::stoull(arg); }
            catch (...) {
                std::cerr << "[WARNING] Ignoring unrecognised argument: " << arg << "\n";
            }
        }
    }

    CoSim cosim(cfg);
    CoSimResult result = cosim.run();
    result.print_summary();

    return (result.mismatches == 0) ? 0 : 1;
}
