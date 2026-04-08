// ============================================================================
// cosim_main.cpp  –  Co-simulation entry point
// ============================================================================
//
// Usage:
//   ./cosim_tb <hex_file> <elf_base> [isa] [max_retired] [--verbose]
//
// Examples:
//   ./cosim_tb ../tests/build/test.hex ../tests/build/test rv32imc
//   ./cosim_tb ../tests/build/test.hex ../tests/build/test rv32imc 500 --verbose
//
//   hex_file     path to test.hex
//   elf_base     path prefix for SpikeBridge (no extension)
//                SpikeBridge appends .elf and .hex automatically
//   isa          RISC-V ISA string  (default: rv32imc)
//   max_retired  instruction retirement limit  (default: 100000)
//   --verbose    print every retired instruction with RTL→Spike comparison
// ============================================================================

#include "cosim.h"
#include <iostream>
#include <string>

int main(int argc, char** argv) {
    if (argc < 3) {
        std::cerr << "\nUsage: " << argv[0]
                  << " <program_file> [isa] [max_retired] [--verbose]\n\n"
                  << "  program_file path to the program file (where .elf and .hex are) (no extension)\n"
                  << "  isa          RISC-V ISA string  (default: rv32imc)\n"
                  << "  max_retired  instruction limit  (default: 100000)\n"
                  << "  --verbose    print every retired instruction\n\n";
        return 1;
    }

    CoSimConfig cfg;
    cfg.program_path = std::string(program_str(argv[1]));
    cfg.isa          = (argc >= 3) ? argv[2] : "rv32imc";

    for (int i = 3; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--verbose") {
            cfg.verbose = true;
        } else {
            try {
                cfg.max_retired = std::stoull(arg);
            } catch (...) {
                std::cerr << "[WARNING] Ignoring unrecognised argument: " << arg << "\n";
            }
        }
    }

    CoSim cosim(cfg);
    CoSimResult result = cosim.run();
    result.print_summary();

    return (result.mismatches == 0) ? 0 : 1;
}
