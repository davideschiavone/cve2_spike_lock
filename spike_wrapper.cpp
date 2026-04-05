#include <riscv/sim.h>
#include <riscv/processor.h>
#include <riscv/devices.h>
#include <pybind11/pybind11.h>
#include <vector>
#include <string>
#include <memory>

namespace py = pybind11;

class SpikeBridge {
public:
    cfg_t *cfg;
    sim_t *sim;
    processor_t *cpu;

    SpikeBridge(const char* elf_path) {
        // 1. Configurazione del core (RVA23 come richiesto)
        // Definiamo l'architettura e il set di estensioni
        const char* isa = "rv64gc_zba_zbb_zbs_v_zicond_zfa_zcb";
        
        // Creiamo l'oggetto configurazione
        cfg = new cfg_t(
            std::make_pair(0, 0), // default_init_hartids
            "MSU",                // priv (Machine, Supervisor, User)
            isa,                  // isa
            "v1.12",              // priv_spec
            "v1.0",               // varch
            false,                // misaligned
            0,                    // endianness
            1,                    // nprocs
            {mem_cfg_t(0x80000000, 0x1000000)}, // memory (16MB starting at 0x80000000)
            {elf_path},           // args (HTIF)
            false                 // real_time_clint
        );

        // 2. Inizializzazione simulatore
        // Passiamo cfg e gli altri parametri richiesti (debug_module, etc)
        sim = new sim_t(cfg, false, {}, {}, false, {elf_path}, 
                        debug_module_config_t(), nullptr, false, nullptr, false, nullptr, std::nullopt);
        
        cpu = sim->get_core(0);
    }

    // Usiamo il metodo interattivo per fare uno step, 
    // dato che sim->step(1) è privato.
    void step() {
        // Il modo corretto di avanzare di 1 istruzione via API:
        cpu->step(1);
    }

    uint64_t get_pc() {
        return cpu->get_state()->pc;
    }

    uint64_t get_reg(int i) {
        if (i < 0 || i >= 32) return 0;
        return cpu->get_state()->XPR[i];
    }

    // Metodo per iniettare l'interrupt (Machine External Interrupt)
    void set_interrupt(bool high) {
        if (high)
            cpu->get_state()->mip->write_with_mask(MIP_MEIP, MIP_MEIP);
        else
            cpu->get_state()->mip->write_with_mask(MIP_MEIP, 0);
    }

    ~SpikeBridge() {
        delete sim;
        delete cfg;
    }
};

PYBIND11_MODULE(spike_py, m) {
    py::class_<SpikeBridge>(m, "SpikeBridge")
        .def(py::init<const char*>())
        .def("step", &SpikeBridge::step)
        .def("get_pc", &SpikeBridge::get_pc)
        .def("get_reg", &SpikeBridge::get_reg)
        .def("set_interrupt", &SpikeBridge::set_interrupt);
}