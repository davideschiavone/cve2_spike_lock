#include <riscv/sim.h>
#include <riscv/processor.h>
#include <riscv/devices.h>
#include <riscv/cfg.h>
#include <pybind11/pybind11.h>
#include <vector>
#include <string>
#include <memory>

namespace py = pybind11;

class SpikeBridge {
public:
    std::unique_ptr<cfg_t> cfg;
    sim_t *sim;
    processor_t *cpu;

    SpikeBridge(const char* elf_path) {
        // 1. Inizializziamo cfg con i valori di default
        cfg = std::make_unique<cfg_t>();

        // 2. Impostiamo l'ISA RVA23
        // In molte versioni recenti, 'isa' è una stringa pubblica o settabile
        cfg->isa = "rv64gc_zba_zbb_zbs_v_zicond_zfa_zcb";
        
        // Impostiamo il layout di memoria
        cfg->mem_layout = {mem_cfg_t(0x80000000, 0x1000000)};
        
        // Specifichiamo il file ELF per l'interfaccia Host-Target (HTIF)
        std::vector<std::string> htif_args = {elf_path};

        // 3. Creiamo il simulatore
        // Passiamo cfg.get() perché sim_t vuole un puntatore a cfg_t
        sim = new sim_t(cfg.get(), false, {}, {}, false, htif_args, 
                        debug_module_config_t(), nullptr, false, nullptr, false, nullptr, std::nullopt);
        
        cpu = sim->get_core(0);
    }

    void step() {
        cpu->step(1);
    }

    uint64_t get_pc() {
        return cpu->get_state()->pc;
    }

    uint64_t get_reg(int i) {
        if (i < 0 || i >= 32) return 0;
        return cpu->get_state()->XPR[i];
    }

    void set_interrupt(bool high) {
        if (high)
            cpu->get_state()->mip->write_with_mask(MIP_MEIP, MIP_MEIP);
        else
            cpu->get_state()->mip->write_with_mask(MIP_MEIP, 0);
    }

    ~SpikeBridge() {
        delete sim;
        // cfg viene eliminato automaticamente da unique_ptr
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