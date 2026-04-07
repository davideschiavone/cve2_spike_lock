#!/bin/bash

# Configuration
TOP_MODULE="cve2_top_tracing"
VC_FILE="cve2.vc"
CPP_WRAPPER="sim_main.cpp" # Your C++ testbench
EXE_NAME="Vtop_sim"

echo "--- Verilating Design ---"
# -cc: Generate C++ output
# --exe: Generate an executable
# --build: Automatically run make after verilating (Verilator 4.200+)
# -f: Read command line arguments/files from the .vc file
# --top-module: Specify the top level
verilator -Wall -cc\
          --trace \
          --trace-structs \
          --trace-underscore \
          --trace-max-array 1024 \
          -f $VC_FILE \
          --top-module $TOP_MODULE \
          --build

if [ $? -eq 0 ]; then
    echo "--- Build Successful: ./obj_dir/$EXE_NAME ---"
else
    echo "--- Build Failed ---"
    exit 1
fi