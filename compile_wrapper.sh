g++ -O3 -shared -std=c++20 -fPIC \
    $(python3 -m pybind11 --includes) \
    -I/home/$USER/tools/spike/include \
    spike_wrapper.cpp \
    -L/home/$USER/tools/spike/lib \
    -Wl,-rpath,/home/$USER/tools/spike/lib \
    -o spike_py$(python3-config --extension-suffix) \
    -lriscv -lfesvr
