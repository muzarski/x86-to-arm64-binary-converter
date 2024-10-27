
# Converter

A converter of x86-64 `ET_REL` binary files to ARM64.

This is an [assignment](https://students.mimuw.edu.pl/ZSO/PUBLIC-SO/2022-2023/z1_elf/index.html) from MIMUW, Advanced Operating Systems class.

## Building and Compilation
First, install the necessary tools and libraries. To do this, run the script:
```
sudo ./install_dependencies.sh
```
This should install `cmake` and the `capstone` and `libstone` libraries to the system.

Now you can build the project:
```
mkdir build
cd build
cmake ..
make
```

If the linker complains about the missing `keystone` library, update the `/etc/ld.so.conf` file and add the path `/usr/local/bin` to it. Then run:
```
sudo ldconfig
```

## Solution Description
The project consists of 4 main files. Here is a brief description of each one.

### `elf_section.cpp`
Contains the implementation of classes representing sections in an ELF file. Specifically, it implements sections crucial for the task, such as relocation sections, symbol sections, string sections, etc.

### `elf_file.cpp`
The `elf_file` class allows manipulation of the ELF file content (header, sections) needed for conversion. It provides a basic API for conversion.

### `elf_converter.cpp`
Implementation of the conversion of functions contained in the ELF file. It takes the payload prepared by `elf_file` required for the conversion. It uses the Capstone library for disassembling the input code and the Keystone library for assembling the code produced by instructions from `x86_instruction.cpp`.

### `x86_instruction.cpp`
Implementation of classes representing individual x86 instructions to be converted. Each instruction provides a `convert_to_aarch64` function, which returns a string corresponding to the ARM instructions.
