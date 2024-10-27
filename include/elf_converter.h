#ifndef ELF_CONVERTER_H
#define ELF_CONVERTER_H

#include <elf_section.h>
#include <capstone/capstone.h>
#include <keystone/keystone.h>

using capstone_handle = csh;

class elf_converter {
private:
    capstone_handle handle;
    ks_engine *engine;
    
public:
    elf_converter();
    ~elf_converter();
    elf_converter(const elf_converter &other) = delete;
    void operator=(const elf_converter &other) = delete;
    void convert_functions(std::vector<function_conversion_payload> &payloads) const;
    void convert_function(function_conversion_payload &payload) const;
};

#endif // ELF_CONVERTER_H
