#include <iostream>
#include <map>
#include <algorithm>

#include <elf_converter.h>
#include <x86_instruction.h>


elf_converter::elf_converter() : handle(0), engine(nullptr) {
    cs_err _cs_err;
    if ((_cs_err = cs_open(CS_ARCH_X86, CS_MODE_64, &handle)) != CS_ERR_OK) {
        throw std::runtime_error("Capstone open error: " + std::string(cs_strerror(_cs_err)));
    }

    if ((_cs_err = cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON)) != CS_ERR_OK) {
        cs_close(&handle);
        throw std::runtime_error("Capstone option error: " + std::string(cs_strerror(_cs_err)));
    }

    ks_err _ks_err;
    if ((_ks_err = ks_open(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN, &engine)) != KS_ERR_OK) {
        cs_close(&handle);
        throw std::runtime_error("Keystone open error: " + std::string(ks_strerror(_ks_err)));
    }
}


elf_converter::~elf_converter() {
    if (handle != 0) {
        cs_close(&handle);
    }

    if (engine) {
        ks_close(engine);
    }
}


constexpr static size_t AARCH64_INSTRUCTION_SIZE = 4;


void elf_converter::convert_function(function_conversion_payload &payload) const {
    cs_insn *insn;
    auto *code = reinterpret_cast<const uint8_t *>(payload.code.data());
    size_t count = cs_disasm(handle, code, payload.size, payload.section_offset, 0, &insn);
    
    if (count <= 0) {
        throw std::runtime_error("Capstone disasm error: " + std::string(cs_strerror(cs_errno(handle))));
    }
    
    auto instructions = from({insn, insn + count}, payload.relocations);
    std::string converted_code;
    size_t instruction_count = 0;
    for (auto &instruction : instructions) {
        instruction->handle_known_offset_in_converted_function(instruction_count * AARCH64_INSTRUCTION_SIZE);
        converted_code.append(instruction->convert_to_aarch64());
        instruction_count += instruction->converted_instructions_count();
    }
    
    cs_free(insn, count);
    
    unsigned char *encode;
    size_t size;

    if (ks_asm(engine, converted_code.c_str(), 0, &encode, &size, &count) != KS_ERR_OK) {
        throw std::runtime_error("Keystone asm error: " + std::string(ks_strerror(ks_errno(engine))));
    }
    
    payload.converted_code = {encode, encode + size};
    ks_free(encode);
}


using sections_conversion_info = std::map<std::shared_ptr<elf_section>, std::vector<function_conversion_payload>>;


static void adjust_elf_file_contents_related_to_section(const std::shared_ptr<elf_section> &section, 
                                                        std::vector<function_conversion_payload> &payloads) 
{
    if (payloads.empty()) {
        return;
    }
    
    std::sort(payloads.begin(), payloads.end(), [] (const auto &p1, const auto &p2) {
        return p1.section_offset < p2.section_offset;
    });
    
    size_t old_section_offset = 0;
    size_t new_section_offset;
    
    std::vector<char> new_content;
    std::vector<char> old_content = section->get_content();
    for (auto &payload : payloads) {
        // Copy old section data.
        new_content.insert(new_content.end(), 
                           old_content.begin() + static_cast<long>(old_section_offset),
                           old_content.begin() + static_cast<long>(payload.section_offset));

        // `new_section_offset points` at new location of the function. Update the symbol and relocation entries.
        new_section_offset = new_content.size();
        payload.symbol->set_section_offset(new_section_offset);
        payload.symbol->set_size(payload.converted_code.size());
        
        // We assume that each relocation context already holds the in-function offset 
        // of the pointed instruction. We have to add the new in-section function offset. 
        for (auto &relocation : payload.relocations) {
            relocation->add_offset(new_section_offset);
        }
        
        new_content.insert(new_content.end(),
                           payload.converted_code.begin(),
                           payload.converted_code.end());
        
        old_section_offset = payload.section_offset + payload.size;
    }
    
    // Copy the remaining section content.
    new_content.insert(new_content.end(), 
                       old_content.begin() + static_cast<long>(old_section_offset),
                       old_content.end());
    
    section->set_content(std::move(new_content));
}


static void adjust_elf_file_contents(sections_conversion_info &section_functions) {
    for (auto &[section, payload] : section_functions) {
        adjust_elf_file_contents_related_to_section(section, payload);
    }
}


void elf_converter::convert_functions(std::vector<function_conversion_payload> &payloads) const {
    sections_conversion_info section_info;
    for (auto &payload : payloads) {
        convert_function(payload);
        section_info[payload.section].push_back(payload);
    }
    
    adjust_elf_file_contents(section_info);
}
