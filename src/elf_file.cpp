#include <fstream>
#include <cstring>
#include <iostream>
#include <regex>
#include <algorithm>

#include <elf_file.h>
#include <elf_converter.h>


elf_file::elf_file() = default;


void elf_file::parse_sections(const std::vector<char> &content) {
    Elf64_Shdr sec_headers[header.e_shnum];
    safe_memcpy(sec_headers, content, header.e_shoff, sizeof(Elf64_Shdr) * header.e_shnum);

    Elf64_Shdr str_table_header = sec_headers[header.e_shstrndx];
    const char *string_table_content = safe_offset_pointer(content, str_table_header.sh_offset);
    string_table = std::make_shared<elf_string_table>(
            header.e_shstrndx,
            sec_headers[header.e_shstrndx],
            std::vector<char>{string_table_content,
                              safe_offset_pointer(content, str_table_header.sh_offset + str_table_header.sh_size)});

    for (size_t i = 0; i < header.e_shnum; ++i) {
        Elf64_Shdr sec_header = sec_headers[i];
        std::vector<char> sec_content(safe_offset_pointer(content, sec_header.sh_offset),
                                        safe_offset_pointer(content, sec_header.sh_offset + sec_header.sh_size));
        std::string sec_name = string_table->at(sec_header.sh_name);

        std::shared_ptr<elf_section> section;

        if (sec_header.sh_type == SHT_RELA) {
            auto rela_section = std::make_shared<elf_rela_section>(i, sec_header, sec_content, std::move(sec_name));
            rela_sections.push_back(rela_section);
            section = std::dynamic_pointer_cast<elf_section>(rela_section);
        }
        else if (i == header.e_shstrndx) {
            section = std::dynamic_pointer_cast<elf_section>(string_table);
        }
        else if (sec_header.sh_type == SHT_SYMTAB) {
            symbol_table = std::make_shared<elf_symbol_table>(i, sec_header, sec_content, std::move(sec_name));
            section = std::dynamic_pointer_cast<elf_section>(symbol_table);
        }
        else if (sec_header.sh_type == SHT_STRTAB && sec_name == ".strtab") {
            symbol_string_table = std::make_shared<elf_string_table>(i, sec_header, sec_content, std::move(sec_name));
            section = std::dynamic_pointer_cast<elf_section>(symbol_string_table);
        }
        else {
            section = std::make_shared<elf_section>(i, sec_header, sec_content, std::move(sec_name));
        }

        sections.push_back(section);
    }
}


void elf_file::link_sections() {
    for (auto & section : sections) {
        section->link_sections(sections);
    }
}


bool elf_file::verify_is_elf_header() {
    if (header.e_ident[EI_MAG0] == ELFMAG0 && header.e_ident[EI_MAG1] == ELFMAG1
       && header.e_ident[EI_MAG2] == ELFMAG2 && header.e_ident[EI_MAG3] == ELFMAG3) {
        return true;
    }
    
    return false;
}


elf_file elf_file::from(const std::string &filename) {
    std::ifstream file(filename, std::ios::binary);
    
    if (!file.is_open()) {
        throw std::runtime_error("Cannot find file `" + filename + '`');
    }
    
    std::vector<char> content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();

    elf_file elf;
    elf.size = content.size();
    safe_memcpy(&elf.header, content, 0, sizeof(Elf64_Ehdr));
    
    
    if (!elf.verify_is_elf_header()) {
        throw std::runtime_error("Invalid elf file - `" + filename + '`');
    }
    
    elf.parse_sections(content);
    elf.link_sections();
    
    return elf;
}


void elf_file::fix_indices() {
    for (size_t i = 0; i < sections.size(); ++i) {
        sections[i]->index = i;
    }

    header.e_shstrndx = string_table->index;
    for (auto &section : sections) {
        section->fix_indices();
    }
}


void elf_file::adjust_string_table() {
    std::vector<char> string_table_content;

    for (auto &section : sections) {
        section->header.sh_name = string_table_content.size();
        std::string &name = section->name;
        string_table_content.insert(string_table_content.end(), name.begin(), name.end());
        string_table_content.push_back('\0');
    }

    string_table->content = string_table_content;
    string_table->header.sh_size = string_table_content.size();
}


void elf_file::remove_section_by_regexp_match(const std::string &regexp) {
    std::regex name_regex(regexp);

    sections.erase(std::remove_if(sections.begin(), sections.end(), [&name_regex] (auto &section) {
       return std::regex_match(section->name, name_regex);
    }), sections.end());

    rela_sections.erase(std::remove_if(rela_sections.begin(), rela_sections.end(), [&name_regex] (auto &section) {
        return std::regex_match(section->name, name_regex);
    }), rela_sections.end());
    
    fix_indices();
    adjust_string_table();
}


void elf_file::convert_functions() {
    auto payloads = symbol_table->prepare_conversion_payload();
    for (auto &rela_section : rela_sections) {
        rela_section->add_relocation_info_to_conversion_payload(payloads);
    }
    
    elf_converter converter;
    converter.convert_functions(payloads);
}


void elf_file::convert_remaining_relocations() {
    for (auto &rela_section : rela_sections) {
        rela_section->convert_remaining_relocations(R_AARCH64_ABS64);
    }
}


void elf_file::convert_header() {
    header.e_machine = EM_AARCH64;
}


void elf_file::convert_to_aarch64() {
    convert_header();
    convert_functions();
    convert_remaining_relocations();
}


void elf_file::adjust_headers() {
    header.e_shnum = sections.size();
    header.e_shoff = sizeof(Elf64_Ehdr);
    
    size_t file_offset = header.e_shoff + header.e_shnum * sizeof(Elf64_Shdr);
    for (auto & section : sections) {
        section->header.sh_offset = file_offset;
        section->header.sh_size = section->content.size();
        file_offset += (section->header.sh_type == SHT_NOBITS ? 0 : section->header.sh_size);
    }
    
    size = file_offset;
}


void elf_file::write_to_file(const std::string &filename) {
    adjust_headers();
    
    std::vector<char> content(size, 0);
    
    std::memcpy(content.data(), &header, sizeof(Elf64_Ehdr));
    
    for (size_t i = 0; i < sections.size(); ++i) {
        auto &section = sections[i];
        char *cur_header_pos = content.data() + header.e_shoff + i * sizeof(Elf64_Shdr);
        std::memcpy(cur_header_pos, &section->header, sizeof(Elf64_Shdr));
        char *cur_content_pos = content.data() + section->header.sh_offset;
        size_t section_size_in_file = section->header.sh_type == SHT_NOBITS ? 0 : section->header.sh_size;
        std::memcpy(cur_content_pos, section->get_content().data(), section_size_in_file);
    }
    
    std::ofstream file(filename, std::ios::binary | std::ios::trunc);
    std::copy(content.begin(), content.end(), std::ostreambuf_iterator<char>(file));
    
    file.close();
}


elf_file::~elf_file() {
    for (auto &section : sections) {
        section->link.reset();
    }
}