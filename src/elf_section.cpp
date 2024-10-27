#include <cstring>
#include <elf_section.h>
#include <iostream>
#include <sstream>


void safe_memcpy(void *src, const std::vector<char> &dst, size_t from, size_t size) {
    if (dst.size() < from + size) {
        std::stringstream ss;
        ss << "Invalid ELF file. Cannot access memory at offset " << from << " of size " << size;
        throw std::runtime_error(ss.str());
    }
    std::memcpy(src, dst.data() + from, size);
}


const char *safe_offset_pointer(const std::vector<char> &dst, size_t offset) {
    if (dst.size() < offset) {
        std::stringstream ss;
        ss << "Invalid ELF file. Cannot access memory at offset " << offset;
        throw std::runtime_error(ss.str());
    }
    
    return dst.data() + offset;
}


elf_section::elf_section(size_t _index, Elf64_Shdr _header, 
                         const std::vector<char> &_content, std::string &&_name)
    : header(_header)
    , content(_content)
    , name(std::move(_name))
    , link()
    , index(_index) {}
    

elf_section::~elf_section() = default;


size_t elf_section::idx() const {
    return index;
}


void elf_section::link_sections(const std::vector<std::shared_ptr<elf_section>> &sections) {
    link = sections[header.sh_link];
}


void elf_section::fix_indices() {
    header.sh_link = link->idx();
}


const std::vector<char>& elf_section::get_content() {
    return content;
}


std::vector<char> elf_section::subcontent(long offset, long size) {
    return {content.begin() + offset, content.begin() + offset + size};
}


void elf_section::set_content(std::vector<char> &&new_content) {
    content = std::move(new_content);
    header.sh_size = content.size();
}


elf_symbol::elf_symbol() = default;


unsigned char elf_symbol::type() const {
    return ELF64_ST_TYPE(content.st_info);
}


std::optional<function_conversion_payload> elf_symbol::get_function_conversion_payload() {
    if (!related_section || type() != STT_FUNC) {
        return std::nullopt;
    }
    
    function_conversion_payload payload {
        .section = related_section,
        .section_offset = content.st_value,
        .size = content.st_size,
        .code = related_section->subcontent(static_cast<long>(content.st_value), static_cast<long>(content.st_size)),
        .symbol = this->shared_from_this(),
        .relocations = {},
        .converted_code = {},
    };
    
    return payload;
}


void elf_symbol::set_section_offset(size_t section_offset) {
    content.st_value = section_offset;
}


void elf_symbol::set_size(size_t size) {
    content.st_size = size;
}


elf_symbol_table::elf_symbol_table(size_t _index, Elf64_Shdr _header, 
                                   const std::vector<char> &_content, std::string &&_name)
    : elf_section(_index, _header, _content, std::move(_name))
    , symbols(header.sh_size / header.sh_entsize) {}


void elf_symbol_table::link_sections(const std::vector<std::shared_ptr<elf_section>> &sections) {
    link = sections[header.sh_link];

    auto *symbols_table = (Elf64_Sym *) content.data();
    for (size_t i = 0; i < symbols.size(); ++i) {
        symbols[i] = std::make_shared<elf_symbol>();
        symbols[i]->content = symbols_table[i];
        if (symbols_table[i].st_shndx < sections.size()) {
            symbols[i]->related_section = sections[symbols_table[i].st_shndx];    
        }
    }
}


void elf_symbol_table::fix_indices() {
    header.sh_link = link->idx();

    auto *symbols_table = (Elf64_Sym *) content.data();
    for (size_t i = 0; i < symbols.size(); ++i) {
        if (symbols[i]->related_section) {
            symbols_table[i].st_shndx = symbols[i]->related_section->idx();
        }
    }
}


const std::vector<char>& elf_symbol_table::get_content() {
    size_t iter = 0;
    for (auto &symbol : symbols) {
        std::memcpy(content.data() + iter, &symbol->content, sizeof(Elf64_Sym));
        iter += sizeof(Elf64_Sym);
    }
    return content;
}


std::vector<function_conversion_payload> elf_symbol_table::prepare_conversion_payload() {
    std::vector<function_conversion_payload> payloads;
    
    for (auto &symbol : symbols) {
        auto payload_opt = symbol->get_function_conversion_payload();
        if (payload_opt) {
            payloads.push_back(payload_opt.value());
        }
    }
    
    return payloads;
}


elf_rela::elf_rela() = default;


size_t elf_rela::symbol() const {
    return ELF64_R_SYM(content.r_info);
}


size_t elf_rela::offset() const {
    return content.r_offset;
}


bool elf_rela::is_converted() const {
    return converted;
}


void elf_rela::set_converted() {
    converted = true;
}


void elf_rela::set_type(size_t _type) {
    content.r_info = ELF64_R_INFO(symbol(), _type);
}


void elf_rela::add_addend(long _addend) {
    content.r_addend += _addend;
}


void elf_rela::set_offset(size_t _offset) {
    content.r_offset = _offset;
}


void elf_rela::add_offset(size_t _offset) {
    content.r_offset += _offset;
}


bool elf_rela::is_offset_in_range(size_t from, size_t range) const {
    return offset() >= from && offset() < from + range;  
}


elf_rela_section::elf_rela_section(size_t _index, Elf64_Shdr _header, 
                                   const std::vector<char> &_content, std::string &&_name)
    : elf_section(_index, _header, _content, std::move(_name))
    , rela_entries(header.sh_size / header.sh_entsize)
    , relocated() {}


void elf_rela_section::link_sections(const std::vector<std::shared_ptr<elf_section>> &sections) {
    link = sections[header.sh_link];
    relocated = sections[header.sh_info];

    auto *rela_table = (Elf64_Rela*) content.data();
    for (size_t i = 0; i < rela_entries.size(); ++i) {
        rela_entries[i] = std::make_shared<elf_rela>();
        rela_entries[i]->content = rela_table[i];
    }
}


void elf_rela_section::fix_indices() {
    header.sh_link = link->idx();
    header.sh_info = relocated->idx();
}


const std::vector<char>& elf_rela_section::get_content() {
    size_t iter = 0;
    for (auto &rela : rela_entries) {
        std::memcpy(content.data() + iter, &rela->content, sizeof(Elf64_Rela));
        iter += sizeof(Elf64_Rela);
    }
    return content;
}


void elf_rela_section::add_relocation_info_to_conversion_payload(std::vector<function_conversion_payload> &payloads) {
    for (auto &payload : payloads) {
        for (auto &rela : rela_entries) {
            if (payload.section == relocated && rela->is_offset_in_range(payload.section_offset, payload.size)) {
                payload.relocations.push_back(rela);
            }
        }
    }
}


void elf_rela_section::convert_remaining_relocations(size_t _relocation_type) {
    for (auto &rela : rela_entries) {
        if (!rela->is_converted()) {
            rela->set_type(_relocation_type);
        }
    }
}

    
elf_string_table::elf_string_table(size_t _index, Elf64_Shdr _header, 
                                   const std::vector<char> &_content, std::string &&_name)
    : elf_section(_index, _header, _content, std::move(_name)) {}

    
elf_string_table::elf_string_table(size_t _index, Elf64_Shdr _header, const std::vector<char> &_content)
    : elf_section(_index, _header, _content, safe_offset_pointer(_content, _header.sh_name)) {}

    
std::string elf_string_table::at(size_t i) {
    return content.data() + i;
}
