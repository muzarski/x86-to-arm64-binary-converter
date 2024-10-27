#ifndef ELF_SECTION_H
#define ELF_SECTION_H

#include <elf.h>
#include <utility>
#include <vector>
#include <memory>
#include <string>
#include <optional>


void safe_memcpy(void *src, const std::vector<char> &dst, size_t from, size_t size);
const char *safe_offset_pointer(const std::vector<char> &dst, size_t offset);

class elf_section;
class elf_symbol;
class elf_rela;


struct function_conversion_payload {
    std::shared_ptr<elf_section> section;
    size_t section_offset;
    size_t size;
    std::vector<char> code;
    std::shared_ptr<elf_symbol> symbol;
    std::vector<std::shared_ptr<elf_rela>> relocations;
    std::vector<uint8_t> converted_code;
};


class elf_section {
private:
    friend class elf_file;
    friend class elf_symbol_table;
    
protected:
    Elf64_Shdr header;
    std::vector<char> content;
    std::string name;
    std::shared_ptr<elf_section> link;
    size_t index;
    
public:
    elf_section(size_t _index, Elf64_Shdr _header, const std::vector<char> &_content, std::string &&_name);
    virtual ~elf_section();
    
    virtual void link_sections(const std::vector<std::shared_ptr<elf_section>> &sections);
    virtual void fix_indices();
    virtual const std::vector<char>& get_content();
    [[nodiscard]] size_t idx() const;
    std::vector<char> subcontent(long offset, long size);
    void set_content(std::vector<char> &&new_content);
};


class elf_symbol : public std::enable_shared_from_this<elf_symbol> {
private:
    std::shared_ptr<elf_section> related_section;
    Elf64_Sym content{};
    
private:
    friend class elf_symbol_table;
    
public:
    elf_symbol();
    [[nodiscard]] unsigned char type() const;
    [[nodiscard]] std::optional<function_conversion_payload> get_function_conversion_payload();
    void set_section_offset(size_t section_offset);
    void set_size(size_t size);
};


class elf_symbol_table : public elf_section {
private:
    std::vector<std::shared_ptr<elf_symbol>> symbols;
    friend class elf_file;
    
public:
    elf_symbol_table(size_t _index, Elf64_Shdr _header, const std::vector<char> &_content, std::string &&_name);
    
    std::vector<function_conversion_payload> prepare_conversion_payload();
    void link_sections(const std::vector<std::shared_ptr<elf_section>> &sections) override;
    void fix_indices() override;
    const std::vector<char>& get_content() override;
};


class elf_rela {
private:
    Elf64_Rela content{};
    bool converted = false;
    
private:
    friend class elf_rela_section;
    
public:
    elf_rela();
    [[nodiscard]] size_t symbol() const;
    [[nodiscard]] size_t offset() const;
    [[nodiscard]] bool is_offset_in_range(size_t from, size_t range) const;
    [[nodiscard]] bool is_converted() const;
    void set_converted();
    void set_type(size_t _type);
    void add_addend(long _addend);
    void add_offset(size_t _offset);
    void set_offset(size_t _offset);
};


class elf_rela_section : public elf_section {
private:
    std::vector<std::shared_ptr<elf_rela>> rela_entries;
    std::shared_ptr<elf_section> relocated;
    friend class elf_file;
    
public:
    elf_rela_section(size_t _index, Elf64_Shdr _header, const std::vector<char> &_content, std::string &&_name);
    void link_sections(const std::vector<std::shared_ptr<elf_section>> &sections) override;
    void fix_indices() override;
    const std::vector<char>& get_content() override;
    void add_relocation_info_to_conversion_payload(std::vector<function_conversion_payload> &payloads);
    void convert_remaining_relocations(size_t _relocation_type);
};


class elf_string_table : public elf_section {
private:
    friend class elf_file;
    
public:
    elf_string_table(size_t _index, Elf64_Shdr _header, const std::vector<char> &_content, std::string &&_name);
    elf_string_table(size_t _index, Elf64_Shdr _header, const std::vector<char> &_content);
    std::string at(size_t i);
};


#endif // ELF_SECTION_H
