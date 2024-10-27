#ifndef ELF_FILE_HH
#define ELF_FILE_HH

#include <elf.h>
#include <vector>
#include <memory>

class elf_section;
class elf_symbol_table;
class elf_rela_section;
class elf_string_table;


class elf_file {
private:
    size_t size = 0;
    Elf64_Ehdr header{};
    std::vector<std::shared_ptr<elf_section>> sections;
    std::shared_ptr<elf_string_table> string_table;
    std::shared_ptr<elf_symbol_table> symbol_table;
    std::shared_ptr<elf_string_table> symbol_string_table;
    std::vector<std::shared_ptr<elf_rela_section>> rela_sections;
    
    elf_file();
    void parse_sections(const std::vector<char> &content);
    void link_sections();
    bool verify_is_elf_header();

    void adjust_headers();
    void fix_indices();
    void adjust_string_table();
    void convert_functions();
    void convert_remaining_relocations();
    void convert_header();
public:
    
    static elf_file from(const std::string &filename);
    void write_to_file(const std::string &filename);
    void remove_section_by_regexp_match(const std::string &regexp);
    void convert_to_aarch64();
    ~elf_file();
};

#endif // ELF_FILE_HH
