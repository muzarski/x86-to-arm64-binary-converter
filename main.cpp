#include <iostream>
#include <elf_file.h>

int main(int argc, char **argv) {
    if (argc != 3) {
        std::cerr << "Usage: ./converter <source elf path> <target elf path>\n";
        exit(1);
    }
    
    try {
        elf_file elf = elf_file::from(argv[1]);
        elf.remove_section_by_regexp_match(R"(.*\.eh_frame|\.note\.gnu\.property)");
        elf.convert_to_aarch64();
        elf.write_to_file(argv[2]);    
    } catch (const std::exception &e) {
        std::cerr << "Conversion error: " << e.what() << '\n';
        return 1;
    }
    
    return 0;
}
