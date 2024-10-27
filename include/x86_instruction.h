#ifndef X86_INSTRUCTION_H
#define X86_INSTRUCTION_H

#include <capstone/capstone.h>
#include <keystone/keystone.h>
#include <string>
#include <memory>
#include <utility>
#include <vector>
#include <optional>

class elf_rela;

namespace impl {
    
    using relocation_opt = std::optional<std::shared_ptr<elf_rela>>;

    class x86_instruction_impl {
    protected:
        relocation_opt relocation_context;
        std::optional<std::string> label;
        
        void apply_label(std::stringstream &ss);

    public:
        x86_instruction_impl()
        : relocation_context(std::nullopt)
        , label(std::nullopt) {}

        explicit x86_instruction_impl(relocation_opt _relocation_context)
        : relocation_context(std::move(_relocation_context))
        , label(std::nullopt) {}


        virtual std::string convert_to_aarch64() = 0;
        virtual size_t converted_instructions_count() = 0;
        void set_label(const std::string &_label);
        virtual void handle_known_offset_in_converted_function(size_t _instruction_offset_in_converted_function);
        virtual ~x86_instruction_impl();
    };
    
} // namespace impl



class x86_instruction {
private:
    std::unique_ptr<impl::x86_instruction_impl> impl;
    
public:
    explicit x86_instruction(std::unique_ptr<impl::x86_instruction_impl> &&_impl);
    std::string convert_to_aarch64();
    void set_label(const std::string &label);
    size_t converted_instructions_count();
    void handle_known_offset_in_converted_function(size_t _instruction_offset_in_converted_function);
};

    
std::vector<std::shared_ptr<x86_instruction>> from(const std::vector<cs_insn> &instructions, 
                                  std::vector<std::shared_ptr<elf_rela>> &relocation_contexts);
    

#endif // X86_INSTRUCTION_H
