#include <utility>
#include <iostream>
#include <unordered_map>
#include <sstream>
#include <algorithm>

#include <x86_instruction.h>
#include <elf_section.h>


using namespace impl;

namespace {
    
    enum x86_op_size {
        DWORD, QWORD
    };


    std::unordered_map<x86_reg, std::string> reg_mapping = {
            {X86_REG_RDI, "x0"},  {X86_REG_EDI, "w0"},
            {X86_REG_RSI, "x1"},  {X86_REG_ESI, "w1"},
            {X86_REG_RDX, "x2"},  {X86_REG_EDX, "w2"},
            {X86_REG_RCX, "x3"},  {X86_REG_ECX, "w3"},
            {X86_REG_R8,  "x4"},  {X86_REG_R8D, "w4"},
            {X86_REG_R9,  "x5"},  {X86_REG_R9D, "w5"},
            {X86_REG_RAX, "x9"},  {X86_REG_EAX, "w9"},
            {X86_REG_R10, "x10"}, {X86_REG_R10D, "w10"},
            {X86_REG_R11, "x11"}, {X86_REG_R11D, "w11"},
            {X86_REG_RBP, "x29"}, {X86_REG_EBP, "w29"},
            {X86_REG_RBX, "x19"}, {X86_REG_EBX, "w19"},
            {X86_REG_R12, "x20"}, {X86_REG_R12D, "w20"},
            {X86_REG_R13, "x21"}, {X86_REG_R13D, "w21"},
            {X86_REG_R14, "x22"}, {X86_REG_R14D, "w22"},
            {X86_REG_R15, "x23"}, {X86_REG_R15D, "w23"},
            {X86_REG_RSP, "sp"},
    };


    std::unordered_map<x86_reg, x86_reg> reg64_mapping = {
            {X86_REG_RDI, X86_REG_RDI},  {X86_REG_EDI, X86_REG_RDI},
            {X86_REG_RSI, X86_REG_RSI},  {X86_REG_ESI, X86_REG_RSI},
            {X86_REG_RDX, X86_REG_RDX},  {X86_REG_EDX, X86_REG_RDX},
            {X86_REG_RCX, X86_REG_RCX},  {X86_REG_ECX, X86_REG_RCX},
            {X86_REG_R8,  X86_REG_R8},  {X86_REG_R8D, X86_REG_R8},
            {X86_REG_R9,  X86_REG_R9},  {X86_REG_R9D, X86_REG_R9},
            {X86_REG_RAX, X86_REG_RAX},  {X86_REG_EAX, X86_REG_RAX},
            {X86_REG_R10, X86_REG_R10}, {X86_REG_R10D, X86_REG_R10},
            {X86_REG_R11, X86_REG_R11}, {X86_REG_R11D, X86_REG_R11},
            {X86_REG_RBP, X86_REG_RBP}, {X86_REG_EBP, X86_REG_RBP},
            {X86_REG_RBX, X86_REG_RBX}, {X86_REG_EBX, X86_REG_RBX},
            {X86_REG_R12, X86_REG_R12}, {X86_REG_R12D, X86_REG_R12},
            {X86_REG_R13, X86_REG_R13}, {X86_REG_R13D, X86_REG_R13},
            {X86_REG_R14, X86_REG_R14}, {X86_REG_R14D, X86_REG_R14},
            {X86_REG_R15, X86_REG_R15}, {X86_REG_R15D, X86_REG_R15},
            {X86_REG_RSP, X86_REG_RSP},
    };


    std::unordered_map<x86_reg, x86_op_size> reg_size = {
            {X86_REG_RDI, QWORD},  {X86_REG_EDI, DWORD},
            {X86_REG_RSI, QWORD},  {X86_REG_ESI, DWORD},
            {X86_REG_RDX, QWORD},  {X86_REG_EDX, DWORD},
            {X86_REG_RCX, QWORD},  {X86_REG_ECX, DWORD},
            {X86_REG_R8,  QWORD},  {X86_REG_R8D, DWORD},
            {X86_REG_R9,  QWORD},  {X86_REG_R9D, DWORD},
            {X86_REG_RAX, QWORD},  {X86_REG_EAX, DWORD},
            {X86_REG_R10, QWORD}, {X86_REG_R10D, DWORD},
            {X86_REG_R11, QWORD}, {X86_REG_R11D, DWORD},
            {X86_REG_RBP, QWORD}, {X86_REG_EBP, DWORD},
            {X86_REG_RBX, QWORD}, {X86_REG_EBX, DWORD},
            {X86_REG_R12, QWORD}, {X86_REG_R12D, DWORD},
            {X86_REG_R13, QWORD}, {X86_REG_R13D, DWORD},
            {X86_REG_R14, QWORD}, {X86_REG_R14D, DWORD},
            {X86_REG_R15, QWORD}, {X86_REG_R15D, DWORD},
            {X86_REG_RSP, QWORD},
    };
    
    
    std::unordered_map<std::string, std::string> jumps_mapping = {
            {"jmp", "b"}, {"ja", "b.hi"},
            {"jae", "b.hs"}, {"jb", "b.lo"},
            {"je", "b.eq"}, {"jg", "b.gt"},
            {"jge", "b.ge"}, {"jl", "b.lt"},
            {"jle", "b.le"}, {"jna", "b.ls"},
            {"jnae", "b.lo"}, {"jnb", "b.hs"},
            {"jnbe", "b.hi"}, {"jne", "b.ne"}, 
            {"jng", "b.le"}, {"jnge", "b.lt"}, 
            {"jnl", "b.ge"}, {"jnle", "b.gt"}, 
            {"jno", "b.vc"}, {"jnz", "b.ne"}, 
            {"jo", "b.vs"}, {"jz", "b.eq"},
            {"jbe", "b.ls"},
    };


    std::string op_to_string(cs_x86_op op) {
        std::stringstream ss;
        if (op.type == X86_OP_IMM) {
            ss << "#" << op.imm;
        }
        else if (op.type == X86_OP_REG) {
            ss << reg_mapping[op.reg];
        }

        return ss.str();
    }
    
    
    std::string tmp1(x86_op_size size) {
        switch (size) {
            case QWORD: return "x12";
            case DWORD: return "w12";
            default:    return "";
        }
    }
    
    
    std::string tmp2(x86_op_size size) {
        switch (size) {
            case QWORD: return "x13";
            case DWORD: return "w13";
            default   : return "";
        }
    }
    
    
    x86_op_size instruction_operands_size(cs_x86_op op1, cs_x86_op op2, const std::string &op_str) {
        if (op1.type == X86_OP_REG) {
            return reg_size[op1.reg];
        }
        if (op2.type == X86_OP_REG) {
            return reg_size[op2.reg];
        }
        return op_str.find("dword") != std::string::npos ? DWORD : QWORD;
    }
    
    
    void move_mem_to_reg_helper(std::stringstream &ss, const std::string &reg, 
                                x86_op_mem mem, relocation_opt &relocation_context,
                                size_t offset_in_function, const std::string &tmp = tmp1(QWORD)) {
        if (mem.base == X86_REG_RIP) {
            ss << "ldr " << reg << ", #" << offset_in_function << '\n';
            relocation_context.value()->add_addend(4);
            relocation_context.value()->set_type(R_AARCH64_LD_PREL_LO19);
            relocation_context.value()->set_converted();
        }
        else {
            ss << "mov " << tmp << ", #" << mem.disp << '\n';
            ss << "ldr " << reg << ", [" << reg_mapping[mem.base] << ", " << tmp << "]\n";
        }
    }
    
    
    struct jump_info {
        uint64_t address;
        std::string label;
    };
    

} // anonymous namespace

x86_instruction::x86_instruction(std::unique_ptr<x86_instruction_impl> &&_impl) 
    : impl(std::move(_impl)) {}


std::string x86_instruction::convert_to_aarch64() {
    return impl->convert_to_aarch64();
}


void x86_instruction::set_label(const std::string &label) {
    impl->set_label(label);
}


size_t x86_instruction::converted_instructions_count() {
    return impl->converted_instructions_count();
}


void x86_instruction::handle_known_offset_in_converted_function(size_t _instruction_offset_in_converted_function) {
    impl->handle_known_offset_in_converted_function(_instruction_offset_in_converted_function);
}


x86_instruction_impl::~x86_instruction_impl() = default;


void x86_instruction_impl::set_label(const std::string &_label) {
    label = _label;
}


void x86_instruction_impl::apply_label(std::stringstream &ss) {
    if (label) {
        ss << label.value() << ": ";
    }
}


void x86_instruction_impl::handle_known_offset_in_converted_function(size_t _instruction_offset_in_converted_function) {
    if (relocation_context) {
        relocation_context.value()->set_offset(_instruction_offset_in_converted_function);
    }
}


class x86_prologue : public x86_instruction_impl {
public:
    x86_prologue() : x86_instruction_impl() {}
    std::string convert_to_aarch64() override;
    size_t converted_instructions_count() override;
};


class x86_epilogue : public x86_instruction_impl {
public:
    x86_epilogue() : x86_instruction_impl() {}
    std::string convert_to_aarch64() override;
    size_t converted_instructions_count() override;
};


class x86_mov : public x86_instruction_impl {
private:
    cs_x86_op to;
    cs_x86_op from;
    x86_op_size size_directive;
    size_t offset_in_function = 0;
    
    void mov_to_reg(std::stringstream &ss);
    void mov_to_reg_from_reg(std::stringstream &ss) const;
    void mov_to_reg_from_mem(std::stringstream &ss);
    void mov_to_reg_from_imm(std::stringstream &ss);
    void mov_to_mem(std::stringstream &ss);
    void mov_to_mem_base_rip(std::stringstream &ss);
    void mov_to_mem_with_relocation(std::stringstream &ss);
    void mov_to_mem_without_relocation(std::stringstream &ss);
    
public:
    x86_mov(const relocation_opt &relocation_context, cs_x86_op _to, cs_x86_op _from, x86_op_size _size_directive);
    std::string convert_to_aarch64() override;
    size_t converted_instructions_count() override;
    void handle_known_offset_in_converted_function(size_t _offset) override;
};


class x86_cmp : public x86_instruction_impl {
private:
    cs_x86_op op1;
    cs_x86_op op2;
    x86_op_size size_directive;
    size_t offset_in_function = 0;
    
public:
    x86_cmp(const relocation_opt &relocation_context, cs_x86_op _op1, cs_x86_op _op2, x86_op_size _size_directive);
    std::string convert_to_aarch64() override;
    size_t converted_instructions_count() override;
    void handle_known_offset_in_converted_function(size_t _offset) override;
};


class x86_add : public x86_instruction_impl {
private:
    cs_x86_op op1;
    cs_x86_op op2;
    
public:
    x86_add(const relocation_opt &relocation_context, cs_x86_op _op1, cs_x86_op _op2);
    std::string convert_to_aarch64() override;
    size_t converted_instructions_count() override;
};


class x86_sub : public x86_instruction_impl {
private:
    cs_x86_op op1;
    cs_x86_op op2;

public:
    x86_sub(const relocation_opt &relocation_context, cs_x86_op _op1, cs_x86_op _op2);
    std::string convert_to_aarch64() override;
    size_t converted_instructions_count() override;
};


class x86_call : public x86_instruction_impl {
private:
    size_t offset_in_function = 0;

public:
    explicit x86_call(const relocation_opt &relocation_context);
    std::string convert_to_aarch64() override;
    size_t converted_instructions_count() override;
    void handle_known_offset_in_converted_function(size_t _offset) override;
};


class x86_jmp : public x86_instruction_impl {
private:
    std::string mapped_mnemonic;
    std::string label_str;
    
public:
    x86_jmp(std::string _mapped_mnemonic, std::string _label);
    std::string convert_to_aarch64() override;
    size_t converted_instructions_count() override;
};


constexpr size_t X86_EPILOGUE_INSTRUCTION_COUNT = 2;


static int64_t verify_prologue_size(const std::vector<cs_insn> &instructions) {
    if (instructions[0].id == X86_INS_ENDBR64) {
        return 3;
    }
    return 2;
}


static x86_instruction prologue() {
    return x86_instruction(std::make_unique<x86_prologue>());
}


static x86_instruction epilogue() {
    return x86_instruction(std::make_unique<x86_epilogue>());
}


static x86_instruction from_jump(const cs_insn &instruction, std::vector<jump_info> &jump_infos) {
    static constexpr auto generate_label = [] () {
        static uint64_t label_id = 0;
        
        std::stringstream ss;
        ss << ".l" << label_id++;
        return ss.str();
    };
    
    std::string label = generate_label();
    jump_infos.push_back({static_cast<uint64_t>(instruction.detail->x86.operands[0].imm), label});
    
    return x86_instruction(std::make_unique<x86_jmp>(jumps_mapping[instruction.mnemonic], label));
}


static x86_instruction from(const cs_insn &instruction, relocation_opt &relocation_context, 
                            std::vector<jump_info> &jump_infos) {
    
    if (instruction.mnemonic[0] == 'j') {
        return from_jump(instruction, jump_infos);
    }
    
    switch (instruction.id) {
        case X86_INS_MOV:
            return x86_instruction(std::make_unique<x86_mov>(
                relocation_context, 
                instruction.detail->x86.operands[0],
                instruction.detail->x86.operands[1],
                instruction_operands_size(instruction.detail->x86.operands[0], 
                                          instruction.detail->x86.operands[1], instruction.op_str)));
        case X86_INS_CMP: return x86_instruction(std::make_unique<x86_cmp>(
                relocation_context,
                instruction.detail->x86.operands[0],
                instruction.detail->x86.operands[1],
                instruction_operands_size(instruction.detail->x86.operands[0],
                                          instruction.detail->x86.operands[1], instruction.op_str)));
        case X86_INS_ADD: return x86_instruction(std::make_unique<x86_add>(
                relocation_context,
                instruction.detail->x86.operands[0],
                instruction.detail->x86.operands[1]));
        case X86_INS_SUB: return x86_instruction(std::make_unique<x86_sub>(
                relocation_context,
                instruction.detail->x86.operands[0],
                instruction.detail->x86.operands[1]));
        case X86_INS_CALL: return x86_instruction(std::make_unique<x86_call>(relocation_context)); 
        default: return x86_instruction(std::make_unique<x86_prologue>());
    }
}


std::vector<std::shared_ptr<x86_instruction>> from(const std::vector<cs_insn> &instructions,
                                                       std::vector<std::shared_ptr<elf_rela>> &relocation_contexts) {
    int64_t prologue_instructions_count = verify_prologue_size(instructions);
    
    std::vector<cs_insn> actual_content(instructions.begin() + prologue_instructions_count,
                                        instructions.end() - X86_EPILOGUE_INSTRUCTION_COUNT);
    
    // Relocations should be sorted based on their offsets in relocated sections.
    std::sort(relocation_contexts.begin(), relocation_contexts.end(), [] (const auto &r1, const auto &r2) {
        return r1->offset() < r2->offset();
    });

    std::vector<std::shared_ptr<x86_instruction>> parsed;
    // address -> instruction
    std::unordered_map<uint64_t, std::shared_ptr<x86_instruction>> instruction_at;
    std::vector<jump_info> jump_infos;
    auto rela_iter = relocation_contexts.begin();
    
    // Handle prologue.
    std::shared_ptr<x86_instruction> prologue_ptr = std::make_shared<x86_instruction>(prologue());
    parsed.push_back(prologue_ptr);
    instruction_at.insert({instructions.begin()->address, prologue_ptr});
    
    // Handle rest of the instructions.
    for (auto &instruction : actual_content) {
        relocation_opt relocation_context = std::nullopt;
        if (rela_iter != relocation_contexts.end()
            && (*rela_iter)->is_offset_in_range(instruction.address, instruction.size)) {
            relocation_context = *rela_iter;
            ++rela_iter;
        }
        
        std::shared_ptr<x86_instruction> instruction_ptr = 
                std::make_shared<x86_instruction>(from(instruction, relocation_context, jump_infos));
        parsed.push_back(instruction_ptr);
        instruction_at.insert({instruction.address, instruction_ptr});
    }

    // Handle epilogue.
    std::shared_ptr<x86_instruction> epilogue_ptr = std::make_shared<x86_instruction>(epilogue());
    parsed.push_back(epilogue_ptr);
    instruction_at.insert({(instructions.end() - X86_EPILOGUE_INSTRUCTION_COUNT)->address, epilogue_ptr});
    
    for (auto &info : jump_infos) {
        instruction_at[info.address]->set_label(info.label);
    }
    
    return parsed;
}


std::string x86_prologue::convert_to_aarch64() {
    std::stringstream ss;
    apply_label(ss);
    
    ss << "stp x29, x30, [sp, #-16]!\n";
    ss << "mov x29, sp\n";
    
    return ss.str();
}


size_t x86_prologue::converted_instructions_count() {
    return 2;
}


std::string x86_epilogue::convert_to_aarch64() {
    std::stringstream ss;
    apply_label(ss);
    
    ss << "mov x0, x9\n"
                 "add sp, x29, #16\n"
                 "ldp x29, x30, [sp, #-16]\n"
                 "ret\n";
    
    return ss.str();
}


size_t x86_epilogue::converted_instructions_count() {
    return 4;
}


x86_mov::x86_mov(const relocation_opt &relocation_context, cs_x86_op _to, cs_x86_op _from, x86_op_size _size_directive)
    : x86_instruction_impl(relocation_context) 
    , to(_to)
    , from(_from)
    , size_directive(_size_directive) {}


void x86_mov::handle_known_offset_in_converted_function(size_t _offset) {
    if (relocation_context) {
        relocation_context.value()->set_offset(_offset);
    }
    offset_in_function = _offset;
}
    
    
void x86_mov::mov_to_reg_from_reg(std::stringstream &ss) const {
    ss << "mov " << reg_mapping[to.reg] << ", " + reg_mapping[from.reg] << '\n';
}


void x86_mov::mov_to_reg_from_mem(std::stringstream &ss) {
    move_mem_to_reg_helper(ss, reg_mapping[to.reg], from.mem, relocation_context, offset_in_function);
}


void x86_mov::mov_to_reg_from_imm(std::stringstream &ss) {
    if (relocation_context) {
        ss << "adr " << reg_mapping[reg64_mapping[to.reg]] << ", #0\n";
        relocation_context.value()->set_type(R_AARCH64_ADR_PREL_LO21);
        relocation_context.value()->set_converted();
    }
    else {
        ss << "mov " << op_to_string(to) << ", #" << from.imm << '\n';
    }
}

    
void x86_mov::mov_to_reg(std::stringstream &ss) {
    if (from.type == X86_OP_REG) {
        mov_to_reg_from_reg(ss);
    }
    else if (from.type == X86_OP_IMM) {
        mov_to_reg_from_imm(ss);
    }
    else {
        mov_to_reg_from_mem(ss);
    }
}


void x86_mov::mov_to_mem_base_rip(std::stringstream &ss) {
    ss << "adr " << tmp1(QWORD) << ", 0\n";
    ss << "mov " << tmp2(size_directive) << ", " << op_to_string(from) << '\n';
    ss << "str " << tmp2(size_directive)  << ", " << "[" << tmp1(QWORD) << "]\n";

    relocation_context.value()->set_type(R_AARCH64_ADR_PREL_LO21);
    relocation_context.value()->add_addend(4);
    relocation_context.value()->set_converted();
}


void x86_mov::mov_to_mem_with_relocation(std::stringstream &ss) {
    ss << "adr " << tmp1(QWORD) << ", #0\n";
    ss << "mov " << tmp2(QWORD) << ", #" << to.mem.disp << '\n';
    ss << "str " << tmp1(size_directive) << ", [" << reg_mapping[to.mem.base] << ", " << tmp2(QWORD) << "]\n";

    relocation_context.value()->set_type(R_AARCH64_ADR_PREL_LO21);
    relocation_context.value()->set_converted();
}


void x86_mov::mov_to_mem_without_relocation(std::stringstream &ss) {
    ss << "mov " << tmp1(size_directive) << ", " << op_to_string(from) << '\n';
    ss << "mov " << tmp2(QWORD) << ", #" << to.mem.disp << '\n';
    ss << "str " << tmp1(size_directive) << ", [" << reg_mapping[to.mem.base] << ", " << tmp2(QWORD) << "]\n";
}


void x86_mov::mov_to_mem(std::stringstream &ss) {
    if (to.mem.base == X86_REG_RIP) {
        mov_to_mem_base_rip(ss);
    }
    else {
        if (from.type == X86_OP_IMM && relocation_context) {
            mov_to_mem_with_relocation(ss);
        }
        else {
            mov_to_mem_without_relocation(ss);
        }
    }
}
    
    
std::string x86_mov::convert_to_aarch64() {
    std::stringstream ss;
    apply_label(ss);
    
    if (to.type == X86_OP_REG) {
        mov_to_reg(ss);
    }
    else if (to.type == X86_OP_MEM) {
        mov_to_mem(ss);
    }
    
    return ss.str();
}


size_t x86_mov::converted_instructions_count() {
    if (to.type == X86_OP_REG) {
        if (from.type == X86_OP_REG || from.type == X86_OP_IMM || 
            (from.type == X86_OP_MEM && from.mem.base == X86_REG_RIP)) {
            return 1;
        }
        else {
            return 2;
        }
    }
    else if (to.type == X86_OP_MEM) {
        return 3;
    }
    return 0;
}


x86_cmp::x86_cmp(const relocation_opt &relocation_context, cs_x86_op _op1, cs_x86_op _op2, x86_op_size _size_directive)
    : x86_instruction_impl(relocation_context)
    , op1(_op1)
    , op2(_op2)
    , size_directive(_size_directive) {}


void x86_cmp::handle_known_offset_in_converted_function(size_t _offset) {
    if (relocation_context) {
        relocation_context.value()->set_offset(_offset);
    }
    offset_in_function = _offset;
}
    

std::string x86_cmp::convert_to_aarch64() {
    std::stringstream ss;
    apply_label(ss);
    
    if (op1.type == X86_OP_REG) {
        if (op2.type == X86_OP_MEM) {
            move_mem_to_reg_helper(ss, tmp1(size_directive), op2.mem, 
                                   relocation_context, offset_in_function, tmp2(QWORD));
            ss << "cmp " << op_to_string(op1) << ", " << tmp1(size_directive) << '\n';
        }
        else {
            ss << "cmp " << op_to_string(op1) << ", " << op_to_string(op2) << '\n';
        }
    }
    else if (op1.type == X86_OP_MEM) {
        move_mem_to_reg_helper(ss, tmp1(size_directive), op1.mem, relocation_context, offset_in_function, tmp2(QWORD));
        ss << "cmp " << tmp1(size_directive) << ", " << op_to_string(op2) << '\n';
    }
    
    return ss.str();
}


size_t x86_cmp::converted_instructions_count() {
    if (op1.type == X86_OP_MEM) {
        if (op1.mem.base == X86_REG_RIP) {
            return 2;
        }
        return 3;
    }
    
    if (op2.type == X86_OP_MEM) {
        if (op2.mem.base == X86_REG_RIP) {
            return 2;
        }
        return 3;
    }
    
    return 1;
}
    
    
x86_add::x86_add(const relocation_opt &relocation_context, cs_x86_op _op1, cs_x86_op _op2)
        : x86_instruction_impl(relocation_context)
        , op1(_op1)
        , op2(_op2) {}


std::string x86_add::convert_to_aarch64() {
    std::stringstream ss;
    apply_label(ss);
    
    ss << "add " << op_to_string(op1) << ", " << op_to_string(op1) << ", " << op_to_string(op2) << '\n';
    return ss.str();
}


size_t x86_add::converted_instructions_count() {
    return 1;
}


x86_sub::x86_sub(const relocation_opt &relocation_context, cs_x86_op _op1, cs_x86_op _op2)
        : x86_instruction_impl(relocation_context)
        , op1(_op1)
        , op2(_op2) {}


std::string x86_sub::convert_to_aarch64() {
    std::stringstream ss;
    apply_label(ss);
    
    ss << "sub " << op_to_string(op1) << ", " << op_to_string(op1) << ", " << op_to_string(op2) << '\n';
    return ss.str();
}


size_t x86_sub::converted_instructions_count() {
    return 1;
}


x86_call::x86_call(const relocation_opt &relocation_context)
        : x86_instruction_impl(relocation_context)
        , offset_in_function(0) {}


std::string x86_call::convert_to_aarch64() {
    std::stringstream ss;
    apply_label(ss);
    
    ss << "bl #" << offset_in_function << '\n';
    ss << "mov x9, x0\n";
    
    relocation_context.value()->set_type(R_AARCH64_CALL26);
    relocation_context.value()->add_addend(4);
    relocation_context.value()->set_converted();
    
    return ss.str();
}


size_t x86_call::converted_instructions_count() {
    return 2;
}


void x86_call::handle_known_offset_in_converted_function(size_t _offset) {
    if (relocation_context) {
        relocation_context.value()->set_offset(_offset);
    }
    offset_in_function = _offset;
}


x86_jmp::x86_jmp(std::string _mapped_mnemonic, std::string _label)
    : mapped_mnemonic(std::move(_mapped_mnemonic)) 
    , label_str(std::move(_label)) {}


std::string x86_jmp::convert_to_aarch64() {
    std::stringstream ss;
    apply_label(ss);
    
    ss << mapped_mnemonic << " " << label_str << '\n';
    return ss.str();
}


size_t x86_jmp::converted_instructions_count() {
    return 1;
}