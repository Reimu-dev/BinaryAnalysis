#include <stdio.h>
#include <string>
#include <queue>
#include <map>
#include <capstone/capstone.h>
#include "Loader.h"
#include "OptionParser.h"

int disasm(Binary *bin);
void print_ins(cs_insn *ins);
bool is_cs_cflow_group(uint8_t g);
bool is_cs_cflow_ins(cs_insn *ins);
bool is_cs_unconditional_cflow_ins(cs_insn *ins);
uint64_t get_cs_ins_immediate_target(cs_insn *ins);

int main(int argc, char *argv[])
{
    Binary bin;
    std::string fname;

    char usage[100];
    sprintf(usage, "%s -b <binary>", argv[0]);
    OptionParser option_parser = OptionParser(usage);
    option_parser.add_option("-b", "string", "binary", "target binary");
    option_parser.options(argc, argv);

    std::variant<std::string, int, bool> fname_temp;
    fname_temp = option_parser.get_value("binary");
    if(std::get_if<bool>(&fname_temp))
    {
        fprintf(stderr, "not set such dest 'binary'\n");
        option_parser.print_help();
        return 1;
    }
    fname = std::get<std::string>(fname_temp);

    if(load_binary(fname, &bin, Binary::BIN_TYPE_AUTO) < 0)
    {
        return 1;
    }

    if(disasm(&bin) < 0)
    {
        return 1;
    }

    unload_binary(&bin);

    return 0;
}

int disasm(Binary *bin)
{
    csh dis;
    cs_insn *cs_ins;
    Section *text;
    size_t n;
    const uint8_t *pc;
    uint64_t addr, offset, target;
    std::queue<uint64_t> Q;
    std::map<uint64_t, bool> seen;

    text = bin->get_text_section();
    if(!text)
    {
        fprintf(stderr, "Nothing to disassemble\n");
        return 0;
    }

    if(cs_open(CS_ARCH_X86, CS_MODE_64, &dis) != CS_ERR_OK)
    {
        fprintf(stderr, "Faild to open Capstone\n");
        return -1;
    }
    cs_option(dis, CS_OPT_DETAIL, CS_OPT_ON);

    cs_ins = cs_malloc(dis);
    if(!cs_ins)
    {
        fprintf(stderr, "Out of memory\n");
        cs_close(&dis);
        return -1;
    }

    addr = bin->entry;
    if(text->contains(addr)) Q.push(addr);

    printf("entry point: 0x%016jx\n", addr);

    for(auto &sym: bin->symbols)
    {
        if(sym.type == Symbol::SYM_TYPE_FUNC && text->contains(sym.addr))
        {
            Q.push(sym.addr);
            printf("function symbol: 0x%016x\n", sym.addr);
        }
    }

    while(!Q.empty())
    {
        addr = Q.front();
        Q.pop();
        if(seen[addr]) continue;

        offset = addr - text->vma;
        pc = text->bytes + offset;
        n = text->size - offset;

        while (cs_disasm_iter(dis, &pc, &n, &addr, cs_ins))
        {
            if(cs_ins->id == X86_INS_INVALID || cs_ins->size == 0)
            {
                break;
            }

            seen[cs_ins->address] = true;
            print_ins(cs_ins);

            if(is_cs_cflow_ins(cs_ins))
            {
                target = get_cs_ins_immediate_target(cs_ins);
                if(target && !seen[target] && text->contains(target))
                {
                    Q.push(target);
                    printf("  -> new target: 0x%016jx\n", target);
                }
                if(is_cs_unconditional_cflow_ins(cs_ins))
                {
                    break;
                }
            }
            else if(cs_ins->id == X86_INS_HLT)
            {
                break;
            }
        }
        printf("---------------\n");
    }

    cs_free(cs_ins, 1);
    cs_close(&dis);

    return 0;
}

void print_ins(cs_insn *ins)
{
    size_t i;

    printf("0x%08jx: ", ins->address);
    for(i = 0; i < 10; i++)
    {
        if(i < ins->size)
        {
            printf("%02x ", ins->bytes[i]);
        }
        else
        {
            printf("   ");
        }
    }
    printf("%-12s %s\n", ins->mnemonic, ins->op_str);
}

bool is_cs_cflow_group(uint8_t g)
{
    return (g == CS_GRP_JUMP) || (g == CS_GRP_CALL) || (g == CS_GRP_RET) || (g == CS_GRP_IRET);
}

bool is_cs_cflow_ins(cs_insn *ins)
{
    size_t i;
    for(i = 0; i < ins->detail->groups_count; i++)
    {
        if(is_cs_cflow_group(ins->detail->groups[i]))
        {
            return true;
        }
    }

    return false;
}

bool is_cs_unconditional_cflow_ins(cs_insn *ins)
{
    switch (ins->id)
    {
    case X86_INS_JMP:
    case X86_INS_LJMP:
    case X86_INS_RET:
    case X86_INS_RETF:
    case X86_INS_RETFQ:
        return true;
    default:
        return false;
    }
}

uint64_t get_cs_ins_immediate_target(cs_insn *ins)
{
    cs_x86_op *cs_op;
    size_t i, j;

    for(i = 0; i < ins->detail->groups_count; i++)
    {
        if(is_cs_cflow_group(ins->detail->groups[i]))
        {
            for(j = 0; j < ins->detail->x86.op_count; j++)
            {
                cs_op = &ins->detail->x86.operands[j];
                if(cs_op->type == X86_OP_IMM)
                {
                    return cs_op->imm;
                }
            }
        }
    }

    return 0;
}
