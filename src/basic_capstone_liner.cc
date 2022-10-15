#include <stdio.h>
#include <string>
#include <capstone/capstone.h>
#include "Loader.h"
#include "OptionParser.h"

int disasm(Binary *bin);

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
    cs_insn *insns;
    Section *text;
    size_t n, i, j;

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

    n = cs_disasm(dis, text->bytes, text->size, text->vma, 0, &insns);
    if(n <= 0)
    {
        fprintf(stderr, "Disassembly error: %s\n", cs_strerror(cs_errno(dis)));
        return -1;
    }

    for(i = 0; i < n; i++)
    {
        printf("0x%08jx: ", insns[i].address);
        for(j = 0; j < 10; j++)
        {
            if(j < insns[i].size)
            {
                printf("%02x ", insns[i].bytes[j]);
            }
            else 
            {
                printf("   ");
            }
        }
        printf("%-12s %s\n", insns[i].mnemonic, insns[i].op_str);
    }

    cs_free(insns, n);
    cs_close(&dis);

    return 0;
}
