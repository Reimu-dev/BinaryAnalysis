#include <stdio.h>
#include <stdint.h>
#include <string>
#include "Loader.h"
#include "OptionParser.h"

void analysis_binary(Binary bin)
{
    size_t i;
    Section *sec;
    Symbol *sym;

    printf("loaded binary '%s' %s/%s (%u bits) entry@0x%016jx\n",
            bin.filename.c_str(),
            bin.type_str.c_str(),
            bin.arch_str.c_str(),
            bin.bits, bin.entry);

    for(i=0; i<bin.sections.size(); i++)
    {
        sec = &bin.sections[i];
        printf(" 0x%016jx %-8ju %-20s %s\n",
                sec->vma, sec->size, sec->name.c_str(),
                sec->type == Section::SEC_TYPE_CODE ? "CODE" : "DATA");
    }
    printf("\n");

    if(bin.symbols.size() > 0)
    {
        printf("scanned symbol tables\n");
        for(i=0; i<bin.symbols.size(); i++)
        {
            sym = &bin.symbols[i];
            printf(" %-40s 0x%016jx %s\n",
                    sym->name.c_str(), (long unsigned int) sym->addr,
                    (sym->type & Symbol::SYM_TYPE_FUNC) ? "FUNC" : "");
        }
    }
}

void print_section(Binary bin, std::string secname)
{
    size_t i;
    Section *sec;
    uint64_t size, index;
    uint8_t *bytes;

    for(i=0; i<bin.sections.size(); i++)
    {
        sec = &bin.sections[i];
        if(sec->name == secname)
        {
            printf("Section %s:", secname.c_str());
            size = sec->size;
            bytes = sec->bytes;
            for(index=0; index<size; index++)
            {
                if(index%16 == 0)
                {
                    printf("\n");
                    printf("%08lx: ", index);
                }
                printf("%02x ", bytes[index]);
            }
            printf("\n");
        }
    }
}

int main(int argc, char *argv[])
{
    Binary bin;
    std::string fname;
    std::string secname;

    char usage[100];
    sprintf(usage, "%s -b <binary>", argv[0]);
    OptionParser option_parser = OptionParser(usage);
    option_parser.add_option("-b", "string", "binary", "target binary");
    option_parser.add_option("-s", "string", "section", "target section");
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

    std::variant<std::string, int, bool> secname_temp;
    secname_temp = option_parser.get_value("section");
    if(std::get_if<bool>(&secname_temp))
    {
        analysis_binary(bin);
    }
    else
    {
        secname = std::get<std::string>(secname_temp);
        print_section(bin, secname);
    }
    

    unload_binary(&bin);

    return 0;
}