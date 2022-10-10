#ifndef OptionParser_H
#define OptionParser_H

#include <stdint.h>
#include <string.h>
#include <string>
#include <vector>
#include <variant>

class ARG
{
public:
    std::string name;
    std::string dest;
    std::string type;
    std::string help;
    std::variant<std::string, int, bool> value;
};

class OptionParser
{
public:
    std::string USAGE;
    std::vector<ARG> args;

    OptionParser(std::string usage)
    {
        USAGE = usage;
    }

    void add_option(std::string name, std::string type, std::string dest, std::string help)
    {
        args.push_back(ARG());
        ARG *arg = &args.back();

        arg->name = name;
        arg->type = type;
        arg->dest = dest;
        arg->help = help;
        arg->value = true;
    }

    void options(int argc, char *argv[])
    {
        size_t i, j;

        for(i=1; i<argc; i++)
        {
            if(!strcmp(argv[i], "-h") | !strcmp(argv[i], "--help"))
            {
                print_help();
                exit(0);
            }

            if(argv[i][0] == '-')
            {
                if(argv[i][1] == '-')
                {
                    for(j=0; j<args.size(); j++)
                    {
                        std::string target_dest = "--" + args[j].dest;
                        if(!strcmp(argv[i], target_dest.c_str()))
                        {
                            if(args[j].type == "int")
                            {
                                args[j].value = atoi(argv[i+1]);
                            }
                            else
                            {
                                args[j].value = argv[i+1];
                            }
                            break;
                        }
                    }
                    
                }
                else
                {
                    for(j=0; j<args.size(); j++)
                    {
                        std::string target_name = args[j].name;
                        if(!strcmp(argv[i], target_name.c_str()))
                        {
                            if(args[j].type == "int")
                            {
                                args[j].value = atoi(argv[i+1]);
                            }
                            else
                            {
                                args[j].value = argv[i+1];
                            }
                            break;
                        }
                    }
                }
            }
        }
    }

    std::variant<std::string, int, bool> get_value(std::string dest)
    {
        std::variant<std::string, int, bool> value;
        size_t i;
        
        for(i=0; i<args.size(); i++)
        {
            if(args[i].dest == dest)
            {
                value = args[i].value;
                break;
            }
        }

        return value;
    }

    void print_help()
    {
        size_t i;

        printf("\nUsage:\n");
        printf("\t%s\n", USAGE.c_str());
        printf("Arguments:\n");
        for (i=0; i<args.size(); i++)
        {
            printf("\t%s --%s:\t%s\n", args[i].name.c_str(), args[i].dest.c_str(), args[i].help.c_str());
        }
    }
};

#endif