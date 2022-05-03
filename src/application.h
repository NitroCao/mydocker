#ifndef _APPLICATION_H_
#define _APPLICATION_H_

#include <CLI/App.hpp>
#include <CLI/Config.hpp>
#include <CLI/Formatter.hpp>

namespace mydocker {
namespace app {

class application {
public:
    application();
    ~application();
    int run(int argc, char **argv);

private:
    enum subcommand {
        SUB_CREATE,
        SUB_RUN,
        SUB_NON_EXIST,
    };
    typedef std::pair<const char *, const char *> flag_desc;
    typedef struct subcomm {
        const char *name;
        const char *desc;
        const std::vector<flag_desc> flags;
        const std::vector<flag_desc> options;
    } subcomm;

    const std::map<subcommand, const subcomm> subcommands{
        {SUB_CREATE,
         subcomm{
             "create",
             "create a container",
             {},
             std::vector<flag_desc>{
                 flag_desc{"-b,--bundle",
                           "path to the root of the bundle directory, defaults to the current directory"},
                 flag_desc{"--pid-file", "specify the file to write the process id to"},
                 flag_desc{"--no-pivot", "do not use pivot root to jail process inside rootfs. "
                                         "This should be used whenever the rootfs is on top of a ramdisk"},
             },
         }},
        {SUB_RUN,
         subcomm{
             "run",
             "create and run a container",
             {},
             std::vector<flag_desc>{flag_desc{"-b,--bundle", "path to the root of the bundle directory, "
                                                             "defaults to the current directory"}},
         }},
    };

    CLI::App app;

    inline void create_subcommand(subcomm const &subc);
    inline int get_subcommand_idx(std::string const &subc) const;
};

}; // namespace app
}; // namespace mydocker

#endif // _APPLICATION_H_
