#include <cassert>
#include <map>
#include <vector>
#include <spdlog/spdlog.h>

#include "application.h"
#include "config.h"
#include "spec_cmd.h"

namespace mydocker {
namespace app {

static const char *app_desc = "My own container runtime written in C++";

application::application() : app(app_desc, APP_NAME)
{
    app.add_flag("-d,--debug", "enable debug logging");

    for (auto &subc : subcommands)
        create_subcommand(subc.second);

    app.require_subcommand(1);
}

int application::run(int argc, char **argv)
{
    CLI11_PARSE(app, argc, argv);

    int ret = init_env();
    if (ret != 0)
        return ret;

    auto subcoms = app.get_subcommands();
    assert(subcoms.size() == 1 && "the command line only requires one subcommand");
    auto subcomm = subcoms[0];

    switch (get_subcommand_idx(subcomm->get_name())) {
    case SUB_CREATE:
        std::cout << "create subcommand create a container\n";
        break;
    case SUB_RUN: {
        std::cout << "run subcommand create and run a container\n";
        break;
    }
    case SUB_SPEC:
        return mydocker::spec::spec::run(subcomm);
        break;
    case SUB_NON_EXIST:
    default:
        std::cerr << "unknown subcommand\n";
        return 1;
    }

    return 0;
}

int application::init_env()
{
    int ret = 0;
    auto debug_opt = app.get_option("--debug");
    bool is_debug = debug_opt->as<bool>();
    if (is_debug) {
        spdlog::set_level(spdlog::level::debug);
    } else {
        spdlog::set_level(spdlog::level::info);
    }

    std::string json_pattern = {R"({"level": "%^%l%$", "time": "%Y-%m-%dT%H:%M:%S.%f%z", "process": %P, "thread": %t, "message": "%v"})"};
    spdlog::set_pattern(json_pattern);

    return ret;
}

void application::create_subcommand(subcomm const &subc)
{
    auto sub_comm = app.add_subcommand(subc.name, subc.desc);
    for (auto &flag : subc.flags)
        sub_comm->add_flag(flag.first, flag.second);
    for (auto &option : subc.options)
        sub_comm->add_option(option.first, option.second);
    sub_comm->allow_extras();
}

int application::get_subcommand_idx(std::string const &subc) const
{
    for (auto &sub_comm : subcommands) {
        if (std::string(sub_comm.second.name) == subc)
            return sub_comm.first;
    }

    return SUB_NON_EXIST;
}

application::~application() {}

}; // namespace app
}; // namespace mydocker
