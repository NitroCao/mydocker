#include <spdlog/spdlog.h>

#include "app.h"
#include "spec_app.h"

App::App() : debug(false) {
    app.add_flag("-d,--debug", debug, "Enable debug mode");

    app.add_subcommand(create_run_cmd());
    app.add_subcommand(create_spec_cmd());
    app.require_subcommand(1);
    app.positionals_at_end(true);
    app.parse_complete_callback(pre_callback());
}

std::function<void ()> App::pre_callback() const {
    return [&]() {
        auto log_level = debug ? spdlog::level::debug : spdlog::level::info;
        spdlog::set_level(log_level);
    };
}

int App::run(int argc, char **argv) {
    try {
        CLI11_PARSE(app, argc, argv)
    } catch (CLI::ParseError &e) {
        app.exit(e);
    }

    return 0;
}

CLI::App_p App::create_run_cmd() {
    subcmd_args = RunApp::run_args{};
    auto run = std::make_shared<CLI::App>("Create and run a container", "run");
    run->add_option("COMMAND", std::get<RunApp::run_args>(subcmd_args).command,
                    "Command to run");
    run->callback(
        RunApp::run_callback(std::get<RunApp::run_args>(subcmd_args)));

    return run;
}
CLI::App_p App::create_spec_cmd() {
    subcmd_args = SpecApp::spec_args{
        .bundle = ".",
    };
    auto spec_cmd =
        std::make_shared<CLI::App>("create a new specification file", "spec");
    spec_cmd->add_option("-b,--bundle",
                         std::get<SpecApp::spec_args>(subcmd_args).bundle,
                         "path to the root of the bundle directory");
    spec_cmd->add_option("--rootless",
                         std::get<SpecApp::spec_args>(subcmd_args).rootless,
                         "generate a configuration for a rootless container");
    spec_cmd->callback(
        SpecApp::spec_callback(std::get<SpecApp::spec_args>(subcmd_args)));

    return spec_cmd;
}
