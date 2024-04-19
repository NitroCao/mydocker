#ifndef MYDOCKER_APP_H
#define MYDOCKER_APP_H

#include <CLI/CLI.hpp>
#include <variant>

#include "run.h"
#include "spec_app.h"

class App {
  private:
    bool                           debug;
    CLI::App                       app;
    std::variant<RunApp::run_args, SpecApp::spec_args> subcmd_args;

    CLI::App_p                          create_run_cmd();
    CLI::App_p                          create_spec_cmd();
    [[nodiscard]] std::function<void ()> pre_callback() const;

  public:
    App();

    int run(int argc, char **argv);
};

#endif // MYDOCKER_APP_H
