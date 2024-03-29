#ifndef MYDOCKER_APP_H
#define MYDOCKER_APP_H

#include <CLI/CLI.hpp>
#include <variant>

#include "run.h"

class App {
  private:
    bool                           debug;
    CLI::App                       app;
    std::variant<RunApp::run_args> subcmd_args;

    [[nodiscard]] CLI::App_p create_run_cmd();
    [[nodiscard]] std::function<void ()> pre_callback() const;

  public:
    App();

    int run(int argc, char **argv);
};

#endif // MYDOCKER_APP_H
