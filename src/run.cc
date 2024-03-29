#include "app.h"

std::function<void()> RunApp::run_callback(const run_args& args) {
    return [&]() {
        std::cout << "This command will create and run a container"
                     "executing command" << args.command << "\n";
    };
}
