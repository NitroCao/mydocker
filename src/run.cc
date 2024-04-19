#include <filesystem>
#include <sys/wait.h>

#include <spdlog/spdlog.h>

#include "app.h"
#include "spec.h"

using json = nlohmann::json;

int RunApp::run_child(void *arg) {
    spdlog::debug("msg from child func");
    auto                      spec_config = (spec::Spec *)arg;
    const char               *exe_path = spec_config->process.args[0].c_str();
    auto exec_arg = create_exec_arg(*spec_config);

    auto ret = execve(exe_path, const_cast<char *const *>(exec_arg.first.data()),
                      const_cast<char *const *>(exec_arg.second.data()));
    if (ret == -1) {
        spdlog::error("failed to exec {}: {}", exe_path, strerror(errno));
        return ret;
    }
    return 0;
}

RunApp::exec_arg_t RunApp::create_exec_arg(const spec::Spec& config) {
    auto run_args = config.process.args;

    std::vector<const char*> args(run_args.size() + 1);
    for (int i = 0; i < args.size() - 1; ++i) {
        args[i] = run_args[i].c_str();
    }
    args[args.size() - 1] = nullptr;

    std::vector<const char*>envp(config.process.env.size() + 1);
    for (int i = 0; i < envp.size() - 1; ++i) {
        envp[i] = config.process.env[i].c_str();
    }
    envp[envp.size() - 1] = nullptr;

    return {args, envp};
}

std::function<void()> RunApp::run_callback(const RunApp::run_args &arg) {
    return [&]() {
        auto config_filename = std::filesystem::path(arg.bundle_dir) /
                               std::string(spec::spec_config);
        std::ifstream config_file(config_filename);
        if (!config_file.is_open()) {
            spdlog::error("failed to open {}", config_filename.string());
            exit(EXIT_FAILURE);
        }
        spec::Spec spec_config;
        try {
            spec_config = json::parse(config_file);
        } catch (std::exception &e) {
            std::cerr << std::format("failed to parse {}: {}",
                                     config_filename.string(), e.what());
            exit(EXIT_FAILURE);
        }

        int       ret, status;
        const int stack_size = 4096;
        char     *stack = new char[stack_size]{0};
        int       child_pid = clone(run_child, stack + stack_size,
                                    CLONE_NEWUTS | SIGCHLD, (void *)&spec_config);
        if (child_pid == -1) {
            spdlog::error("failed to create child process: {}",
                          strerror(errno));
            ret = EXIT_FAILURE;
            goto clean;
        }
        spdlog::debug("child process created, pid {}", child_pid);

        if ((ret = waitpid(child_pid, &status, 0)) == -1) {
            spdlog::error("failed to wait child process {}: {}", child_pid,
                          strerror(errno));
            goto clean;
        }
        if (WIFEXITED(status)) {
            spdlog::info("child {} exits with code {}", child_pid,
                         WEXITSTATUS(status));
        } else if (WIFSIGNALED(status)) {
            spdlog::info("child {} terminates with signal {}", child_pid,
                         WTERMSIG(status));
        }

    clean:
        delete[] stack;
        return ret;
    };
}
