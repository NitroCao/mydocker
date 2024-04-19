#include <filesystem>
#include <sys/wait.h>

#include <spdlog/spdlog.h>

#include "app.h"
#include "spec.h"

using json = nlohmann::json;

int RunApp::run_child(void *arg) {
    spdlog::debug("msg from child func");
    auto                      spec_config = (spec::Spec *)arg;
    auto exe_path = find_exe(*spec_config);
    auto exec_arg = create_exec_arg(*spec_config);

    auto ret = execve(exe_path.c_str(), const_cast<char *const *>(exec_arg.first.data()),
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

std::string RunApp::find_exe(const spec::Spec &config) {
    auto exe_name = config.process.args[0];
    if (exe_name.starts_with('/')) {
        return exe_name;
    }

    const char *PATH_ENV = "PATH=";
    for (auto const& each : config.process.env) {
        auto pos = each.find(PATH_ENV);
        if (pos == std::string::npos)
            continue;
        auto path_env = std::string(each, strlen(PATH_ENV));

        auto exe_path = _find_exe(path_env, exe_name);
        if (exe_path.has_value())
            return exe_path.value();
    }

    return exe_name;
}

std::optional<std::string> RunApp::_find_exe(const std::string &path_env, const std::string &exe_name) {
    std::string::size_type begin_pos = 0, pos;
    while ((pos = path_env.find(':', begin_pos)) != std::string::npos) {
        auto each_path = std::string(path_env.begin() + begin_pos, path_env.begin() + pos);
        auto exe_path = std::filesystem::path(each_path) / exe_name;
        if (std::filesystem::exists(exe_path))
            return exe_path;
        begin_pos = pos + 1;
    }

    return {};
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
