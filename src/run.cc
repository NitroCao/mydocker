#include "app.h"
#include <spdlog/spdlog.h>
#include <sys/wait.h>

int RunApp::run_child(void *arg) {
    spdlog::debug("msg from child func");
    auto                      run_args = (RunApp::run_args *)arg;
    const char               *exe_path = run_args->command.c_str();
    std::vector<const char *> args = {exe_path, nullptr};
    std::vector<const char *> envp = {"PATH=/bin:/sbin:/usr/bin:/usr/sbin",
                                      nullptr};
    auto ret = execve(exe_path, const_cast<char *const *>(args.data()),
                      const_cast<char *const *>(envp.data()));
    if (ret == -1) {
        spdlog::error("failed to exec {}: {}", exe_path, strerror(errno));
        return ret;
    }
    return 0;
}

std::function<void()> RunApp::run_callback(const RunApp::run_args &arg) {
    return [&]() {
        int       ret, status;
        const int stack_size = 4096;
        char     *stack = new char[stack_size]{0};
        int       child_pid = clone(run_child, stack + stack_size,
                                    CLONE_NEWUTS | SIGCHLD, (void *)&arg);
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
