#ifndef _SPEC_CMD_H_
#define _SPEC_CMD_H_

#include <CLI/App.hpp>
#include <cstring>
#include <fstream>
#include <sys/stat.h>
#include <unistd.h>
#include <spdlog/spdlog.h>

#include "specs.h"

namespace mydocker {
namespace spec {
using json = nlohmann::json;

class spec {
public:
    static int run(CLI::App const *const app)
    {
        std::string bundle_dir;

        spdlog::debug("Creating sample config.json under current directory");
        auto bundle_option = app->get_option("--bundle");
        if (bundle_option != nullptr) {
            auto results = bundle_option->results();
            if (results.size() > 0)
                bundle_dir = results.at(0);
        }

        return run(bundle_dir);
    }

    static int run(std::string const &bundle_dir)
    {
        json default_spec = default_config();

        // Change current working directory to the specified bundle dir.
        if (!bundle_dir.empty()) {
            if (chdir(bundle_dir.c_str()) != 0) {
                spdlog::error("Failed to chdir to bundle directory {}: {}", bundle_dir, strerror(errno));
                return errno;
            }
        }

        struct stat file_info;
        if (stat(specs::spec_config, &file_info) == 0) {
            spdlog::error("{} file already exists in the bundle directory. Remove it first.", specs::spec_config);
            return 1;
        }

        try {
            std::ofstream spec_file(specs::spec_config);
            spec_file.exceptions(std::ofstream::badbit | std::ofstream::failbit);

            spec_file << default_spec.dump(2) << std::endl;
        }
        catch (std::ofstream::failure &e) {
            spdlog::error("Failed to create {}: {}", specs::spec_config, strerror(errno));
            return e.code().value();
        }

        return 0;
    }

private:
    static specs::Spec default_config()
    {
        return specs::Spec{
            .version = specs::version(),
            .process =
                specs::Process{
                    .terminal = true,
                    .user = specs::User{},
                    .args = std::vector<std::string>{"sh"},
                    .env = std::vector<std::string>{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                                                    "TERM=xterm"},
                    .cwd = "/",
                    .capabilities =
                        specs::LinuxCapabilities{
                            .bounding = std::vector<std::string>{"CAP_AUDIT_WRITE", "CAP_KILL", "CAP_NET_BIND_SERVICE"},
                            .effective =
                                std::vector<std::string>{"CAP_AUDIT_WRITE", "CAP_KILL", "CAP_NET_BIND_SERVICE"},
                            .inheritable =
                                std::vector<std::string>{"CAP_AUDIT_WRITE", "CAP_KILL", "CAP_NET_BIND_SERVICE"},
                            .permitted =
                                std::vector<std::string>{"CAP_AUDIT_WRITE", "CAP_KILL", "CAP_NET_BIND_SERVICE"},
                            .ambient = std::vector<std::string>{"CAP_AUDIT_WRITE", "CAP_KILL", "CAP_NET_BIND_SERVICE"}},
                    .rlimits =
                        std::vector<specs::POSIXRlimit>{
                            specs::POSIXRlimit{.type = "RLIMIT_NOFILE", .hard = 1024, .soft = 1024},
                        },
                    .no_new_privileges = true,
                },
            .root = specs::Root{.path = "rootfs", .read_only = true},
            .hostname = "runc",
            .mounts =
                std::vector<specs::Mount>{
                    specs::Mount{.destination = "/proc",
                                 .type = "proc",
                                 .source = "proc",
                                 .options = std::vector<std::string>{}},
                    specs::Mount{.destination = "/dev",
                                 .type = "tmpfs",
                                 .source = "tmpfs",
                                 .options =
                                     std::vector<std::string>{"nosuid", "strictatime", "mode=755", "size=65536k"}},
                    specs::Mount{.destination = "/dev/pts",
                                 .type = "devpts",
                                 .source = "devpts",
                                 .options = std::vector<std::string>{"nosuid", "noexec", "newinstance",
                                                                     "ptmxmode=0666", "mode=0620", "gid=5"}},
                    specs::Mount{.destination = "/dev/shm",
                                 .type = "tmpfs",
                                 .source = "shm",
                                 .options =
                                     std::vector<std::string>{"nosuid", "noexec", "nodev", "mode=1777", "size=65536k"}},
                    specs::Mount{.destination = "/dev/mqueue",
                                 .type = "mqueue",
                                 .source = "mqueue",
                                 .options = std::vector<std::string>{"nosuid", "noexec", "nodev"}},
                    specs::Mount{.destination = "/sys",
                                 .type = "sysfs",
                                 .source = "sysfs",
                                 .options = std::vector<std::string>{"nosuid", "noexec", "nodev", "ro"}},
                    specs::Mount{.destination = "/sys/fs/cgroup",
                                 .type = "cgroup",
                                 .source = "cgroup",
                                 .options = std::vector<std::string>{"nosuid", "noexec", "nodev", "relatime", "ro"}},
                },
            ._linux =
                specs::Linux{
                    .resources =
                        specs::LinuxResources{
                            .devices = std::vector<specs::LinuxDeviceCgroup>{specs::LinuxDeviceCgroup{.allow = false,
                                                                                                      .access = "rwm"}},
                        },
                    .namespaces =
                        std::vector<specs::LinuxNamespace>{specs::LinuxNamespace{.type = specs::pid_namespace},
                                                           specs::LinuxNamespace{.type = specs::network_namespaec},
                                                           specs::LinuxNamespace{.type = specs::ipc_namespace},
                                                           specs::LinuxNamespace{.type = specs::uts_namespace},
                                                           specs::LinuxNamespace{.type = specs::mount_namespace}},
                    .masked_paths =
                        std::vector<std::string>{"/proc/acpi", "/proc/asound", "/proc/kcore", "/proc/keys",
                                                 "/proc/latency_stats", "/proc/timer_list", "/proc/timer_stats",
                                                 "/proc/sched_debug", "/sys/firmware", "/proc/scsi"},
                    .read_only_paths = std::vector<std::string>{"/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys",
                                                                "/proc/sysrq-trigger"},
                },
        };
    }
};
}; // namespace spec
}; // namespace mydocker

#endif // _SPEC_CMD_H_
