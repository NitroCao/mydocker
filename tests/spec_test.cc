#include <gtest/gtest.h>

#include "spec.h"

using json = nlohmann::json;

TEST(SpecTests, Deserialize) {
    const char *default_config =
        "{\n"
        "        \"ociVersion\": \"1.0.2-dev\",\n"
        "        \"process\": {\n"
        "                \"terminal\": true,\n"
        "                \"user\": {\n"
        "                        \"uid\": 0,\n"
        "                        \"gid\": 0\n"
        "                },\n"
        "                \"args\": [\n"
        "                        \"sh\"\n"
        "                ],\n"
        "                \"env\": [\n"
        "                        "
        "\"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/"
        "bin\",\n"
        "                        \"TERM=xterm\"\n"
        "                ],\n"
        "                \"cwd\": \"/\",\n"
        "                \"capabilities\": {\n"
        "                        \"bounding\": [\n"
        "                                \"CAP_AUDIT_WRITE\",\n"
        "                                \"CAP_KILL\",\n"
        "                                \"CAP_NET_BIND_SERVICE\"\n"
        "                        ],\n"
        "                        \"effective\": [\n"
        "                                \"CAP_AUDIT_WRITE\",\n"
        "                                \"CAP_KILL\",\n"
        "                                \"CAP_NET_BIND_SERVICE\"\n"
        "                        ],\n"
        "                        \"permitted\": [\n"
        "                                \"CAP_AUDIT_WRITE\",\n"
        "                                \"CAP_KILL\",\n"
        "                                \"CAP_NET_BIND_SERVICE\"\n"
        "                        ],\n"
        "                        \"ambient\": [\n"
        "                                \"CAP_AUDIT_WRITE\",\n"
        "                                \"CAP_KILL\",\n"
        "                                \"CAP_NET_BIND_SERVICE\"\n"
        "                        ]\n"
        "                },\n"
        "                \"rlimits\": [\n"
        "                        {\n"
        "                                \"type\": \"RLIMIT_NOFILE\",\n"
        "                                \"hard\": 1024,\n"
        "                                \"soft\": 1024\n"
        "                        }\n"
        "                ],\n"
        "                \"noNewPrivileges\": true\n"
        "        },\n"
        "        \"root\": {\n"
        "                \"path\": \"rootfs\",\n"
        "                \"readonly\": true\n"
        "        },\n"
        "        \"hostname\": \"runc\",\n"
        "        \"mounts\": [\n"
        "                {\n"
        "                        \"destination\": \"/proc\",\n"
        "                        \"type\": \"proc\",\n"
        "                        \"source\": \"proc\"\n"
        "                },\n"
        "                {\n"
        "                        \"destination\": \"/dev\",\n"
        "                        \"type\": \"tmpfs\",\n"
        "                        \"source\": \"tmpfs\",\n"
        "                        \"options\": [\n"
        "                                \"nosuid\",\n"
        "                                \"strictatime\",\n"
        "                                \"mode=755\",\n"
        "                                \"size=65536k\"\n"
        "                        ]\n"
        "                },\n"
        "                {\n"
        "                        \"destination\": \"/dev/pts\",\n"
        "                        \"type\": \"devpts\",\n"
        "                        \"source\": \"devpts\",\n"
        "                        \"options\": [\n"
        "                                \"nosuid\",\n"
        "                                \"noexec\",\n"
        "                                \"newinstance\",\n"
        "                                \"ptmxmode=0666\",\n"
        "                                \"mode=0620\",\n"
        "                                \"gid=5\"\n"
        "                        ]\n"
        "                },\n"
        "                {\n"
        "                        \"destination\": \"/dev/shm\",\n"
        "                        \"type\": \"tmpfs\",\n"
        "                        \"source\": \"shm\",\n"
        "                        \"options\": [\n"
        "                                \"nosuid\",\n"
        "                                \"noexec\",\n"
        "                                \"nodev\",\n"
        "                                \"mode=1777\",\n"
        "                                \"size=65536k\"\n"
        "                        ]\n"
        "                },\n"
        "                {\n"
        "                        \"destination\": \"/dev/mqueue\",\n"
        "                        \"type\": \"mqueue\",\n"
        "                        \"source\": \"mqueue\",\n"
        "                        \"options\": [\n"
        "                                \"nosuid\",\n"
        "                                \"noexec\",\n"
        "                                \"nodev\"\n"
        "                        ]\n"
        "                },\n"
        "                {\n"
        "                        \"destination\": \"/sys\",\n"
        "                        \"type\": \"sysfs\",\n"
        "                        \"source\": \"sysfs\",\n"
        "                        \"options\": [\n"
        "                                \"nosuid\",\n"
        "                                \"noexec\",\n"
        "                                \"nodev\",\n"
        "                                \"ro\"\n"
        "                        ]\n"
        "                },\n"
        "                {\n"
        "                        \"destination\": \"/sys/fs/cgroup\",\n"
        "                        \"type\": \"cgroup\",\n"
        "                        \"source\": \"cgroup\",\n"
        "                        \"options\": [\n"
        "                                \"nosuid\",\n"
        "                                \"noexec\",\n"
        "                                \"nodev\",\n"
        "                                \"relatime\",\n"
        "                                \"ro\"\n"
        "                        ]\n"
        "                }\n"
        "        ],\n"
        "        \"linux\": {\n"
        "                \"resources\": {\n"
        "                        \"devices\": [\n"
        "                                {\n"
        "                                        \"allow\": false,\n"
        "                                        \"access\": \"rwm\"\n"
        "                                }\n"
        "                        ]\n"
        "                },\n"
        "                \"namespaces\": [\n"
        "                        {\n"
        "                                \"type\": \"pid\"\n"
        "                        },\n"
        "                        {\n"
        "                                \"type\": \"network\"\n"
        "                        },\n"
        "                        {\n"
        "                                \"type\": \"ipc\"\n"
        "                        },\n"
        "                        {\n"
        "                                \"type\": \"uts\"\n"
        "                        },\n"
        "                        {\n"
        "                                \"type\": \"mount\"\n"
        "                        }\n"
        "                ],\n"
        "                \"maskedPaths\": [\n"
        "                        \"/proc/acpi\",\n"
        "                        \"/proc/asound\",\n"
        "                        \"/proc/kcore\",\n"
        "                        \"/proc/keys\",\n"
        "                        \"/proc/latency_stats\",\n"
        "                        \"/proc/timer_list\",\n"
        "                        \"/proc/timer_stats\",\n"
        "                        \"/proc/sched_debug\",\n"
        "                        \"/sys/firmware\",\n"
        "                        \"/proc/scsi\"\n"
        "                ],\n"
        "                \"readonlyPaths\": [\n"
        "                        \"/proc/bus\",\n"
        "                        \"/proc/fs\",\n"
        "                        \"/proc/irq\",\n"
        "                        \"/proc/sys\",\n"
        "                        \"/proc/sysrq-trigger\"\n"
        "                ]\n"
        "        }\n"
        "}";

    spec::Spec expected{
        .version = "1.0.2-dev",
        .process =
            {
                .terminal = true,
                .args = {"sh"},
                .env = {"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/"
                        "bin:/sbin:/bin",
                        "TERM=xterm"},
                .cwd = "/",
                .capabilities =
                    {
                        .bounding = {"CAP_AUDIT_WRITE", "CAP_KILL",
                                     "CAP_NET_BIND_SERVICE"},
                        .effective = {"CAP_AUDIT_WRITE", "CAP_KILL",
                                      "CAP_NET_BIND_SERVICE"},
                        .permitted = {"CAP_AUDIT_WRITE", "CAP_KILL",
                                      "CAP_NET_BIND_SERVICE"},
                        .ambient = {"CAP_AUDIT_WRITE", "CAP_KILL",
                                    "CAP_NET_BIND_SERVICE"},
                    },
                .rlimits = {{
                    .type = "RLIMIT_NOFILE",
                    .hard = 1024,
                    .soft = 1024,
                }},
                .noNewPrivileges = true,
            },
        .root =
            {
                .path = "rootfs",
                .readonly = true,
            },
        .hostname = "runc",
        .mounts =
            {{
                 .destination = "/proc",
                 .type = "proc",
                 .source = "proc",
             },
             {.destination = "/dev",
              .type = "tmpfs",
              .source = "tmpfs",
              .options = {"nosuid", "strictatime", "mode=755", "size=65536k"}},
             {.destination = "/dev/pts",
              .type = "devpts",
              .source = "devpts",
              .options = {"nosuid", "noexec", "newinstance", "ptmxmode=0666",
                          "mode=0620", "gid=5"}},
             {.destination = "/dev/shm",
              .type = "tmpfs",
              .source = "shm",
              .options = {"nosuid", "noexec", "nodev", "mode=1777",
                          "size=65536k"}},
             {.destination = "/dev/mqueue",
              .type = "mqueue",
              .source = "mqueue",
              .options = {"nosuid", "noexec", "nodev"}},
             {.destination = "/sys",
              .type = "sysfs",
              .source = "sysfs",
              .options = {"nosuid", "noexec", "nodev", "ro"}},
             {.destination = "/sys/fs/cgroup",
              .type = "cgroup",
              .source = "cgroup",
              .options = {"nosuid", "noexec", "nodev", "relatime", "ro"}}},
        ._linux = {.resources = {.devices = {{
                                     .allow = false,
                                     .access = "rwm",
                                 }}},
                   .namespaces = {{
                                      .type = "pid",
                                  },
                                  {
                                      .type = "network",
                                  },
                                  {
                                      .type = "ipc",
                                  },
                                  {
                                      .type = "uts",
                                  },
                                  {
                                      .type = "mount",
                                  }},
                   .maskedPaths =
                       {

                           "/proc/acpi", "/proc/asound", "/proc/kcore",
                           "/proc/keys", "/proc/latency_stats",
                           "/proc/timer_list", "/proc/timer_stats",
                           "/proc/sched_debug", "/sys/firmware", "/proc/scsi"},
                   .readonlyPaths = {"/proc/bus", "/proc/fs", "/proc/irq",
                                     "/proc/sys", "/proc/sysrq-trigger"}}};
    spec::Spec obj = json::parse(default_config);

    ASSERT_EQ(expected, obj);
}