#ifndef MYDOCKER_SPEC_H
#define MYDOCKER_SPEC_H

#include <map>
#include <memory>
#include <nlohmann/json.hpp>
#include <sstream>
#include <string>
#include <vector>

namespace spec {

using json = nlohmann::json;

static const char *spec_config = "config.json";
const int          version_major = 1;
const int          version_minor = 0;
const int          version_patch = 2;

static inline std::string version() {
    std::stringstream ver;
    ver << version_major << "." << version_minor << "." << version_patch;
    return ver.str();
}

typedef struct Box {
    unsigned int height = 0;
    unsigned int width = 0;

    inline friend bool operator==(const Box &a, const Box &b) {
        return std::tie(a.height, a.width) == std::tie(b.height, b.width);
    };
} Box;
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT(Box, height, width);

typedef struct User {
    unsigned int              uid = 0;
    unsigned int              gid = 0;
    unsigned int              umask = 0;
    std::vector<unsigned int> additionalGids;
    std::string               username;

    friend bool operator==(const User &a, const User &b) {
        return std::tie(a.uid, a.gid, a.umask, a.additionalGids, a.username) ==
               std::tie(b.uid, b.gid, b.umask, b.additionalGids, b.username);
    }
} User;
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT(User, uid, gid, umask,
                                                additionalGids, username);

typedef struct LinuxCapabilities {
    std::vector<std::string> bounding;
    std::vector<std::string> effective;
    std::vector<std::string> inheritable;
    std::vector<std::string> permitted;
    std::vector<std::string> ambient;

    friend bool operator==(const LinuxCapabilities &a,
                           const LinuxCapabilities &b) {
        return std::tie(a.bounding, a.effective, a.inheritable, a.permitted,
                        a.ambient) == std::tie(b.bounding, b.effective,
                                               b.inheritable, b.permitted,
                                               b.ambient);
    }
} LinuxCapabilities;
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT(LinuxCapabilities, bounding,
                                                effective, inheritable,
                                                permitted, ambient);

typedef struct POSIXRlimit {
    std::string   type;
    unsigned long hard = 0;
    unsigned long soft = 0;

    friend bool operator==(const POSIXRlimit &a, const POSIXRlimit &b) {
        return std::tie(a.type, a.hard, a.soft) ==
               std::tie(b.type, b.hard, b.soft);
    }
} POSIXRlimit;
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT(POSIXRlimit, type, hard, soft);

typedef struct Process {
    bool                     terminal;
    Box                      consoleSize;
    User                     user;
    std::vector<std::string> args;
    std::vector<std::string> env;
    std::string              cwd;
    LinuxCapabilities        capabilities;
    std::vector<POSIXRlimit> rlimits;
    bool                     noNewPrivileges;
    std::string              apparmorProfile;
    int                      oomScoreAdj;
    std::string              selinuxLabel;

    friend bool operator==(const Process &a, const Process &b) {
        return std::tie(a.terminal, a.consoleSize, a.user, a.args, a.env, a.cwd,
                        a.capabilities, a.rlimits, a.noNewPrivileges,
                        a.apparmorProfile, a.oomScoreAdj, a.selinuxLabel) ==
               std::tie(b.terminal, b.consoleSize, b.user, b.args, b.env, b.cwd,
                        b.capabilities, b.rlimits, b.noNewPrivileges,
                        b.apparmorProfile, b.oomScoreAdj, b.selinuxLabel);
    }
} Process;
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT(
    Process, terminal, consoleSize, user, args, env, cwd, capabilities, rlimits,
    noNewPrivileges, apparmorProfile, oomScoreAdj, selinuxLabel);

typedef struct Root {
    std::string path;
    bool        readonly = false;

    friend bool operator==(const Root &a, const Root &b) {
        return std::tie(a.path, a.readonly) == std::tie(b.path, b.readonly);
    }
} Root;
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT(Root, path, readonly);

typedef struct Mount {
    std::string              destination;
    std::string              type;
    std::string              source;
    std::vector<std::string> options;

    friend bool operator==(const Mount &a, const Mount &b) {
        return std::tie(a.destination, a.type, a.source, a.options) ==
               std::tie(b.destination, b.type, b.source, b.options);
    }
} Mount;
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT(Mount, destination, type,
                                                source, options);

typedef struct Hook {
    std::string              path;
    std::vector<std::string> args;
    std::vector<std::string> env;
    int                      timeout = 0;

    friend bool operator==(const Hook &a, const Hook &b) {
        return std::tie(a.path, a.args, a.env, a.timeout) ==
               std::tie(b.path, b.args, b.env, b.timeout);
    }
} Hook;
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT(Hook, path, args, env, timeout);

typedef struct Hooks {
    std::vector<Hook> prestart;
    std::vector<Hook> createRuntime;
    std::vector<Hook> createContainer;
    std::vector<Hook> startContainer;
    std::vector<Hook> poststart;
    std::vector<Hook> poststop;

    friend bool operator==(const Hooks &a, const Hooks &b) {
        return std::tie(a.prestart, a.createRuntime, a.createContainer,
                        a.startContainer, a.poststart, a.poststop) ==
               std::tie(b.prestart, b.createRuntime, b.createContainer,
                        a.startContainer, a.poststart, a.poststop);
    }
} Hooks;
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT(Hooks, prestart, createRuntime,
                                                createContainer, startContainer,
                                                poststart, poststop);

typedef struct LinuxIDMapping {
    unsigned int containerID = 0;
    unsigned int hostID = 0;
    unsigned int size = 0;

    friend bool operator==(const LinuxIDMapping &a, const LinuxIDMapping &b) {
        return std::tie(a.containerID, a.hostID, a.size) ==
               std::tie(b.containerID, b.hostID, b.size);
    }
} LinuxIDMapping;
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT(LinuxIDMapping, containerID,
                                                hostID, size);

typedef struct LinuxDeviceCgroup {
    bool        allow = false;
    std::string type;
    long        major = 0;
    long        minor = 0;
    std::string access;

    friend bool operator==(const LinuxDeviceCgroup &a,
                           const LinuxDeviceCgroup &b) {
        return std::tie(a.allow, a.type, a.major, a.minor, a.access) ==
               std::tie(b.allow, b.type, b.major, b.minor, b.access);
    }
} LinuxDeviceCgroup;
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT(LinuxDeviceCgroup, allow, type,
                                                major, minor, access);

typedef struct LinuxMemory {
    long limit = 0;
    long reservation = 0;
    long swap = 0;
    long kernel = 0;
    long kernelTCP = 0;
    long swappiness = 0;
    bool disableOOMKiller = false;
    bool useHierarchy = false;

    friend bool operator==(const LinuxMemory &a, const LinuxMemory &b) {
        return std::tie(a.limit, a.reservation, a.swap, a.kernel, a.kernelTCP,
                        a.swappiness, a.disableOOMKiller, a.useHierarchy) ==
               std::tie(b.limit, b.reservation, b.swap, b.kernel, b.kernelTCP,
                        b.swappiness, b.disableOOMKiller, b.useHierarchy);
    }
} LinuxMemory;
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT(LinuxMemory, limit, reservation,
                                                swap, kernel, kernelTCP,
                                                swappiness, disableOOMKiller,
                                                useHierarchy);

typedef struct LinuxCPU {
    unsigned long shares = 0;
    unsigned long period = 0;
    unsigned long realtimePeriod = 0;
    long          quota = 0;
    long          realtimeRuntime = 0;
    std::string   cpus;
    std::string   mems;

    friend bool operator==(const LinuxCPU &a, const LinuxCPU &b) {
        return std::tie(a.shares, a.period, a.realtimePeriod, a.quota,
                        a.realtimeRuntime, a.cpus, a.mems) ==
               std::tie(b.shares, b.period, b.realtimePeriod, b.quota,
                        b.realtimeRuntime, b.cpus, b.mems);
    }
} LinuxCPU;
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT(LinuxCPU, shares, period,
                                                realtimePeriod, quota,
                                                realtimeRuntime, cpus, mems);

typedef struct LinuxPids {
    long limit = 0;

    friend bool operator==(const LinuxPids &a, const LinuxPids &b) {
        return a.limit == b.limit;
    }
} LinuxPids;
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT(LinuxPids, limit);

typedef struct LinuxWeightDevice {
    unsigned short weight = 0;
    unsigned short leafWeight = 0;
    long           major = 0;
    long           minor = 0;

    friend bool operator==(const LinuxWeightDevice &a,
                           const LinuxWeightDevice &b) {
        return std::tie(a.weight, a.leafWeight, a.major, a.minor) ==
               std::tie(b.weight, b.leafWeight, b.major, b.minor);
    }
} LinuxWeightDevice;
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT(LinuxWeightDevice, weight,
                                                leafWeight, major, minor);

typedef struct LinuxThrottleDevice {
    unsigned long rate = 0;
    long          major = 0;
    long          minor = 0;

    friend bool operator==(const LinuxThrottleDevice &a,
                           const LinuxThrottleDevice &b) {
        return std::tie(a.rate, a.major, a.minor) ==
               std::tie(b.rate, b.major, b.minor);
    }
} LinuxThrottleDevice;
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT(LinuxThrottleDevice, rate,
                                                major, minor);

typedef struct LinuxBLockIO {
    unsigned short                   weight = 0;
    unsigned short                   leafWeight = 0;
    std::vector<LinuxWeightDevice>   weightDevice;
    std::vector<LinuxThrottleDevice> throttleReadBpsDevice;
    std::vector<LinuxThrottleDevice> throttleWriteBpsDevice;
    std::vector<LinuxThrottleDevice> throttleReadIopsDevice;
    std::vector<LinuxThrottleDevice> throttleWriteIopsDevice;

    friend bool operator==(const LinuxBLockIO &a, const LinuxBLockIO &b) {
        return std::tie(a.weight, a.leafWeight, a.weightDevice,
                        a.throttleReadBpsDevice, a.throttleWriteBpsDevice,
                        a.throttleReadIopsDevice, a.throttleWriteIopsDevice) ==
               std::tie(b.weight, b.leafWeight, b.weightDevice,
                        b.throttleReadBpsDevice, b.throttleWriteBpsDevice,
                        b.throttleReadIopsDevice, b.throttleWriteIopsDevice);
    }
} LinuxBLockIO;
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT(
    LinuxBLockIO, weight, leafWeight, weightDevice, throttleReadBpsDevice,
    throttleWriteBpsDevice, throttleReadIopsDevice, throttleWriteIopsDevice);

typedef struct LinuxHugepageLimit {
    unsigned long limit = 0;
    std::string   pageSize;

    friend bool operator==(const LinuxHugepageLimit &a,
                           const LinuxHugepageLimit &b) {
        return std::tie(a.limit, a.pageSize) == std::tie(b.limit, b.pageSize);
    }
} LinuxHugePageLimit;
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT(LinuxHugepageLimit, limit,
                                                pageSize);

typedef struct LinuxInterfacePriority {
    unsigned int priority = 0;
    std::string  name;

    friend bool operator==(const LinuxInterfacePriority &a,
                           const LinuxInterfacePriority &b) {
        return std::tie(a.priority, a.name) == std::tie(b.priority, b.name);
    }
} LinuxInterfacePriority;
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT(LinuxInterfacePriority,
                                                priority, name);

typedef struct LinuxNetwork {
    unsigned int                        classID = 0;
    std::vector<LinuxInterfacePriority> priorities;

    friend bool operator==(const LinuxNetwork &a, const LinuxNetwork &b) {
        return std::tie(a.classID, a.priorities) ==
               std::tie(b.classID, b.priorities);
    }
} LinuxNetwork;
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT(LinuxNetwork, classID,
                                                priorities);

typedef struct LinuxRdma {
    unsigned int hcaHandles = 0;
    unsigned int hcaObjects = 0;

    friend bool operator==(const LinuxRdma &a, const LinuxRdma &b) {
        return std::tie(a.hcaHandles, a.hcaObjects) ==
               std::tie(b.hcaHandles, b.hcaObjects);
    }
} LinuxRdma;
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT(LinuxRdma, hcaHandles,
                                                hcaObjects);

typedef struct LinuxResources {
    std::vector<LinuxDeviceCgroup>     devices;
    LinuxMemory                        memory;
    LinuxCPU                           cpu;
    LinuxPids                          pids;
    LinuxBLockIO                       blockIO;
    std::vector<LinuxHugepageLimit>    hugepageLimits;
    LinuxNetwork                       network;
    std::map<std::string, LinuxRdma>   rdma;
    std::map<std::string, std::string> unified;

    friend bool operator==(const LinuxResources &a, const LinuxResources &b) {
        return std::tie(a.devices, a.memory, a.cpu, a.pids, a.blockIO,
                        a.hugepageLimits, a.network, a.rdma, a.unified) ==
               std::tie(b.devices, b.memory, b.cpu, b.pids, b.blockIO,
                        b.hugepageLimits, b.network, b.rdma, b.unified);
    }
} LinuxResources;
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT(LinuxResources, devices, memory,
                                                cpu, pids, blockIO,
                                                hugepageLimits, network, rdma,
                                                unified);

typedef std::string      LinuxNamespaceType;
const LinuxNamespaceType pid_namespace("pid");
const LinuxNamespaceType network_namespace("network");
const LinuxNamespaceType mount_namespace("mount");
const LinuxNamespaceType ipc_namespace("ipc");
const LinuxNamespaceType uts_namespace("uts");
const LinuxNamespaceType user_namespace("user");
const LinuxNamespaceType cgroup_namespace("cgroup");

typedef struct LinuxNamespace {
    LinuxNamespaceType type;
    std::string        path;

    friend bool operator==(const LinuxNamespace &a, const LinuxNamespace &b) {
        return std::tie(a.type, a.path) == std::tie(b.type, b.path);
    }
} LinuxNamespace;
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT(LinuxNamespace, type, path);

typedef struct LinuxDevice {
    unsigned int uid = 0;
    unsigned int gid = 0;
    unsigned int fileMode = 0;
    long         major = 0;
    long         minor = 0;
    std::string  path;
    std::string  type;

    friend bool operator==(const LinuxDevice &a, const LinuxDevice &b) {
        return std::tie(a.uid, a.gid, a.fileMode, a.major, a.minor, a.path,
                        a.type) == std::tie(b.uid, b.gid, b.fileMode, b.major,
                                            b.minor, b.path, b.type);
    }
} LinuxDevice;
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT(LinuxDevice, uid, gid, fileMode,
                                                major, minor, path, type);

typedef std::string      LinuxSeccompAction;
const LinuxSeccompAction act_kill = "SCMP_ACT_KILL";
const LinuxSeccompAction act_kill_process = "SCMP_ACT_KILL_PROCESS";
const LinuxSeccompAction act_kill_thread = "SCMP_ACT_KILL_THREAD";
const LinuxSeccompAction act_trap = "SCMP_ACT_TRAP";
const LinuxSeccompAction act_errno = "SCMP_ACT_ERRNO";
const LinuxSeccompAction act_trace = "SCMP_ACT_TRACE";
const LinuxSeccompAction act_allow = "SCMP_ACT_ALLOW";
const LinuxSeccompAction act_log = "SCMP_ACT_LOG";
const LinuxSeccompAction act_notify = "SCMP_ACT_NOTIFY";

typedef std::string Arch;
const Arch          arch_x86("SCMP_ARCH_X86");
const Arch          arch_x86_64("SCMP_ARCH_X86_64");
const Arch          arch_x32("SCMP_ARCH_X32");

typedef std::string LinuxSeccompFlag;

typedef std::string        LinuxSeccompOperator;
const LinuxSeccompOperator op_not_equal("SCMP_CMP_NE");
const LinuxSeccompOperator op_less_than("SCMP_CMP_LT");
const LinuxSeccompOperator op_less_equal("SCMP_CMP_LE");
const LinuxSeccompOperator op_equal_to("SCMP_CMP_EQ");
const LinuxSeccompOperator op_greater_equal("SCMP_CMP_GE");
const LinuxSeccompOperator op_greater_than("SCMP_CMP_GT");
const LinuxSeccompOperator op_masked_equal("SCMP_CMP_MASKED_EQ");

typedef struct LinuxSeccompArg {
    unsigned int         index = 0;
    unsigned long        value = 0;
    unsigned long        valueTwo = 0;
    LinuxSeccompOperator op;

    friend bool operator==(const LinuxSeccompArg &a, const LinuxSeccompArg &b) {
        return std::tie(a.index, a.value, a.valueTwo, a.op) ==
               std::tie(b.index, b.value, b.valueTwo, b.op);
    }
} LinuxSeccompArg;
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT(LinuxSeccompArg, index, value,
                                                valueTwo, op);

typedef struct LinuxSyscall {
    std::vector<std::string>     names;
    LinuxSeccompAction           action;
    unsigned int                 errnoRet = 0;
    std::vector<LinuxSeccompArg> args;

    friend bool operator==(const LinuxSyscall &a, const LinuxSyscall &b) {
        return std::tie(a.names, a.action, a.errnoRet, a.args) ==
               std::tie(b.names, b.action, b.errnoRet, b.args);
    }
} LinuxSyscall;
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT(LinuxSyscall, names, action,
                                                errnoRet, args);

typedef struct LinuxSeccomp {
    unsigned int                  defaultErrnoRet = 0;
    LinuxSeccompAction            defaultAction;
    std::vector<Arch>             architectures;
    std::vector<LinuxSeccompFlag> flags;
    std::string                   listenerPath;
    std::string                   listenerMetadata;
    std::vector<LinuxSyscall>     syscalls;

    friend bool operator==(const LinuxSeccomp &a, const LinuxSeccomp &b) {
        return std::tie(a.defaultErrnoRet, a.defaultAction, a.architectures,
                        a.flags, a.listenerPath, a.listenerMetadata,
                        a.syscalls) ==
               std::tie(b.defaultErrnoRet, b.defaultAction, b.architectures,
                        b.flags, b.listenerPath, b.listenerMetadata,
                        b.syscalls);
    }
} LinuxSeccomp;
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT(LinuxSeccomp, defaultErrnoRet,
                                                defaultAction, architectures,
                                                flags, listenerPath,
                                                listenerMetadata, syscalls);

typedef struct LinuxIntelRdt {
    std::string closID;
    std::string l3CacheSchema;
    std::string memBwSchema;

    friend bool operator==(const LinuxIntelRdt &a, const LinuxIntelRdt &b) {
        return std::tie(a.closID, a.l3CacheSchema, a.memBwSchema) ==
               std::tie(b.closID, b.l3CacheSchema, b.memBwSchema);
    }
} LinuxIntelRdt;
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT(LinuxIntelRdt, closID,
                                                l3CacheSchema, memBwSchema);

typedef std::string          LinuxPersonalityDomain;
const LinuxPersonalityDomain per_linux("LINUX");
const LinuxPersonalityDomain per_linux32("LINUX32");

typedef std::string LinuxPersonalityFlag;

typedef struct LinuxPersonality {
    LinuxPersonalityDomain            domain;
    std::vector<LinuxPersonalityFlag> flags;

    friend bool operator==(const LinuxPersonality &a,
                           const LinuxPersonality &b) {
        return std::tie(a.domain, a.flags) == std::tie(b.domain, b.flags);
    }
} LinuxPersonality;
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT(LinuxPersonality, domain,
                                                flags);

typedef struct Linux {
    std::vector<LinuxIDMapping>        uidMappings;
    std::vector<LinuxIDMapping>        gidMappings;
    std::map<std::string, std::string> sysctl;
    LinuxResources                     resources;
    std::string                        cgroupsPath;
    std::vector<LinuxNamespace>        namespaces;
    std::vector<LinuxDevice>           devices;
    LinuxSeccomp                       seccomp;
    std::string                        rootfsPropagation;
    std::vector<std::string>           maskedPaths;
    std::vector<std::string>           readonlyPaths;
    std::string                        mountLabel;
    LinuxIntelRdt                      intelRdt;
    LinuxPersonality                   personality;

    friend bool operator==(const Linux &a, const Linux &b) {
        return std::tie(a.uidMappings, a.gidMappings, a.sysctl, a.resources,
                        a.cgroupsPath, a.namespaces, a.devices, a.seccomp,
                        a.rootfsPropagation, a.maskedPaths, a.readonlyPaths,
                        a.mountLabel, a.intelRdt, a.personality) ==
               std::tie(b.uidMappings, b.gidMappings, b.sysctl, b.resources,
                        b.cgroupsPath, b.namespaces, b.devices, b.seccomp,
                        b.rootfsPropagation, b.maskedPaths, b.readonlyPaths,
                        b.mountLabel, b.intelRdt, b.personality);
    }
} Linux;
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT(Linux, uidMappings, gidMappings,
                                                sysctl, resources, cgroupsPath,
                                                namespaces, devices, seccomp,
                                                rootfsPropagation, maskedPaths,
                                                readonlyPaths, mountLabel,
                                                intelRdt, personality);

typedef struct Spec {
    std::string                        version;
    Process                            process;
    Root                               root;
    std::string                        hostname;
    std::vector<Mount>                 mounts;
    std::vector<Hooks>                 hooks;
    std::map<std::string, std::string> annotations;
    Linux                              _linux;

    inline friend bool operator==(const Spec &a, const Spec &b) {
        return std::tie(a.version, a.process, a.root, a.hostname, a.mounts,
                        a.hooks, a.annotations, a._linux) ==
               std::tie(b.version, b.process, b.root, b.hostname, b.mounts,
                        b.hooks, b.annotations, b._linux);
    }
} Spec;
inline void to_json(json &j, const Spec &s) {
    j = json{{"ociVersion", s.version},
             {"process", s.process},
             {"root", s.root},
             {"hostname", s.hostname},
             {"linux", s._linux}};
    if (!s.mounts.empty())
        j["mounts"] = s.mounts;
    if (!s.hooks.empty())
        j["hooks"] = s.hooks;
    if (!s.annotations.empty())
        j["annotations"] = s.annotations;
}
inline void from_json(const json &j, Spec &s) {
    j.at("ociVersion").get_to(s.version);
    try {
        j.at("process").get_to(s.process);
    } catch (std::exception &_) {
    }
    try {
        j.at("root").get_to(s.root);
    } catch (std::exception &_) {
    }
    j.at("hostname").get_to(s.hostname);
    try {
        j.at("mounts").get_to(s.mounts);
    } catch (std::exception &_) {
    }
    try {
        j.at("hooks").get_to(s.hooks);
    } catch (std::exception &_) {
    }
    try {
        j.at("annotations").get_to(s.annotations);
    } catch (std::exception &_) {
    }
    try {
        j.at("linux").get_to(s._linux);
    } catch (std::exception &_) {
    }
}

}; // namespace spec

#endif // MYDOCKER_SPEC_H
