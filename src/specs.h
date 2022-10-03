#ifndef _SPECS_H_
#define _SPECS_H_

#include <map>
#include <memory>
#include <nlohmann/json.hpp>
#include <sstream>
#include <string>
#include <vector>

namespace mydocker {
namespace specs {

using json = nlohmann::json;

static const char *spec_config = "config.json";
const int version_major = 1;
const int version_minor = 0;
const int version_patch = 2;

static inline std::string version()
{
    std::stringstream ver;
    ver << version_major << "." << version_minor << "." << version_patch;
    return ver.str();
}

typedef struct Box {
    unsigned int height;
    unsigned int width;
} Box;
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(Box, height, width);

typedef struct User {
    unsigned int uid;
    unsigned int gid;
    unsigned int umask;
    std::vector<unsigned int> additionalGids;
    std::string username;
} User;
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(User, uid, gid, umask, additionalGids, username);

typedef struct LinuxCapabilities {
    std::vector<std::string> bounding;
    std::vector<std::string> effective;
    std::vector<std::string> inheritable;
    std::vector<std::string> permitted;
    std::vector<std::string> ambient;
} LinuxCapabilities;
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(LinuxCapabilities, bounding, effective, inheritable, permitted, ambient);

typedef struct POSIXRlimit {
    std::string type;
    unsigned long hard;
    unsigned long soft;
} POSIXRlimit;
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(POSIXRlimit, type, hard, soft);

typedef struct Process {
    bool terminal;
    Box consoleSize;
    User user;
    std::vector<std::string> args;
    std::vector<std::string> env;
    std::string cwd;
    LinuxCapabilities capabilities;
    std::vector<POSIXRlimit> rlimits;
    bool noNewPrivileges;
    std::string apparmorProfile;
    int oomScoreAdj;
    std::string selinuxLabel;
} Process;
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(Process, terminal, consoleSize, user, args, env, cwd, capabilities, rlimits,
                                   noNewPrivileges, apparmorProfile, oomScoreAdj, selinuxLabel);

typedef struct Root {
    std::string path;
    bool readonly;
} Root;
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(Root, path, readonly);

typedef struct Mount {
    std::string destination;
    std::string type;
    std::string source;
    std::vector<std::string> options;
} Mount;
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(Mount, destination, type, source, options);

typedef struct Hook {
    std::string path;
    std::vector<std::string> args;
    std::vector<std::string> env;
    int timeout;
} Hook;
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(Hook, path, args, env);

typedef struct Hooks {
    std::vector<Hook> prestart;
    std::vector<Hook> createRuntime;
    std::vector<Hook> createContainer;
    std::vector<Hook> startContainer;
    std::vector<Hook> poststart;
    std::vector<Hook> poststop;
} Hooks;
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(Hooks, prestart, createRuntime, createContainer, startContainer, poststart,
                                   poststop);

typedef struct LinuxIDMapping {
    unsigned int containerID;
    unsigned int hostID;
    unsigned int size;
} LinuxIDMapping;
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(LinuxIDMapping, containerID, hostID, size);

typedef struct LinuxDeviceCgroup {
    bool allow;
    std::string type;
    long major;
    long minor;
    std::string access;
} LinuxDeviceCgroup;
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(LinuxDeviceCgroup, allow, type, major, minor, access);

typedef struct LinuxMemory {
    long limit;
    long reservation;
    long swap;
    long kernel;
    long kernelTCP;
    long swappiness;
    bool disableOOMKiller;
    bool useHierarchy;
} LinuxMemory;
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(LinuxMemory, limit, reservation, swap, kernel, kernelTCP, swappiness,
                                   disableOOMKiller, useHierarchy);

typedef struct LinuxCPU {
    unsigned long shares;
    unsigned long period;
    unsigned long realtimePeriod;
    long quota;
    long realtimeRuntime;
    std::string cpus;
    std::string mems;
} LinuxCPU;
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(LinuxCPU, shares, period, realtimePeriod, quota, realtimeRuntime, cpus, mems);

typedef struct LinuxPids {
    long limit;
} LinuxPids;
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(LinuxPids, limit);

typedef struct LinuxWeightDevice {
    unsigned short weight;
    unsigned short leafWeight;
    long major;
    long minor;
} LinuxWeightDevice;
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(LinuxWeightDevice, weight, leafWeight, major, minor);

typedef struct LinuxThrottleDevice {
    unsigned long rate;
    long major;
    long minor;
} LinuxThrottleDevice;
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(LinuxThrottleDevice, rate, major, minor);

typedef struct LinuxBLockIO {
    unsigned short weight;
    unsigned short leafWeight;
    std::vector<LinuxWeightDevice> weightDevice;
    std::vector<LinuxThrottleDevice> throttleReadBpsDevice;
    std::vector<LinuxThrottleDevice> throttleWriteBpsDevice;
    std::vector<LinuxThrottleDevice> throttleReadIopsDevice;
    std::vector<LinuxThrottleDevice> throttleWriteIopsDevice;
} LinuxBLockIO;
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(LinuxBLockIO, weight, leafWeight, weightDevice, throttleReadBpsDevice,
                                   throttleWriteBpsDevice, throttleReadIopsDevice, throttleWriteIopsDevice);

typedef struct LinuxHugepageLimit {
    unsigned long limit;
    std::string pageSize;
} LinuxHugePageLimit;
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(LinuxHugepageLimit, limit, pageSize);

typedef struct LinuxInterfacePriority {
    unsigned int priority;
    std::string name;
} LinuxInterfacePriority;
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(LinuxInterfacePriority, priority, name);

typedef struct LinuxNetwork {
    unsigned int classID;
    std::vector<LinuxInterfacePriority> priorities;
} LinuxNetwork;
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(LinuxNetwork, classID, priorities);

typedef struct LinuxRdma {
    unsigned int hcaHandles;
    unsigned int hcaObjects;
} LinuxRdma;
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(LinuxRdma, hcaHandles, hcaObjects);

typedef struct LinuxResources {
    std::vector<LinuxDeviceCgroup> devices;
    LinuxMemory memory;
    LinuxCPU cpu;
    LinuxPids pids;
    LinuxBLockIO blockIO;
    std::vector<LinuxHugepageLimit> hugepageLimits;
    LinuxNetwork network;
    std::map<std::string, LinuxRdma> rdma;
    std::map<std::string, std::string> unified;
} LinuxResources;
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(LinuxResources, devices, memory, cpu, pids, blockIO, hugepageLimits, network, rdma,
                                   unified);

typedef std::string LinuxNamespaceType;
const LinuxNamespaceType pid_namespace("pid");
const LinuxNamespaceType network_namespaec("network");
const LinuxNamespaceType mount_namespace("mount");
const LinuxNamespaceType ipc_namespace("ipc");
const LinuxNamespaceType uts_namespace("uts");
const LinuxNamespaceType user_namespace("user");
const LinuxNamespaceType cgroup_namespace("cgroup");

typedef struct LinuxNamespace {
    LinuxNamespaceType type;
    std::string path;
} LinuxNamespace;
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(LinuxNamespace, type, path);

typedef struct LinuxDevie {
    unsigned int uid;
    unsigned int gid;
    unsigned int fileMode;
    long major;
    long minor;
    std::string path;
    std::string type;
} LinuxDevice;
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(LinuxDevice, uid, gid, fileMode, major, minor, path, type);

typedef std::string LinuxSeccompAction;
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
const Arch arch_x86("SCMP_ARCH_X86");
const Arch arch_x86_64("SCMP_ARCH_X86_64");
const Arch arch_x32("SCMP_ARCH_X32");

typedef std::string LinuxSeccompFlag;

typedef std::string LinuxSeccompOperator;
const LinuxSeccompOperator op_not_equal("SCMP_CMP_NE");
const LinuxSeccompOperator op_less_than("SCMP_CMP_LT");
const LinuxSeccompOperator op_less_equal("SCMP_CMP_LE");
const LinuxSeccompOperator op_equal_to("SCMP_CMP_EQ");
const LinuxSeccompOperator op_greater_equal("SCMP_CMP_GE");
const LinuxSeccompOperator op_greater_than("SCMP_CMP_GT");
const LinuxSeccompOperator op_masked_equal("SCMP_CMP_MASKED_EQ");

typedef struct LinuxSeccompArg {
    unsigned int index;
    unsigned long value;
    unsigned long valueTwo;
    LinuxSeccompOperator op;
} LinuxSeccompArg;
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(LinuxSeccompArg, index, value, valueTwo, op);

typedef struct LinuxSyscall {
    std::vector<std::string> names;
    LinuxSeccompAction action;
    unsigned int errnoRet;
    std::vector<LinuxSeccompArg> args;
} LinuxSyscall;
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(LinuxSyscall, names, action, errnoRet, args);

typedef struct LinuxSeccomp {
    unsigned int defaultErrnoRet;
    LinuxSeccompAction defaultAction;
    std::vector<Arch> architectures;
    std::vector<LinuxSeccompFlag> flags;
    std::string listenerPath;
    std::string listenerMetadata;
    std::vector<LinuxSyscall> syscalls;
} LinuxSeccomp;
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(LinuxSeccomp, defaultErrnoRet, defaultAction, architectures, flags, listenerPath,
                                   listenerMetadata, syscalls);

typedef struct LinuxIntelRdt {
    std::string closID;
    std::string l3CacheSchema;
    std::string memBwSchema;
} LinuxIntelRdt;
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(LinuxIntelRdt, closID, l3CacheSchema, memBwSchema);

typedef std::string LinuxPersonalityDomain;
const LinuxPersonalityDomain per_linux("LINUX");
const LinuxPersonalityDomain per_linux32("LINUX32");

typedef std::string LinuxPersonalityFlag;

typedef struct LinuxPersonality {
    LinuxPersonalityDomain domain;
    std::vector<LinuxPersonalityFlag> flags;
} LinuxPersonality;
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(LinuxPersonality, domain, flags);

typedef struct Linux {
    std::vector<LinuxIDMapping> uidMappings;
    std::vector<LinuxIDMapping> gidMappings;
    std::map<std::string, std::string> sysctl;
    LinuxResources resources;
    std::string cgroupsPath;
    std::vector<LinuxNamespace> namespaces;
    std::vector<LinuxDevice> devices;
    LinuxSeccomp seccomp;
    std::string rootfsPropagation;
    std::vector<std::string> maskedPaths;
    std::vector<std::string> readonlyPaths;
    std::string mountLabel;
    LinuxIntelRdt intelRdt;
    LinuxPersonality personality;
} Linux;
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(Linux, uidMappings, gidMappings, sysctl, resources, cgroupsPath, namespaces, devices,
                                   seccomp, rootfsPropagation, maskedPaths, readonlyPaths, mountLabel, intelRdt,
                                   personality);

typedef struct Spec {
    std::string version;
    Process process;
    Root root;
    std::string hostname;
    std::vector<Mount> mounts;
    std::vector<Hooks> hooks;
    std::map<std::string, std::string> annotations;
    Linux _linux;
} Spec;
inline void to_json(json &j, const Spec &s)
{
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
inline void from_json(const json &j, Spec &s)
{
    j.at("ociVersion").get_to(s.version);
    j.at("process").get_to(s.process);
    j.at("root").get_to(s.root);
    j.at("hostname").get_to(s.hostname);
    j.at("mounts").get_to(s.mounts);
    j.at("hooks").get_to(s.hooks);
    j.at("annotations").get_to(s.annotations);
    j.at("linux").get_to(s._linux);
}

}; // namespace specs
}; // namespace mydocker

#endif // _SPECS_H_
