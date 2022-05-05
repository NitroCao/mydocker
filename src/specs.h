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
    std::vector<unsigned int> additional_gids;
    std::string username;
} User;
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(User, uid, gid, umask, additional_gids, username);

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
    Box box;
    User user;
    std::vector<std::string> args;
    std::vector<std::string> env;
    std::string cwd;
    LinuxCapabilities capabilities;
    std::vector<POSIXRlimit> rlimits;
    bool no_new_privileges;
    std::string apparmor_profile;
    int oom_score_adj;
    std::string selinux_label;
} Process;
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(Process, terminal, box, user, args, env, cwd, capabilities, rlimits,
                                   no_new_privileges, apparmor_profile, oom_score_adj, selinux_label);

typedef struct Root {
    std::string path;
    bool read_only;
} Root;
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(Root, path, read_only);

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
    std::vector<Hook> create_runtime;
    std::vector<Hook> create_container;
    std::vector<Hook> start_container;
    std::vector<Hook> poststart;
    std::vector<Hook> poststop;
} Hooks;
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(Hooks, prestart, create_runtime, create_container, start_container, poststart,
                                   poststop);

typedef struct LinuxIDMapping {
    unsigned int container_id;
    unsigned int host_id;
    unsigned int size;
} LinuxIDMapping;
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(LinuxIDMapping, container_id, host_id, size);

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
    long kernel_tcp;
    long swappiness;
    bool disable_oom_killer;
    bool use_hierarchy;
} LinuxMemory;
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(LinuxMemory, limit, reservation, swap, kernel, kernel_tcp, swappiness,
                                   disable_oom_killer, use_hierarchy);

typedef struct LinuxCPU {
    unsigned long shares;
    unsigned long period;
    unsigned long realtime_period;
    long quota;
    long realtime_runtime;
    std::string cpus;
    std::string mems;
} LinuxCPU;
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(LinuxCPU, shares, period, realtime_period, quota, realtime_runtime, cpus, mems);

typedef struct LinuxPids {
    long limit;
} LinuxPids;
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(LinuxPids, limit);

typedef struct LinuxWeightDevice {
    unsigned short weight;
    unsigned short leaf_weight;
    long major;
    long minor;
} LinuxWeightDevice;
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(LinuxWeightDevice, weight, leaf_weight, major, minor);

typedef struct LinuxThrottleDevice {
    unsigned long rate;
    long major;
    long minor;
} LinuxThrottleDevice;
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(LinuxThrottleDevice, rate, major, minor);

typedef struct LinuxBLockIO {
    unsigned short weight;
    unsigned short leaf_weight;
    std::vector<LinuxWeightDevice> weight_device;
    std::vector<LinuxThrottleDevice> throttle_read_bps_device;
    std::vector<LinuxThrottleDevice> throttle_write_bps_device;
    std::vector<LinuxThrottleDevice> throttle_read_iops_device;
    std::vector<LinuxThrottleDevice> throttle_write_iops_device;
} LinuxBLockIO;
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(LinuxBLockIO, weight, leaf_weight, weight_device, throttle_read_bps_device,
                                   throttle_write_bps_device, throttle_read_iops_device, throttle_write_iops_device);

typedef struct LinuxHugePageLimit {
    unsigned long limit;
    std::string page_size;
} LinuxHugePageLimit;
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(LinuxHugePageLimit, limit, page_size);

typedef struct LinuxInterfacePriority {
    unsigned int priority;
    std::string name;
} LinuxInterfacePriority;
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(LinuxInterfacePriority, priority, name);

typedef struct LinuxNetwork {
    unsigned int class_id;
    std::vector<LinuxInterfacePriority> priorities;
} LinuxNetwork;
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(LinuxNetwork, class_id, priorities);

typedef struct LinuxRdma {
    unsigned int hca_handles;
    unsigned int hca_objects;
} LinuxRdma;
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(LinuxRdma, hca_handles, hca_objects);

typedef struct LinuxResources {
    std::vector<LinuxDeviceCgroup> devices;
    LinuxMemory memory;
    LinuxCPU cpu;
    LinuxPids pids;
    LinuxBLockIO block_io;
    std::vector<LinuxHugePageLimit> huge_page_limits;
    LinuxNetwork network;
    std::map<std::string, LinuxRdma> rdma;
    std::map<std::string, std::string> unified;
} LinuxResources;
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(LinuxResources, devices, memory, cpu, pids, block_io, huge_page_limits, network,
                                   rdma, unified);

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
    unsigned int file_mode;
    long major;
    long minor;
    std::string path;
    std::string type;
} LinuxDevice;
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(LinuxDevice, uid, gid, file_mode, major, minor, path, type);

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
    unsigned long value_two;
    LinuxSeccompOperator op;
} LinuxSeccompArg;
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(LinuxSeccompArg, index, value, value_two, op);

typedef struct LinuxSyscall {
    std::vector<std::string> names;
    LinuxSeccompAction action;
    unsigned int errno_ret;
    std::vector<LinuxSeccompArg> args;
} LinuxSyscall;
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(LinuxSyscall, names, action, errno_ret, args);

typedef struct LinuxSeccomp {
    unsigned int default_errno_ret;
    LinuxSeccompAction default_action;
    std::vector<Arch> architectures;
    std::vector<LinuxSeccompFlag> flags;
    std::string listener_path;
    std::string listener_metadata;
    std::vector<LinuxSyscall> syscalls;
} LinuxSeccomp;
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(LinuxSeccomp, default_errno_ret, default_action, architectures, flags, listener_path,
                                   listener_metadata, syscalls);

typedef struct LinuxIntelRdt {
    std::string clos_id;
    std::string l3_cache_schema;
    std::string mem_bw_schema;
} LinuxIntelRdt;
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(LinuxIntelRdt, clos_id, l3_cache_schema, mem_bw_schema);

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
    std::vector<LinuxIDMapping> uid_mappings;
    std::vector<LinuxIDMapping> gid_mappings;
    std::map<std::string, std::string> sysctl;
    LinuxResources resources;
    std::string cgroups_path;
    std::vector<LinuxNamespace> namespaces;
    std::vector<LinuxDevice> devices;
    LinuxSeccomp seccomp;
    std::string rootfs_propagation;
    std::vector<std::string> masked_paths;
    std::vector<std::string> read_only_paths;
    std::string mount_label;
    LinuxIntelRdt intel_rdt;
    LinuxPersonality personality;
} Linux;
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(Linux, uid_mappings, gid_mappings, sysctl, resources, cgroups_path, namespaces,
                                   devices, seccomp, rootfs_propagation, masked_paths, read_only_paths, mount_label,
                                   intel_rdt, personality);

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
    j = json{{"ociVersion", s.version},      {"process", s.process}, {"root", s.root},
             {"hostname", s.hostname},       {"mounts", s.mounts},   {"hooks", s.hooks},
             {"annotations", s.annotations}, {"linux", s._linux}};
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
