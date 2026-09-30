#include "ajnat/health_monitor.h"
#include "ajnat/event.h"

#include <sys/utsname.h>
#include <unistd.h>

#include <fstream>
#include <sstream>
#include <string>

#ifdef __ANDROID__
#include <sys/system_properties.h>
#endif

namespace ajnat {
namespace {

bool Exists(const char* path) {
    return access(path, F_OK) == 0;
}

std::string KernelRelease() {
    struct utsname value {};
    return uname(&value) == 0 ? value.release : "unknown";
}

std::string AndroidRelease() {
#ifdef __ANDROID__
    char value[PROP_VALUE_MAX] = {};
    return __system_property_get("ro.build.version.release", value) > 0 ? value : "unknown";
#else
    return "host-test";
#endif
}

bool SelinuxEnforcing() {
    std::ifstream input("/sys/fs/selinux/enforce");
    int enforcing = -1;
    input >> enforcing;
    return enforcing == 1;
}

}  // namespace

std::string KernelCapabilitiesJson() {
    const bool btf = Exists("/sys/kernel/btf/vmlinux");
    const bool bpffs = Exists("/sys/fs/bpf");
    const bool tracefs = Exists("/sys/kernel/tracing/events") || Exists("/sys/kernel/debug/tracing/events");
    const bool process_exec_tracepoint = Exists("/sys/kernel/tracing/events/sched/sched_process_exec")
            || Exists("/sys/kernel/debug/tracing/events/sched/sched_process_exec");
    const bool process_exit_tracepoint = Exists("/sys/kernel/tracing/events/sched/sched_process_exit")
            || Exists("/sys/kernel/debug/tracing/events/sched/sched_process_exit");
    const bool socket_tracepoint = Exists("/sys/kernel/tracing/events/sock/inet_sock_set_state")
            || Exists("/sys/kernel/debug/tracing/events/sock/inet_sock_set_state");
    const bool kernel_config = Exists("/proc/config.gz") || Exists("/system/etc/kernel.config");
    const std::string kernel = KernelRelease();
    const bool gki = kernel.find("android") != std::string::npos || Exists("/system_dlkm");
    const bool process_visibility = Exists("/proc/1/status");
    const bool network_visibility = Exists("/proc/net/tcp") || Exists("/proc/net/udp");
    std::ostringstream output;
    output << "{\"android_version\":\"" << JsonEscape(AndroidRelease())
           << "\",\"kernel_version\":\"" << JsonEscape(kernel)
           << "\",\"gki_detected\":" << (gki ? "true" : "false")
           << "\",\"btf_available\":" << (btf ? "true" : "false")
           << ",\"bpffs_available\":" << (bpffs ? "true" : "false")
           << ",\"tracefs_available\":" << (tracefs ? "true" : "false")
           << ",\"kernel_config_available\":" << (kernel_config ? "true" : "false")
           << ",\"sched_process_exec_tracepoint\":" << (process_exec_tracepoint ? "true" : "false")
           << ",\"sched_process_exit_tracepoint\":" << (process_exit_tracepoint ? "true" : "false")
           << ",\"inet_sock_set_state_tracepoint\":" << (socket_tracepoint ? "true" : "false")
           << ",\"selinux_enforcing\":" << (SelinuxEnforcing() ? "true" : "false")
           << ",\"ebpf_candidate\":" << ((btf && bpffs && tracefs) ? "true" : "false")
           << ",\"ebpf_loaded\":false"
           << ",\"ebpf_program_types\":\"not_probed_without_platform_loader\""
           << ",\"proc_process_visibility\":" << (process_visibility ? "true" : "false")
           << ",\"proc_network_visibility\":" << (network_visibility ? "true" : "false")
           << ",\"netlink_route\":true}";
    return output.str();
}

}  // namespace ajnat
