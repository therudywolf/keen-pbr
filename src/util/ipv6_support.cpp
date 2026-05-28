#include "ipv6_support.hpp"

#include "../log/logger.hpp"
#include "firewall_backend_utils.hpp"
#include "safe_exec.hpp"

#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

namespace keen_pbr3 {

namespace {

// A truthy entry under /proc/sys/net/ipv6/ means the kernel has the IPv6
// stack registered. On Keenetic 4.9 / Entware mipsel-3.4 the daemon has
// occasionally been observed to start before the IPv6 module is fully
// initialised even though `ipv6.ko` is present, in which case the bare
// `socket(AF_INET6, ...)` probe transiently returns EAFNOSUPPORT. Treat the
// /proc tree as the authoritative "kernel knows about v6" source so a brief
// startup race no longer locks us into IPv4-only for the rest of the daemon
// lifetime.
bool proc_sysctl_ipv6_dir_present() {
    struct stat st{};
    if (::stat("/proc/sys/net/ipv6", &st) != 0) {
        return false;
    }
    return S_ISDIR(st.st_mode);
}

} // namespace

bool system_ipv6_supported() {
    // Primary probe: open an AF_INET6 socket. Cheap, no fork, and the most
    // direct signal that the protocol family is usable from userspace.
    const int fd = socket(AF_INET6, SOCK_DGRAM, 0);
    if (fd >= 0) {
        close(fd);
        return true;
    }

    // Secondary probe: /proc/sys/net/ipv6/ is created by the IPv6 stack when
    // ipv6.ko is loaded (or compiled in). Some Keenetic builds expose the v6
    // sysctl tree even when the bare socket() call momentarily fails (busy
    // module-init path during boot, restrictive seccomp, etc.). If the kernel
    // clearly knows about v6, do not declare the system v6-unsupported.
    return proc_sysctl_ipv6_dir_present();
}

bool nft_ipv6_supported() {
    static constexpr const char* kProbeRuleset =
        "table inet keen_pbr_ipv6_probe {\n"
        "  chain prerouting {\n"
        "    type filter hook prerouting priority -150; policy accept;\n"
        "    ip6 saddr ::1 accept\n"
        "  }\n"
        "}\n";
    return safe_exec_pipe_stdin({"nft", "-c", "-f", "-"}, kProbeRuleset) == 0;
}

bool iptables_ipv6_supported() {
    return safe_exec({"ip6tables", "-t", "mangle", "-S"},
                     /*suppress_output=*/true) == 0
        && safe_exec({"ip6tables-restore", "--version"},
                     /*suppress_output=*/true) == 0;
}

bool firewall_ipv6_supported(const Config& config) {
    try {
        const FirewallBackend backend =
            resolve_firewall_backend(firewall_backend_preference(config));
        if (backend == FirewallBackend::iptables) {
            return iptables_ipv6_supported();
        }
        if (backend == FirewallBackend::nftables) {
            return nft_ipv6_supported();
        }
    } catch (const std::exception&) {
        return true;
    }

    return true;
}

Ipv6SupportDecision resolve_ipv6_support(const Config& config) {
    if (config.daemon.has_value()
        && config.daemon->ipv6_enabled.has_value()
        && !*config.daemon->ipv6_enabled) {
        return {false, Ipv6SupportDecision::Reason::DisabledByConfig};
    }

    if (!system_ipv6_supported() || !firewall_ipv6_supported(config)) {
        return {false, Ipv6SupportDecision::Reason::UnsupportedBySystem};
    }

    return {true, Ipv6SupportDecision::Reason::Enabled};
}

void log_ipv6_support_decision_once(const Ipv6SupportDecision& decision) {
    static bool logged_user_disabled = false;
    static bool logged_system_unsupported = false;

    if (decision.reason == Ipv6SupportDecision::Reason::DisabledByConfig) {
        if (!logged_user_disabled) {
            Logger::instance().warn("IPv6 support disabled by config; running IPv4-only");
            logged_user_disabled = true;
        }
        return;
    }

    if (decision.reason == Ipv6SupportDecision::Reason::UnsupportedBySystem) {
        if (!logged_system_unsupported) {
            Logger::instance().error(
                "IPv6 is not supported by this system; continuing in IPv4-only mode");
            logged_system_unsupported = true;
        }
    }
}

} // namespace keen_pbr3
