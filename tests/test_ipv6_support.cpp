#include "../src/util/ipv6_support.hpp"

#include "../src/config/config.hpp"

#include <doctest/doctest.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

namespace keen_pbr3 {

namespace {

// Cheap host-level capability snapshot used to decide which arm of the
// assertion to make. The CI image and any normal developer Linux box has
// both an AF_INET6 socket and /proc/sys/net/ipv6 — but we keep the test
// portable to containers/sandboxes that mask one but not the other.
bool host_has_inet6_socket() {
    const int fd = ::socket(AF_INET6, SOCK_DGRAM, 0);
    if (fd < 0) {
        return false;
    }
    ::close(fd);
    return true;
}

bool host_has_proc_sys_net_ipv6() {
    struct stat st{};
    if (::stat("/proc/sys/net/ipv6", &st) != 0) {
        return false;
    }
    return S_ISDIR(st.st_mode);
}

} // namespace

// Positive path: when EITHER an AF_INET6 socket call works OR
// /proc/sys/net/ipv6 exists (the kernel exposes the IPv6 sysctl tree),
// system_ipv6_supported() must return true.
//
// This is what protects against the historical Keenetic regression where
// the socket() probe transiently returned EAFNOSUPPORT before NDM finished
// initialising the ipv6 module, and the daemon then latched into IPv4-only
// for the rest of its lifetime even though v6 came up moments later.
TEST_CASE("system_ipv6_supported: detects v6 via socket() when the family is usable") {
    if (!host_has_inet6_socket()) {
        // Skip this assertion on hosts where v6 socket really is unavailable
        // (locked-down CI sandboxes). The proc-fallback assertion below still
        // exercises the new code path.
        MESSAGE("AF_INET6 socket unavailable on this host; skipping socket arm");
    } else {
        CHECK(system_ipv6_supported());
    }
}

TEST_CASE("system_ipv6_supported: proc fallback signals v6 even if socket transiently fails") {
    if (!host_has_proc_sys_net_ipv6()) {
        MESSAGE("/proc/sys/net/ipv6 missing on this host; cannot exercise fallback");
        return;
    }
    // The function must accept /proc as a sufficient signal. We cannot easily
    // inject a socket() failure, but if either probe is true the function
    // returns true — and on this branch /proc is true, so the result must be
    // true regardless of whether the socket call succeeded.
    CHECK(system_ipv6_supported());
}

// resolve_ipv6_support honours the explicit config disable, even on a host
// where every system probe would otherwise return true. Guards against a
// future regression where someone removes the early-return shortcut.
TEST_CASE("resolve_ipv6_support: config flag disables v6 regardless of kernel state") {
    Config cfg;
    cfg.daemon = DaemonConfig{};
    cfg.daemon->ipv6_enabled = false;

    const auto decision = resolve_ipv6_support(cfg);
    CHECK_FALSE(decision.enabled);
    CHECK(decision.reason == Ipv6SupportDecision::Reason::DisabledByConfig);
}

// Default (no explicit ipv6_enabled) on a host that supports v6 yields the
// Enabled decision. This guards the "missing config means opt-in" semantics.
TEST_CASE("resolve_ipv6_support: default config keeps v6 enabled on a v6-capable host") {
    if (!host_has_inet6_socket() && !host_has_proc_sys_net_ipv6()) {
        MESSAGE("host has neither AF_INET6 socket nor /proc/sys/net/ipv6; skipping");
        return;
    }

    Config cfg;
    // No daemon overrides; firewall_ipv6_supported tolerates missing iptables/
    // nft binaries by returning true (see ipv6_support.cpp::firewall_ipv6_supported).
    const auto decision = resolve_ipv6_support(cfg);
    CHECK(decision.enabled);
    CHECK(decision.reason == Ipv6SupportDecision::Reason::Enabled);
}

} // namespace keen_pbr3
