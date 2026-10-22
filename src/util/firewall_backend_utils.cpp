#include "firewall_backend_utils.hpp"

#include "cached_probe.hpp"
#include "safe_exec.hpp"

namespace keen_pbr3 {

namespace {

const char* firewall_backend_command(FirewallBackend backend) {
    switch (backend) {
        case FirewallBackend::iptables:
            return "iptables";
        case FirewallBackend::nftables:
            return "nft";
    }

    throw FirewallError("Unexpected firewall backend value");
}

// `which` spawns a process and backend resolution runs on every firewall
// refresh, so the answer is cached per backend (see CachedProbe).
CachedProbe& firewall_backend_probe_cache(FirewallBackend backend) {
    static CachedProbe iptables_cache;
    static CachedProbe nftables_cache;
    return backend == FirewallBackend::nftables ? nftables_cache : iptables_cache;
}

} // namespace

bool firewall_backend_command_exists(FirewallBackend backend) {
    const char* command = firewall_backend_command(backend);
    return firewall_backend_probe_cache(backend).get([command] {
        return safe_exec({"which", command}, /*suppress_output=*/true) == 0;
    });
}

#ifdef KEEN_PBR3_TESTING
void reset_firewall_backend_probe_cache_for_tests() {
    firewall_backend_probe_cache(FirewallBackend::iptables).reset();
    firewall_backend_probe_cache(FirewallBackend::nftables).reset();
}
#endif

FirewallBackend detect_firewall_backend() {
    if (firewall_backend_command_exists(FirewallBackend::nftables)) {
        return FirewallBackend::nftables;
    }
    if (firewall_backend_command_exists(FirewallBackend::iptables)) {
        return FirewallBackend::iptables;
    }

    throw FirewallError("No supported firewall backend found (need nft or iptables)");
}

FirewallBackend resolve_firewall_backend(FirewallBackendPreference backend_pref) {
    switch (backend_pref) {
        case FirewallBackendPreference::auto_detect:
            return detect_firewall_backend();
        case FirewallBackendPreference::iptables:
            if (!firewall_backend_command_exists(FirewallBackend::iptables)) {
                throw FirewallError("iptables backend requested but iptables not found");
            }
            return FirewallBackend::iptables;
        case FirewallBackendPreference::nftables:
            if (!firewall_backend_command_exists(FirewallBackend::nftables)) {
                throw FirewallError("nftables backend requested but nft not found");
            }
            return FirewallBackend::nftables;
    }

    throw FirewallError("Unexpected firewall backend value");
}

} // namespace keen_pbr3
