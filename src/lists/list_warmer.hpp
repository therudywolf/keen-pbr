#pragma once

#include "../config/config.hpp"

#include <chrono>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace keen_pbr3 {

class BlockingExecutor;

// Why this exists
// ===============
// dnsmasq does NOT refresh ipset entries on cache-hit responses (this is a
// documented dnsmasq behaviour, not a bug we can fix). The downstream effect:
// with per-list ttl on the kpbr*d_<list> ipsets, a client that has already
// cached a DNS answer or that uses DoH/DoT (bypassing dnsmasq entirely) may
// later connect to an IP that has expired out of the ipset. The packet then
// misses the PBR mark, gets routed via the default WAN, and is dropped by RKN.
//
// ListWarmer periodically resolves every domain in every active list via a
// direct UDP query to a public resolver (bypassing dnsmasq's cache), and
// `ipset add ... -exist` the answers into the matching kpbr4d_<list> /
// kpbr6d_<list> sets. The `-exist` flag both prevents collisions and refreshes
// the ipset entry's timeout, keeping known-good answers alive ahead of TTL.
//
// Work is dispatched onto a BlockingExecutor (one task per domain) so that a
// stalled upstream resolver cannot block the daemon's event loop. Tasks catch
// all exceptions internally; warmer failures are logged but never propagated.
class ListWarmer {
public:
    struct Settings {
        std::chrono::seconds interval{600};        // poll cadence (default 10 min)
        std::string upstream_dns_ip{"1.1.1.1"};    // public resolver, bypass dnsmasq
        uint16_t upstream_dns_port{53};
        std::chrono::milliseconds query_timeout{2000};
    };

    // Function injected for resolving A records. Real implementation uses
    // query_dns_a_records; tests substitute a deterministic mock.
    using AResolver = std::function<std::vector<std::string>(
        const std::string& server_addr,
        const std::string& domain,
        std::chrono::milliseconds timeout)>;
    // AAAA resolver counterpart.
    using AaaaResolver = std::function<std::vector<std::string>(
        const std::string& server_addr,
        const std::string& domain,
        std::chrono::milliseconds timeout)>;
    // Function injected for bulk-adding IPs into one ipset. Returns true on
    // success. Real implementation pipes a multi-line `ipset restore -` script
    // (one `add <set> <ip> -exist [timeout N]` line per IP) so a domain that
    // resolves to N IPs costs ONE subprocess instead of N fork+exec calls.
    // On a Keenetic KN-1011 at 5k IPs/pass this is the difference between a
    // ~150 s CPU spike and a ~30 s amortised cost.
    using IpsetAdder = std::function<bool(
        const std::string& set_name,
        const std::vector<std::string>& ips,
        uint32_t timeout_seconds /* 0 = no timeout */)>;

    ListWarmer(Settings settings,
               std::function<const Config&()> get_app_config,
               BlockingExecutor* executor);

    // Test-only / injection constructor — overrides the default DNS query and
    // ipset-add implementations.
    ListWarmer(Settings settings,
               std::function<const Config&()> get_app_config,
               BlockingExecutor* executor,
               AResolver a_resolver,
               AaaaResolver aaaa_resolver,
               IpsetAdder ipset_adder);

    // Submit one warming pass. Non-blocking: each (domain, set) task is queued
    // on the executor and runs in parallel. Returns the number of work items
    // queued (one per domain), so callers can record observability counters.
    int warm_once();

    const Settings& settings() const noexcept { return settings_; }

private:
    void warm_domain(const std::string& domain,
                     const std::string& v4_set_name,
                     const std::string& v6_set_name,
                     uint32_t ipset_timeout_seconds);

    Settings settings_;
    std::function<const Config&()> get_app_config_;
    BlockingExecutor* executor_;
    AResolver a_resolver_;
    AaaaResolver aaaa_resolver_;
    IpsetAdder ipset_adder_;
};

// Default bulk ipset-add implementation: pipes one `add <set> <ip> -exist
// [timeout <ttl>]` line per IP to `ipset restore -`. Logs a warning on failure
// so kernel/ipset issues are visible without spamming on every retry.
bool default_ipset_add(const std::string& set_name,
                       const std::vector<std::string>& ips,
                       uint32_t timeout_seconds);

} // namespace keen_pbr3
