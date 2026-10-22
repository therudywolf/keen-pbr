#pragma once

#include "../config/config.hpp"

namespace keen_pbr3 {

struct Ipv6SupportDecision {
    bool enabled{true};
    enum class Reason {
        Enabled,
        DisabledByConfig,
        UnsupportedBySystem
    } reason{Reason::Enabled};
};

bool system_ipv6_supported();
// ip6tables and ip6tables-restore are usable for the mangle table. The answer
// is cached: positive for the process lifetime, negative for about a minute.
bool iptables_ipv6_supported();
// Honours daemon.ipv6_enabled on every call; the tool probes behind it are
// cached (see iptables_ipv6_supported()).
Ipv6SupportDecision resolve_ipv6_support(const Config& config);
void log_ipv6_support_decision_once(const Ipv6SupportDecision& decision);

#ifdef KEEN_PBR3_TESTING
void reset_ipv6_probe_cache_for_tests();
#endif

} // namespace keen_pbr3
