#pragma once

#include "../cache/cache_manager.hpp"
#include "../config/config.hpp"
#include "../lists/list_set_usage.hpp"
#include "../routing/firewall_state.hpp"
#include "firewall.hpp"

#include <map>
#include <string>
#include <vector>

namespace keen_pbr3 {

// What the last full apply (Destructive or PreserveSets) loaded into the
// list sets, so that a later RulesOnly apply can rebuild the rules without
// streaming every list again.
struct FirewallSetCache {
    bool valid{false};
    // firewall_set_fingerprint() of the inputs the sets were loaded from.
    std::string fingerprint;
    // Per-list set layout (static/dynamic sets, dynamic timeout).
    std::map<std::string, ListSetUsage> usage;
    // Why the last RulesOnly attempt fell back to PreserveSets; a repeat of
    // the same reason (a refresh every minute) is not warned about again.
    std::string last_rules_only_fallback;

    void invalidate() {
        valid = false;
        fingerprint.clear();
        usage.clear();
    }
};

// Selector criteria (proto, ports, addresses, negations) of a route rule,
// exactly as the apply installs them. The status command uses the same
// function, so it verifies the rules the daemon actually built.
FirewallRuleCriteria build_firewall_rule_criteria(const RouteRule& rule);

// Identity of everything that decides the layout and contents of the list
// sets: the lists referenced by enabled route rules (inline CIDRs, domain
// count, ttl, file and cache stamps) and the IPv6 decision. Cheap: one
// stat() per file- or URL-backed list, no list is streamed.
std::string firewall_set_fingerprint(const Config& config,
                                     const CacheManager& cache_manager,
                                     bool ipv6_enabled);

// Materialize the runtime firewall configuration using the real backend.
// Returns the realized rule-state snapshot that should be stored for later
// verification and status reporting.
//
// With `set_cache`, a Destructive/PreserveSets apply records what it loaded,
// and a RulesOnly apply reuses that record instead of streaming the lists.
// RulesOnly falls back to PreserveSets on any doubt: no valid record, a
// changed fingerprint, a backend preflight failure or any other error.
std::vector<RuleState> apply_runtime_firewall(
    const Config& config,
    const OutboundMarkMap& outbound_marks,
    const std::map<std::string, std::string>& urltest_selections,
    const CacheManager& cache_manager,
    Firewall& firewall,
    FirewallApplyMode mode = FirewallApplyMode::Destructive,
    FirewallSetCache* set_cache = nullptr);

} // namespace keen_pbr3
