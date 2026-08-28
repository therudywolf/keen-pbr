#pragma once

#include "../config/config.hpp"
#include "../lists/list_set_usage.hpp"
#include "../routing/firewall_state.hpp"
#include "../routing/policy_rule.hpp"
#include "../routing/route_table.hpp"

#include <functional>
#include <map>
#include <vector>

namespace keen_pbr3 {

// Routing table IDs that must never be used for keen-pbr outbound tables.
static constexpr uint32_t RESERVED_TABLE_UNSPEC         = 0;
static constexpr uint32_t RESERVED_TABLE_PRELOCAL       = 128;
static constexpr uint32_t RESERVED_TABLE_BLOCK_LOW      = 250;
static constexpr uint32_t RESERVED_TABLE_BLOCK_HIGH     = 260; // covers 253=default, 254=main, 255=local
static constexpr uint32_t RESERVED_TABLE_SYSTEM_START   = 32000;

inline bool is_reserved_table(uint32_t id) {
    return id == RESERVED_TABLE_UNSPEC ||
           id == RESERVED_TABLE_PRELOCAL ||
           (id >= RESERVED_TABLE_BLOCK_LOW && id <= RESERVED_TABLE_BLOCK_HIGH) ||
           id >= RESERVED_TABLE_SYSTEM_START;
}

using OutboundReachabilityFn = std::function<bool(const Outbound&)>;

// Populate route tables and policy rules from config. Works for real or dry-run instances.
void populate_routing_state(const Config& cfg,
                            const OutboundMarkMap& marks,
                            RouteTable& routes,
                            PolicyRuleManager& rules,
                            OutboundReachabilityFn reachability_check = {},
                            const std::map<std::string, std::string>* urltest_selections = nullptr,
                            bool ipv6_enabled = true);

bool is_interface_outbound_reachable(const Outbound& outbound, NetlinkManager& netlink);

// Build the global firewall prefilter derived from route-level config.
// Missing or empty inbound_interfaces leaves interface restriction disabled.
FirewallGlobalPrefilter build_firewall_global_prefilter(const Config& cfg);

// Build firewall rule state (set names, actions, selectors) from config without touching firewall.
// urltest_selections optionally overrides URLTEST outbounds to a selected child tag.
std::vector<RuleState> build_fw_rule_states(
    const Config& cfg,
    const OutboundMarkMap& marks,
    const std::map<std::string, std::string>* urltest_selections = nullptr);

using ListSetUsageFn = std::function<ListSetUsage(const std::string&,
                                                  const ListConfig&)>;

// Remove set names for list variants that would not produce a live firewall set.
// This keeps dry-run/verification paths aligned with apply_firewall(), which skips
// always-empty static or dynamic sets.
void prune_fw_rule_states_to_realized_sets(
    const Config& cfg,
    std::vector<RuleState>& rule_states,
    const ListSetUsageFn& list_usage_fn);

// Names of the kpbr* sets whose routing may differ between two configs.
//
// A conntrack flush is a forced disconnect of every matching flow, so it must
// be aimed at exactly the destinations whose routing actually changed —
// flushing everything tears unrelated long-lived sessions (IoT MQTT keepalives,
// SSH, streaming) on every unrelated list edit. A list's sets are returned when
// its own contents changed (domains, CIDRs, file/url source), when the outbound
// or selector of a rule referencing it changed, or when the list gained/lost a
// referencing rule. Returns set names for BOTH families and both static and
// dynamic variants; a name that has no live set is simply skipped by the
// snapshot reader.
//
// An empty result means "nothing routing-relevant changed" — the caller should
// then skip the flush entirely rather than fall back to flushing everything.
std::vector<std::string> changed_kpbr_set_names(const Config& before,
                                                const Config& after);

// Names of the kpbr* sets belonging to enabled rules that route to `tag`
// (matching either the rule's literal outbound or, for URLTEST parents, the
// tag itself). Used to scope a flush to one outbound whose nexthop moved.
std::vector<std::string> kpbr_set_names_for_outbound(const Config& cfg,
                                                     const std::string& tag);

} // namespace keen_pbr3
