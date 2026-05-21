#pragma once

#include "firewall.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace keen_pbr3 {

// Ruleset-size optimization for the iptables backend.
//
// keen-pbr emits one `-m set --match-set <ipset> -j <verb>` mangle rule per
// per-list ipset. On real routers most lists route to the same outbound, so
// hundreds of rules differ only in which ipset they match while sharing an
// identical verb/fwmark/selector. This module collapses every group of
// per-list match rules that share the same family, verb, fwmark and selector
// into a single rule backed by an ipset of type `list:set` (which matches when
// the address is in ANY contained set). Behavior is unchanged; the rule count
// drops from hundreds to a handful.
//
// The same grouping is run both when emitting the live ruleset
// (IptablesFirewall) and when verifying it (IptablesFirewallVerifier), so the
// verifier always expects exactly what was emitted.

// One per-list match rule eligible for consolidation.
//
// `criteria.dst_set_name` carries the per-list member ipset. When it is empty
// the rule is "direct" (a raw selector with no ipset, e.g. a DNS detour rule)
// and is passed through unchanged, keeping its original position.
struct ConsolidatableRule {
    enum class Action : uint8_t { Mark, Drop, Pass };

    bool ipv6 = false;
    Action action = Action::Mark;
    uint32_t fwmark = 0; // meaningful only for Action::Mark
    FirewallRuleCriteria criteria;
};

// A rule after consolidation.
//
// `criteria.dst_set_name` is the ipset the emitted rule must match:
//   - empty            -> a pass-through direct rule (input had no ipset)
//   - a per-list set   -> a group that had a single member (no list:set needed)
//   - a synthesized    -> a group of >= 2 members folded into one list:set;
//     `kpbrm_<n>` set     `member_sets` then lists the contained per-list ipsets.
struct ConsolidatedRule {
    bool ipv6 = false;
    ConsolidatableRule::Action action = ConsolidatableRule::Action::Mark;
    uint32_t fwmark = 0;
    FirewallRuleCriteria criteria;
    bool is_combined = false;              // true => criteria.dst_set_name is a list:set
    std::vector<std::string> member_sets;  // contained per-list ipsets (is_combined only)
};

// Prefix of every synthesized list:set. Distinct from the per-list `kpbr4_` /
// `kpbr6_` / `kpbr4d_` / `kpbr6d_` namespaces (those always carry a digit
// directly after `kpbr`).
constexpr const char* kCombinedSetPrefix = "kpbrm_";

// Name of the n-th synthesized list:set (kpbrm_0, kpbrm_1, ...).
std::string combined_set_name(size_t ordinal);

// Collapse list-backed rules sharing (family, verb, fwmark, selector) into one
// list:set-backed rule each. Direct rules (no dst_set_name) and single-member
// groups are emitted unchanged. Output order follows the first occurrence of
// each group / direct rule in the input, so first-match-wins evaluation is
// preserved for the common case of non-overlapping lists.
std::vector<ConsolidatedRule> consolidate_iptables_rules(
    const std::vector<ConsolidatableRule>& rules);

} // namespace keen_pbr3
