#pragma once

#include <string>
#include <unordered_set>
#include <vector>

#include "../config/config.hpp"

namespace keen_pbr3 {

// Auto-heal: promote a set of "leaking" domains to a top-priority VPN list.
// =========================================================================
// This generalizes the manual OpenAI fix — placing a route rule
// {list:[auto], outbound:VPN} FIRST so the auto list's domains win over every
// other rule. The mechanism is one-shot and purely declarative: it transforms a
// config value, it does not touch the kernel, run a worker, or re-apply routing
// by itself. The API handler feeds the result back through the normal config
// staging path, so routing only changes once the staged config is applied.
//
// promote_domains takes the current config by value and returns a NEW config
// that:
//   1. has a list named `list` (created with empty domains/ip_cidrs if absent);
//   2. has `domains` appended to that list, de-duplicated against the entries
//      already present in the list (insertion order of genuinely new domains is
//      preserved; nothing already in the list is added again);
//   3. has a route rule {enabled:true, list:[list], outbound:outbound} as its
//      first rule (route.rules[0]). If rules[0] is already exactly that rule it
//      is reused as-is; otherwise the rule is inserted at the front. The list
//      may also appear in other rules — that is left untouched; only the
//      top-priority rule is guaranteed. No other rule's `list`/`outbound` is
//      modified, and rule ordering is otherwise preserved.
// Everything else in the config is carried through unchanged.
//
// `domains` entries that are empty strings are ignored. Calling promote_domains
// again with the same arguments is idempotent: no duplicate list entries and no
// duplicate top rule are produced.
//
// `Config` is the keen-pbr alias for api::ConfigObject (see config.hpp).
Config promote_domains(Config cfg,
                       const std::string& list,
                       const std::string& outbound,
                       const std::vector<std::string>& domains);

// Auto-heal worker decision input for a single watchlist domain.
// =============================================================
// Filled by the periodic worker from a `forest-pbr test-routing` evaluation of
// the domain (see compute_test_routing). It deliberately carries only the two
// facts the promotion decision needs, so select_autoheal_promotions() stays a
// pure function that can be unit-tested without DNS or a live kernel.
struct AutohealDomainStatus {
    std::string domain;
    // True when the domain currently RESOLVES (at least one IPv4 address came
    // back) AND its resolved routing does NOT go to the auto-heal outbound —
    // i.e. it is "leaking" to WAN/another outbound when the VPN was intended.
    // A domain that fails to resolve, or that already routes to the auto-heal
    // outbound, is not leaking and is never promoted.
    bool leaking{false};
};

// Pure decision core for the auto-heal worker.
// ============================================
// Given the worker's gating inputs and a per-domain leak status, return the
// subset of watchlist domains that should be promoted into the auto list on
// this tick. The result is exactly the domains that are ALL of:
//   * leaking (status.leaking == true), and
//   * not already present in `current_auto_list_domains`, and
//   * non-empty.
// Watchlist input order is preserved and duplicates are collapsed.
//
// Guarantees the "disabled => zero behavior" contract at the decision layer:
//   * if `enabled` is false, returns {} regardless of everything else;
//   * if `statuses` is empty (empty watchlist), returns {}.
// The caller (worker) skips applying any config change when this returns empty,
// so a disabled or empty-watchlist daemon never touches config or routing.
std::vector<std::string> select_autoheal_promotions(
    bool enabled,
    const std::vector<AutohealDomainStatus>& statuses,
    const std::unordered_set<std::string>& current_auto_list_domains);

}  // namespace keen_pbr3
