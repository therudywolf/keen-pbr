#pragma once

#include "config.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace keen_pbr3 {

// Why this exists
// ===============
// Two classes of list mistake are invisible at save time and only surface as
// "the internet is weird" days later. Both have bitten this deployment:
//
//   * An over-broad IP range. A list named after one service carrying whole
//     cloud provider blocks — one such list held 68 CIDRs covering 86 million
//     addresses (AWS, Azure, GCP, Cloudflare) — silently routes unrelated
//     traffic. Symptoms are diffuse: smart-home devices whose cloud lives in
//     those ranges get split across paths, one DNS answer landing in the
//     tunnel and the next going direct.
//
//   * A shadowing bare domain. dnsmasq's `ipset=/example.com/` matches every
//     subdomain, so a bare `googleapis.com` in one list captures
//     `drive.googleapis.com` from another. When the two lists route to
//     different outbounds the more general entry silently wins for everything
//     under it, and the specific list looks like it stopped working.
//
// validate_config() cannot report these: it throws, and both findings are
// judgement calls, not errors — an operator may genuinely want a whole cloud
// range routed. So this is a separate, advisory-only audit whose output is
// surfaced in the UI and never blocks a save.
//
// Deliberately NOT covered: entries that fail to resolve. That needs live DNS,
// which does not belong in a pure config pass; the leak scanner already probes
// resolution against the running resolver.

struct ListAdvisory {
    enum class Kind {
        // An IPv4 CIDR (or IPv6 prefix) in this list is broader than the
        // reporting threshold.
        OversizedRange,
        // `entry` in `list` is a parent domain of `other_entry` in
        // `other_list`, and the two lists route to different outbounds.
        ShadowedDomain,
        // The list exists and has entries but no enabled rule references it,
        // so it routes nothing. Almost always a half-finished intent: the
        // operator curated the domains and never wired the rule, then reads
        // the list's presence as proof the traffic is handled.
        UnusedList,
    };

    Kind kind{Kind::OversizedRange};
    std::string list;         // list holding the offending entry
    std::string entry;        // the offending entry itself
    std::string other_list;   // ShadowedDomain: the list being shadowed
    std::string other_entry;  // ShadowedDomain: the entry being shadowed
    std::uint64_t addresses{0};  // OversizedRange: IPv4 addresses covered (0 for IPv6)
    int prefix_length{0};        // OversizedRange: the CIDR's prefix length
    std::size_t entry_count{0};  // UnusedList: how many entries go unused
    std::string message;      // rendered, human-readable summary

    // Stable machine-readable name for the kind, used in the API payload.
    static const char* kind_name(Kind kind);
};

// Default reporting threshold: anything wider than a /16. A /16 is already
// 65 536 addresses — broad enough to be deliberate, narrow enough that a
// service's own allocation rarely exceeds it.
inline constexpr std::uint64_t kDefaultOversizedRangeThreshold = 65536;

// Audit a config's lists.
//
// Content checks (OversizedRange, ShadowedDomain) look only at lists in use:
// an unreferenced list routes nothing, so its contents cannot misroute
// anything. Being unreferenced is itself reported, once, as UnusedList.
//
// `threshold` is the smallest address count that still counts as oversized
// (a CIDR covering strictly more than this is reported).
//
// Results are ordered deterministically (by kind, then list, then entry) so
// the UI and tests see a stable sequence.
std::vector<ListAdvisory> audit_lists(
    const Config& cfg,
    std::uint64_t threshold = kDefaultOversizedRangeThreshold);

}  // namespace keen_pbr3
