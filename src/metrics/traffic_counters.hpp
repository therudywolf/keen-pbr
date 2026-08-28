#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace keen_pbr3 {

// Why this exists
// ===============
// The kernel keeps per-rule packet/byte counters on every MARK rule keen-pbr
// installs in the mangle KeenPbrTable chain. Reading those counters back gives
// a cheap, always-available view of how much traffic each outbound has carried
// since the last firewall apply — no extra accounting, conntrack, or netlink
// bookkeeping required. This is the data behind GET /api/metrics/traffic.
//
// This module is deliberately pure and dependency-free: it takes the *text*
// emitted by `iptables -t mangle -L <chain> -v -x -n` and turns it into
// per-outbound totals. It never execs anything itself, so it can be unit-tested
// against captured router output with no kernel involvement. The thin IO layer
// (running iptables, reading config) lives in the API handler.

struct OutboundTraffic {
    std::string tag;       // outbound tag from config (mark_to_tag mapping)
    uint32_t fwmark{0};    // integer mark value, e.g. 0x50000 == 327680
    uint64_t packets{0};   // packets summed across all matching MARK rules
    uint64_t bytes{0};     // bytes summed across all matching MARK rules
};

struct SetTraffic {
    std::string set_name;  // the kpbr* set the counting rule matches against
                           // (kpbrm_<N> combined list:set, or a per-list
                           // kpbr4_/kpbr4d_/kpbr6_/kpbr6d_<list> set)
    uint64_t packets{0};   // packets summed across all counting lines for the set
    uint64_t bytes{0};     // bytes summed across all counting lines for the set
};

// Parse the verbose listing of the KeenPbrTable mangle chain and total the
// per-mark packet/byte counters.
//
// Input is the stdout of `iptables -t mangle -L <chain> -v -x -n`. A *counting*
// line is any line whose target column is "MARK" and that carries a
// "MARK xset 0x<MARK>/0x<MASK>" target spec; from such a line field 1 is the
// packet count, field 2 is the byte count, and the mark value is the hex before
// the '/' in the xset spec. Counters are summed PER MARK across every matching
// line (one rule per inbound interface per set), which yields the per-outbound
// total. Lines whose target is RETURN/ACCEPT/anything else are ignored, as are
// the chain header and column-title rows.
//
// `mark_to_tag` maps a mark value to its outbound tag. The result contains
// exactly one entry per tag in `mark_to_tag` (marks with no observed traffic
// report packets=0/bytes=0). Marks present in the listing but absent from
// `mark_to_tag` are dropped — the caller owns the set of outbounds it cares
// about. Parsing is bounds-safe: malformed lines are skipped, never crash.
//
// Entries are returned sorted by fwmark ascending (stable, deterministic).
std::vector<OutboundTraffic> parse_outbound_traffic(
    const std::string& iptables_output,
    const std::map<uint32_t, std::string>& mark_to_tag);

// Parse the same verbose listing and total the packet/byte counters PER
// match-set, keyed by the set name in a "match-set <kpbr*> dst" clause. Set
// names are the stable join key back to config: a per-list set encodes its
// list name (kpbr4d_<list>), and a combined kpbrm_<N> list:set's members can
// be read from the kernel (`ipset list kpbrm_<N>`). Mapping set names to
// route rules is the caller's job — crucially, a kpbrm_<N> ordinal is
// assigned by firewall consolidation GROUP order, not by route-rule index,
// and one combined set can carry the lists of several rules that share an
// outbound, so treating N as an index into route.rules[] (what this API did
// before) misattributes traffic whenever any rule doesn't consolidate.
//
// A *counting* line is any line that (a) has its target column equal to
// "MARK" carrying a "MARK xset 0x.../0x..." spec, or equal to "DROP" (a
// blackhole rule), and (b) contains a "match-set kpbr... dst" clause. The
// RETURN companion rule each set gets is not counted (its target is RETURN),
// so nothing is double-counted.
//
// Parsing is bounds-safe: malformed lines are skipped, never crash. Entries
// are returned sorted by set name ascending (stable, deterministic).
std::vector<SetTraffic> parse_set_traffic(const std::string& iptables_output);

}  // namespace keen_pbr3
