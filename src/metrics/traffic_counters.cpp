#include "traffic_counters.hpp"

#include <optional>
#include <sstream>

namespace keen_pbr3 {

namespace {

// Split a line on runs of whitespace, mirroring the tokenizer used by the
// iptables verifier. Empty tokens are never produced.
std::vector<std::string> split_ws(const std::string& line) {
    std::istringstream stream(line);
    std::vector<std::string> tokens;
    std::string token;
    while (stream >> token) {
        tokens.push_back(token);
    }
    return tokens;
}

// Parse an unsigned 64-bit decimal count (the pkts/bytes columns). Rejects
// anything that is not a pure run of digits so column-title rows ("pkts") and
// malformed lines are skipped rather than silently counted as zero.
std::optional<uint64_t> parse_u64_dec(const std::string& s) {
    if (s.empty()) {
        return std::nullopt;
    }
    uint64_t value = 0;
    for (const char ch : s) {
        if (ch < '0' || ch > '9') {
            return std::nullopt;
        }
        value = value * 10U + static_cast<uint64_t>(ch - '0');
    }
    return value;
}

// Parse the mark value out of an xset target spec of the form
// "0x<MARK>/0x<MASK>" (e.g. "0x50000/0xff0000"). Returns the MARK portion.
// Accepts an optional "0x" prefix and parses the hex before the '/'.
std::optional<uint32_t> parse_xset_mark(const std::string& spec) {
    const auto slash = spec.find('/');
    const std::string mark_str =
        slash == std::string::npos ? spec : spec.substr(0, slash);
    if (mark_str.empty()) {
        return std::nullopt;
    }
    try {
        // Base 0 honours the leading "0x"; the iptables listing always emits it.
        const unsigned long parsed = std::stoul(mark_str, nullptr, 0);
        return static_cast<uint32_t>(parsed);
    } catch (...) {
        return std::nullopt;
    }
}

// Extract (packets, bytes, mark) from one listing line if it is a counting
// line: target column == "MARK" carrying a "MARK xset 0x.../0x..." spec.
// Returns nullopt for header rows, RETURN/ACCEPT rules, and malformed lines.
struct CountingLine {
    uint32_t mark;
    uint64_t packets;
    uint64_t bytes;
};

std::optional<CountingLine> parse_counting_line(const std::string& line) {
    const auto tokens = split_ws(line);
    // Need at least: pkts bytes target ... MARK xset <spec>
    if (tokens.size() < 3) {
        return std::nullopt;
    }

    // Target column is the 3rd field. Anything other than MARK (RETURN,
    // ACCEPT, the "target" title row) is not a counting line.
    if (tokens[2] != "MARK") {
        return std::nullopt;
    }

    // Locate the "MARK" "xset" "<spec>" triple in the trailing target options.
    // Searching rather than fixing an index keeps us robust to differing
    // numbers of match clauses (match-set, in/out interface, etc.) before it.
    std::optional<uint32_t> mark;
    for (std::size_t i = 0; i + 2 < tokens.size(); ++i) {
        if (tokens[i] == "MARK" && tokens[i + 1] == "xset") {
            mark = parse_xset_mark(tokens[i + 2]);
            break;
        }
    }
    if (!mark.has_value()) {
        return std::nullopt;
    }

    const auto packets = parse_u64_dec(tokens[0]);
    const auto bytes = parse_u64_dec(tokens[1]);
    if (!packets.has_value() || !bytes.has_value()) {
        return std::nullopt;
    }

    return CountingLine{*mark, *packets, *bytes};
}

// True for any set name this daemon owns: the combined kpbrm_<N> list:sets and
// the per-list kpbr4_/kpbr4d_/kpbr6_/kpbr6d_<list> sets. A plain prefix check
// covers all five spellings; foreign sets (e.g. NDM's _NDM_* sets) never start
// with "kpbr".
bool is_kpbr_set(const std::string& set_name) {
    return set_name.rfind("kpbr", 0) == 0;
}

// Extract (set_name, packets, bytes) from one listing line if it is a counting
// line that matches a kpbr* destination set. A counting line's target is
// either MARK with an xset spec (the per-outbound parser's predicate — so each
// set's RETURN companion rule is not double-counted) or DROP (a blackhole
// rule, which has no mark). Returns nullopt for header rows, RETURN/ACCEPT
// rules, and lines whose match-set is not one of ours.
struct SetCountingLine {
    std::string set_name;
    uint64_t packets;
    uint64_t bytes;
};

std::optional<SetCountingLine> parse_set_counting_line(const std::string& line) {
    const auto tokens = split_ws(line);
    if (tokens.size() < 3) {
        return std::nullopt;
    }

    if (tokens[2] == "MARK") {
        // Only MARK rules carrying the xset spec count (mirrors
        // parse_counting_line); the mark value itself is irrelevant here.
        if (!parse_counting_line(line).has_value()) {
            return std::nullopt;
        }
    } else if (tokens[2] != "DROP") {
        return std::nullopt;
    }

    // Find the "match-set" "<set>" pair and keep the first kpbr* set name.
    std::optional<std::string> set_name;
    for (std::size_t i = 0; i + 1 < tokens.size(); ++i) {
        if (tokens[i] == "match-set" && is_kpbr_set(tokens[i + 1])) {
            set_name = tokens[i + 1];
            break;
        }
    }
    if (!set_name.has_value()) {
        return std::nullopt;
    }

    const auto packets = parse_u64_dec(tokens[0]);
    const auto bytes = parse_u64_dec(tokens[1]);
    if (!packets.has_value() || !bytes.has_value()) {
        return std::nullopt;
    }

    return SetCountingLine{std::move(*set_name), *packets, *bytes};
}

}  // namespace

std::vector<OutboundTraffic> parse_outbound_traffic(
    const std::string& iptables_output,
    const std::map<uint32_t, std::string>& mark_to_tag) {
    // Seed totals for every known mark so outbounds with no observed traffic
    // still appear with zeroes. std::map keeps marks sorted ascending, which
    // is the deterministic order we return.
    std::map<uint32_t, OutboundTraffic> totals;
    for (const auto& [mark, tag] : mark_to_tag) {
        OutboundTraffic entry;
        entry.tag = tag;
        entry.fwmark = mark;
        totals.emplace(mark, std::move(entry));
    }

    std::istringstream stream(iptables_output);
    std::string line;
    while (std::getline(stream, line)) {
        const auto counting = parse_counting_line(line);
        if (!counting.has_value()) {
            continue;
        }
        // Drop marks we were not asked about; the caller owns the outbound set.
        const auto it = totals.find(counting->mark);
        if (it == totals.end()) {
            continue;
        }
        it->second.packets += counting->packets;
        it->second.bytes += counting->bytes;
    }

    std::vector<OutboundTraffic> result;
    result.reserve(totals.size());
    for (auto& [mark, entry] : totals) {
        (void)mark;
        result.push_back(std::move(entry));
    }
    return result;
}

std::vector<SetTraffic> parse_set_traffic(const std::string& iptables_output) {
    // Accumulate per observed set name. std::map keeps names sorted
    // ascending, which is the deterministic order we return.
    std::map<std::string, SetTraffic> totals;

    std::istringstream stream(iptables_output);
    std::string line;
    while (std::getline(stream, line)) {
        auto counting = parse_set_counting_line(line);
        if (!counting.has_value()) {
            continue;
        }
        auto& entry = totals[counting->set_name];
        entry.set_name = counting->set_name;
        entry.packets += counting->packets;
        entry.bytes += counting->bytes;
    }

    std::vector<SetTraffic> result;
    result.reserve(totals.size());
    for (auto& [name, entry] : totals) {
        (void)name;
        result.push_back(std::move(entry));
    }
    return result;
}

}  // namespace keen_pbr3
