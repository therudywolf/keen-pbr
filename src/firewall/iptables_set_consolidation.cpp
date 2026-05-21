#include "iptables_set_consolidation.hpp"

#include "../util/format_compat.hpp"

#include <map>
#include <string>
#include <utility>
#include <vector>

namespace keen_pbr3 {

namespace {

// Strip a redundant host prefix (/32 IPv4, /128 IPv6) so two spellings of the
// same address produce the same group key.
std::string normalize_addr(const std::string& addr) {
    const auto slash = addr.find('/');
    if (slash == std::string::npos) {
        return addr;
    }
    const std::string base = addr.substr(0, slash);
    const std::string prefix = addr.substr(slash + 1);
    const bool ipv6 = base.find(':') != std::string::npos;
    if ((!ipv6 && prefix == "32") || (ipv6 && prefix == "128")) {
        return base;
    }
    return addr;
}

void append_addr_list(std::string& key,
                      char tag,
                      const std::vector<std::string>& addrs,
                      bool negated) {
    key += tag;
    key += negated ? '!' : '=';
    for (const auto& addr : addrs) {
        key += normalize_addr(addr);
        key += ',';
    }
    key += ';';
}

// Build a key that is identical for two rules iff they may share one combined
// rule: same family, verb, fwmark and packet selector (everything in the
// criteria except the per-list member set).
std::string group_key(const ConsolidatableRule& rule) {
    std::string key;
    key += rule.ipv6 ? "6|" : "4|";
    switch (rule.action) {
        case ConsolidatableRule::Action::Mark:
            key += "m|";
            key += keen_pbr3::format("{:x}|", rule.fwmark);
            break;
        case ConsolidatableRule::Action::Drop:
            key += "d|";
            break;
        case ConsolidatableRule::Action::Pass:
            key += "p|";
            break;
    }
    key += keen_pbr3::format("P{}|", static_cast<int>(rule.criteria.proto));
    key += "sp";
    key += rule.criteria.negate_src_port ? "!" : "=";
    key += rule.criteria.src_port.to_iptables_string();
    key += ";dp";
    key += rule.criteria.negate_dst_port ? "!" : "=";
    key += rule.criteria.dst_port.to_iptables_string();
    key += ";";
    append_addr_list(key, 's', rule.criteria.src_addr, rule.criteria.negate_src_addr);
    append_addr_list(key, 'd', rule.criteria.dst_addr, rule.criteria.negate_dst_addr);
    return key;
}

// Mutable accumulator for one group of rules sharing a group_key.
struct RuleGroup {
    ConsolidatableRule representative;   // first rule seen; supplies the shared criteria
    std::vector<std::string> members;    // distinct member ipsets, in first-seen order
};

} // namespace

std::string combined_set_name(size_t ordinal) {
    return keen_pbr3::format("{}{}", kCombinedSetPrefix, ordinal);
}

std::vector<ConsolidatedRule> consolidate_iptables_rules(
    const std::vector<ConsolidatableRule>& rules) {
    // A reservation is either a direct pass-through rule (resolved immediately)
    // or a placeholder for a group filled in after the whole input is scanned.
    struct Reservation {
        bool is_group = false;
        ConsolidatedRule direct;  // valid when !is_group
        std::string group_key;    // valid when is_group
    };

    std::vector<Reservation> reservations;
    std::map<std::string, RuleGroup> groups;

    for (const auto& rule : rules) {
        if (!rule.criteria.dst_set_name.has_value()
            || rule.criteria.dst_set_name->empty()) {
            // Direct rule: no ipset to fold, keep verbatim and in place.
            Reservation res;
            res.is_group = false;
            res.direct.ipv6 = rule.ipv6;
            res.direct.action = rule.action;
            res.direct.fwmark = rule.fwmark;
            res.direct.criteria = rule.criteria;
            res.direct.is_combined = false;
            reservations.push_back(std::move(res));
            continue;
        }

        const std::string key = group_key(rule);
        auto it = groups.find(key);
        if (it == groups.end()) {
            RuleGroup group;
            group.representative = rule;
            it = groups.emplace(key, std::move(group)).first;

            Reservation res;
            res.is_group = true;
            res.group_key = key;
            reservations.push_back(std::move(res));
        }

        // Record the member ipset, de-duplicating repeated references so a set
        // used by several route rules still appears once in the list:set.
        const std::string& member = *rule.criteria.dst_set_name;
        auto& members = it->second.members;
        bool already_present = false;
        for (const auto& existing : members) {
            if (existing == member) {
                already_present = true;
                break;
            }
        }
        if (!already_present) {
            members.push_back(member);
        }
    }

    // Assign list:set ordinals in first-seen order, but only to groups that
    // actually need one (>= 2 members). Single-member groups keep their lone
    // per-list set, so they consume no ordinal.
    std::map<std::string, size_t> combined_ordinal;
    size_t next_ordinal = 0;
    for (const auto& res : reservations) {
        if (!res.is_group) {
            continue;
        }
        const auto& group = groups.at(res.group_key);
        if (group.members.size() >= 2) {
            combined_ordinal.emplace(res.group_key, next_ordinal++);
        }
    }

    std::vector<ConsolidatedRule> out;
    out.reserve(reservations.size());
    for (const auto& res : reservations) {
        if (!res.is_group) {
            out.push_back(res.direct);
            continue;
        }

        const auto& group = groups.at(res.group_key);
        ConsolidatedRule rule;
        rule.ipv6 = group.representative.ipv6;
        rule.action = group.representative.action;
        rule.fwmark = group.representative.fwmark;
        rule.criteria = group.representative.criteria;

        if (group.members.size() >= 2) {
            rule.is_combined = true;
            rule.member_sets = group.members;
            rule.criteria.dst_set_name = combined_set_name(combined_ordinal.at(res.group_key));
        } else {
            // Exactly one member: emit the per-list set directly, no list:set.
            rule.is_combined = false;
            rule.criteria.dst_set_name = group.members.front();
        }
        out.push_back(std::move(rule));
    }

    return out;
}

} // namespace keen_pbr3
