#include "list_audit.hpp"

#include "../util/format_compat.hpp"

#include <algorithm>
#include <arpa/inet.h>
#include <map>
#include <set>
#include <string>
#include <tuple>
#include <vector>

namespace keen_pbr3 {

namespace {

// Split "1.2.3.0/24" into address and prefix length. Returns false for entries
// that are not CIDRs (bare IPs, host:port forms, malformed text) — those are
// somebody else's problem to validate, and silently skipping them keeps this
// audit advisory-only.
bool split_cidr(const std::string& entry, std::string& addr, int& prefix_len) {
    const auto slash = entry.find('/');
    if (slash == std::string::npos || slash + 1 >= entry.size()) {
        return false;
    }
    addr = entry.substr(0, slash);
    const std::string len_str = entry.substr(slash + 1);
    if (len_str.empty() ||
        len_str.find_first_not_of("0123456789") != std::string::npos) {
        return false;
    }
    try {
        prefix_len = std::stoi(len_str);
    } catch (...) {
        return false;
    }
    return true;
}

// Address count for an IPv4 prefix. IPv6 counts overflow 64 bits and are not
// meaningful to compare against an IPv4 threshold, so IPv6 reports 0 and is
// judged on prefix length alone.
std::uint64_t ipv4_addresses(int prefix_len) {
    if (prefix_len < 0 || prefix_len > 32) {
        return 0;
    }
    return std::uint64_t{1} << (32 - prefix_len);
}

bool is_ipv4(const std::string& addr) {
    struct in_addr v4 {};
    return inet_pton(AF_INET, addr.c_str(), &v4) == 1;
}

bool is_ipv6(const std::string& addr) {
    struct in6_addr v6 {};
    return inet_pton(AF_INET6, addr.c_str(), &v6) == 1;
}

// Mirrors DnsmasqGenerator::strip_wildcard: "*.example.com" and "example.com"
// produce the same dnsmasq directive, so they shadow identically.
std::string strip_wildcard(const std::string& domain) {
    if (domain.size() > 2 && domain[0] == '*' && domain[1] == '.') {
        return domain.substr(2);
    }
    return domain;
}

std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return s;
}

// True when `parent` covers `child` the way dnsmasq does: an exact match, or
// `child` ending in "." + `parent`. "oogle.com" must NOT match "google.com",
// hence the explicit dot check rather than a bare suffix compare.
bool domain_covers(const std::string& parent, const std::string& child) {
    if (parent == child) {
        return true;
    }
    if (child.size() <= parent.size() + 1) {
        return false;
    }
    const std::size_t offset = child.size() - parent.size();
    return child.compare(offset, parent.size(), parent) == 0 &&
           child[offset - 1] == '.';
}

struct UsedList {
    std::string name;
    std::set<std::string> outbounds;  // outbounds this list routes to
};

// Lists referenced by enabled rules, with the outbounds each one feeds. A list
// used by two rules with the same outbound is not ambiguous; one used by rules
// with different outbounds already has an internal conflict the operator owns.
std::map<std::string, UsedList> collect_used_lists(const Config& cfg) {
    std::map<std::string, UsedList> used;
    const auto& rules =
        cfg.route.value_or(RouteConfig{}).rules.value_or(std::vector<RouteRule>{});
    for (const auto& rule : rules) {
        if (!route_rule_enabled(rule)) {
            continue;
        }
        for (const auto& name : route_rule_lists(rule)) {
            auto& entry = used[name];
            entry.name = name;
            entry.outbounds.insert(rule.outbound);
        }
    }
    return used;
}

}  // namespace

const char* ListAdvisory::kind_name(Kind kind) {
    switch (kind) {
        case Kind::OversizedRange:
            return "oversized_range";
        case Kind::ShadowedDomain:
            return "shadowed_domain";
        case Kind::UnusedList:
            return "unused_list";
    }
    return "unknown";
}

std::vector<ListAdvisory> audit_lists(const Config& cfg,
                                      std::uint64_t threshold) {
    std::vector<ListAdvisory> advisories;

    static const std::map<std::string, ListConfig> kNoLists;
    const auto& lists = cfg.lists ? *cfg.lists : kNoLists;
    const auto used = collect_used_lists(cfg);

    // --- Oversized ranges -------------------------------------------------
    for (const auto& [name, usage] : used) {
        const auto list_it = lists.find(name);
        if (list_it == lists.end() || !list_it->second.ip_cidrs) {
            continue;
        }
        for (const auto& raw : *list_it->second.ip_cidrs) {
            std::string addr;
            int prefix_len = 0;
            if (!split_cidr(raw, addr, prefix_len)) {
                continue;
            }

            ListAdvisory advisory;
            advisory.kind = ListAdvisory::Kind::OversizedRange;
            advisory.list = name;
            advisory.entry = raw;
            advisory.prefix_length = prefix_len;

            if (is_ipv4(addr)) {
                const std::uint64_t count = ipv4_addresses(prefix_len);
                if (count <= threshold) {
                    continue;
                }
                advisory.addresses = count;
                advisory.message = keen_pbr3::format(
                    "list '{}' routes {} ({} addresses) — a range this broad "
                    "carries unrelated services with it",
                    name, raw, count);
            } else if (is_ipv6(addr)) {
                // An IPv6 prefix shorter than /48 is a provider-sized
                // allocation, far wider than one service.
                if (prefix_len >= 48) {
                    continue;
                }
                advisory.message = keen_pbr3::format(
                    "list '{}' routes {} — an IPv6 prefix this short is a "
                    "provider-sized allocation, not one service",
                    name, raw);
            } else {
                continue;
            }
            advisories.push_back(std::move(advisory));
        }
    }

    // --- Shadowed domains -------------------------------------------------
    // Flatten every in-use list's domains once, normalised the way dnsmasq
    // sees them, then compare across lists.
    struct DomainEntry {
        std::string list;
        std::string raw;
        std::string normalised;
    };
    std::vector<DomainEntry> domains;
    for (const auto& [name, usage] : used) {
        const auto list_it = lists.find(name);
        if (list_it == lists.end() || !list_it->second.domains) {
            continue;
        }
        for (const auto& raw : *list_it->second.domains) {
            const std::string normalised = to_lower(strip_wildcard(raw));
            if (normalised.empty()) {
                continue;
            }
            domains.push_back({name, raw, normalised});
        }
    }

    for (const auto& parent : domains) {
        for (const auto& child : domains) {
            if (parent.list == child.list) {
                continue;
            }
            if (parent.normalised == child.normalised) {
                // Identical entries in two lists: only a conflict when the
                // outbounds differ, and then it is a duplicate rather than a
                // shadow. The existing duplicate checker owns that case.
                continue;
            }
            if (!domain_covers(parent.normalised, child.normalised)) {
                continue;
            }
            // Same destination for both lists means the shadow changes
            // nothing observable.
            const auto& parent_outbounds = used.at(parent.list).outbounds;
            const auto& child_outbounds = used.at(child.list).outbounds;
            if (parent_outbounds == child_outbounds) {
                continue;
            }

            ListAdvisory advisory;
            advisory.kind = ListAdvisory::Kind::ShadowedDomain;
            advisory.list = parent.list;
            advisory.entry = parent.raw;
            advisory.other_list = child.list;
            advisory.other_entry = child.raw;
            advisory.message = keen_pbr3::format(
                "'{}' in list '{}' also matches '{}' from list '{}', which "
                "routes elsewhere — the broader entry wins for every "
                "subdomain",
                parent.raw, parent.list, child.raw, child.list);
            advisories.push_back(std::move(advisory));
        }
    }

    // --- Unused lists -----------------------------------------------------
    // A list with entries that no enabled rule references. This is the shape
    // of a half-finished intent, and it reads as done: the list is right
    // there in the UI, full of the correct domains, routing nothing.
    for (const auto& [name, list] : lists) {
        if (used.count(name) != 0) {
            continue;
        }
        const std::size_t entries =
            (list.domains ? list.domains->size() : 0) +
            (list.ip_cidrs ? list.ip_cidrs->size() : 0);
        // A list sourced from a URL or file carries the same intent even
        // though it has no inline entries, so it is reported too. Only a list
        // with no source at all is silently skipped — config validation
        // already rejects that, so this is purely defensive.
        const bool has_source =
            entries > 0 ||
            (list.url && !list.url->empty()) ||
            (list.file && !list.file->empty());
        if (!has_source) {
            continue;
        }
        ListAdvisory advisory;
        advisory.kind = ListAdvisory::Kind::UnusedList;
        advisory.list = name;
        advisory.entry_count = entries;
        advisory.message =
            entries > 0
                ? keen_pbr3::format(
                      "list '{}' holds {} entries but no enabled rule "
                      "references it — it routes nothing",
                      name, entries)
                : keen_pbr3::format(
                      "list '{}' is fetched from its source but no enabled "
                      "rule references it — it routes nothing",
                      name);
        advisories.push_back(std::move(advisory));
    }

    std::sort(advisories.begin(), advisories.end(),
              [](const ListAdvisory& a, const ListAdvisory& b) {
                  return std::tie(a.kind, a.list, a.entry, a.other_list,
                                  a.other_entry) <
                         std::tie(b.kind, b.list, b.entry, b.other_list,
                                  b.other_entry);
              });
    return advisories;
}

}  // namespace keen_pbr3
