#include "autoheal.hpp"

#include <algorithm>
#include <map>
#include <string>
#include <unordered_set>
#include <vector>

namespace keen_pbr3 {

namespace {

// True when `rule` is exactly the top-priority auto-heal rule: enabled, routed
// to `outbound`, and matching precisely the single-element list [`list`]. Used
// to decide whether route.rules[0] can be reused as-is rather than prepended.
bool is_autoheal_top_rule(const RouteRule& rule,
                          const std::string& list,
                          const std::string& outbound) {
    if (!route_rule_enabled(rule)) {
        return false;
    }
    if (rule.outbound != outbound) {
        return false;
    }
    const std::vector<std::string>& lists = route_rule_lists(rule);
    return lists.size() == 1 && lists.front() == list;
}

}  // namespace

Config promote_domains(Config cfg,
                       const std::string& list,
                       const std::string& outbound,
                       const std::vector<std::string>& domains) {
    // (1) Ensure the list map exists, then ensure the target list exists with
    //     at least empty domains/ip_cidrs vectors.
    if (!cfg.lists.has_value()) {
        cfg.lists = std::map<std::string, ListConfig>{};
    }
    ListConfig& target = (*cfg.lists)[list];
    if (!target.domains.has_value()) {
        target.domains = std::vector<std::string>{};
    }
    if (!target.ip_cidrs.has_value()) {
        target.ip_cidrs = std::vector<std::string>{};
    }

    // (2) Append new domains, de-duplicated against what the list already holds
    //     (and against each other within this call). Insertion order of the
    //     genuinely-new domains is preserved.
    std::vector<std::string>& existing = *target.domains;
    std::unordered_set<std::string> seen(existing.begin(), existing.end());
    for (const std::string& domain : domains) {
        if (domain.empty()) {
            continue;
        }
        if (seen.insert(domain).second) {
            existing.push_back(domain);
        }
    }

    // (3) Guarantee a top-priority rule {enabled:true, list:[list], outbound}
    //     at route.rules[0], reusing rules[0] if it is already exactly that.
    if (!cfg.route.has_value()) {
        cfg.route = RouteConfig{};
    }
    if (!cfg.route->rules.has_value()) {
        cfg.route->rules = std::vector<RouteRule>{};
    }
    std::vector<RouteRule>& rules = *cfg.route->rules;

    if (rules.empty() || !is_autoheal_top_rule(rules.front(), list, outbound)) {
        RouteRule top;
        top.enabled = true;
        top.list = std::vector<std::string>{list};
        top.outbound = outbound;
        rules.insert(rules.begin(), std::move(top));
    }
    // else: rules[0] is already the desired top rule — leave it untouched.

    return cfg;
}

std::vector<std::string> select_autoheal_promotions(
    bool enabled,
    const std::vector<AutohealDomainStatus>& statuses,
    const std::unordered_set<std::string>& current_auto_list_domains) {
    // Disabled is the default and MUST be an exact no-op: never propose any
    // promotion regardless of the per-domain statuses. An empty `statuses`
    // (which the worker only produces from an empty watchlist) likewise yields
    // nothing, so the loop below already covers that case.
    if (!enabled) {
        return {};
    }

    std::vector<std::string> promotions;
    std::unordered_set<std::string> emitted;
    for (const auto& status : statuses) {
        if (status.domain.empty() || !status.leaking) {
            continue;
        }
        // Already covered by the auto list — adding it again would be a no-op,
        // and promote_domains would dedup it anyway, but skipping here keeps the
        // worker's "promoted" log honest.
        if (current_auto_list_domains.count(status.domain) != 0) {
            continue;
        }
        if (emitted.insert(status.domain).second) {
            promotions.push_back(status.domain);
        }
    }
    return promotions;
}

}  // namespace keen_pbr3
