#ifdef WITH_API

#include "handler_metrics_traffic.hpp"

#include "../config/config.hpp"
#include "../metrics/traffic_counters.hpp"
#include "../util/safe_exec.hpp"

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace keen_pbr3 {

namespace {

// Mirror the iptables backend's KeenPbrTable chain name. The constant lives as
// a private member on IptablesFirewall / IptablesFirewallVerifier and is not
// exported, so — like the verifier does — we restate the shared literal here.
constexpr const char* kMangleChain = "KeenPbrTable";

// Map each fwmark value to its outbound tag. allocate_outbound_marks() returns
// tag -> mark (OutboundMarkMap); the parser wants mark -> tag, so invert it.
std::map<uint32_t, std::string> build_mark_to_tag(const Config& config) {
    const OutboundMarkMap tag_to_mark = allocate_outbound_marks(
        config.fwmark.value_or(FwmarkConfig{}),
        config.outbounds.value_or(std::vector<Outbound>{}));

    std::map<uint32_t, std::string> mark_to_tag;
    for (const auto& [tag, mark] : tag_to_mark) {
        mark_to_tag.emplace(mark, tag);
    }
    return mark_to_tag;
}

} // namespace

void register_metrics_traffic_handler(ApiServer& server, ApiContext& ctx) {
    server.get("/api/metrics/traffic", [&ctx]() -> std::string {
        const Config config = ctx.get_visible_config();
        const auto mark_to_tag = build_mark_to_tag(config);

        nlohmann::json outbounds = nlohmann::json::array();
        nlohmann::json rules = nlohmann::json::array();

        // The route rules backing the kpbrm_<N> sets: rules[N] is route rule N.
        static const std::vector<RouteRule> kNoRules;
        const std::vector<RouteRule>& route_rules =
            (config.route.has_value() && config.route->rules.has_value())
                ? *config.route->rules
                : kNoRules;

        // Read the verbose, exact-counter listing of the mangle chain. -x keeps
        // packet/byte counts un-abbreviated; -n avoids DNS/service lookups.
        const auto capture = safe_exec_capture(
            {"iptables", "-t", "mangle", "-L", kMangleChain, "-v", "-x", "-n"},
            /*suppress_stderr=*/true);

        // On any exec failure (fork/exec failed -> exit_code -1, or iptables
        // returned non-zero) leave both arrays empty but still answer 200.
        if (capture.exit_code == 0) {
            for (const auto& entry :
                 parse_outbound_traffic(capture.stdout_output, mark_to_tag)) {
                outbounds.push_back({
                    {"tag", entry.tag},
                    {"fwmark", entry.fwmark},
                    {"packets", entry.packets},
                    {"bytes", entry.bytes},
                });
            }

            // Per-rule totals, keyed by the index N in "match-set kpbrm_<N>".
            // Map each N back to config.route.rules[N]; skip indices with no
            // matching rule (a stale set, or the listing is ahead of config).
            for (const auto& entry : parse_rule_traffic(capture.stdout_output)) {
                if (entry.index >= route_rules.size()) {
                    continue;
                }
                const RouteRule& rule = route_rules[entry.index];
                rules.push_back({
                    {"index", entry.index},
                    {"outbound", rule.outbound},
                    {"lists", route_rule_lists(rule)},
                    {"packets", entry.packets},
                    {"bytes", entry.bytes},
                });
            }
        }

        nlohmann::json response;
        response["outbounds"] = std::move(outbounds);
        response["rules"] = std::move(rules);
        response["note"] = "counters accumulate since the last firewall apply";
        return response.dump();
    });
}

} // namespace keen_pbr3

#endif // WITH_API
