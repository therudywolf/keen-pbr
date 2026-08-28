#ifdef WITH_API

#include "handler_metrics_traffic.hpp"

#include "../config/config.hpp"
#include "../metrics/traffic_counters.hpp"
#include "../util/safe_exec.hpp"

#include <algorithm>
#include <cstdint>
#include <map>
#include <mutex>
#include <set>
#include <sstream>
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

// Strip the daemon's per-list set-name prefix (kpbr4_/kpbr6_/kpbr4d_/kpbr6d_)
// and return the encoded list name, or nullopt for combined kpbrm_<N> sets and
// anything else that doesn't carry a list name.
std::optional<std::string> list_name_from_set(const std::string& set_name) {
    static constexpr const char* kPrefixes[] = {
        "kpbr4d_", "kpbr6d_", "kpbr4_", "kpbr6_"};
    for (const char* prefix : kPrefixes) {
        const std::size_t len = std::char_traits<char>::length(prefix);
        if (set_name.size() > len && set_name.compare(0, len, prefix) == 0) {
            return set_name.substr(len);
        }
    }
    return std::nullopt;
}

bool is_combined_set(const std::string& set_name) {
    return set_name.rfind("kpbrm_", 0) == 0;
}

// Read the member set names of a combined kpbrm_<N> list:set straight from
// the kernel. The members ARE the ground truth for what the set matches —
// consolidation assigns kpbrm ordinals by group order, not rule order, so
// reconstructing membership from config would just re-implement (and have to
// stay in sync with) the consolidation pass. `ipset list <name>` on a
// list:set prints one member set name per line after the "Members:" header.
std::vector<std::string> read_combined_members(const std::string& set_name) {
    std::vector<std::string> members;
    const auto capture = safe_exec_capture({"ipset", "list", set_name},
                                           /*suppress_stderr=*/true);
    if (capture.exit_code != 0) {
        return members;
    }
    std::istringstream stream(capture.stdout_output);
    std::string line;
    bool in_members = false;
    while (std::getline(stream, line)) {
        while (!line.empty() && (line.back() == '\r' || line.back() == ' ')) {
            line.pop_back();
        }
        if (!in_members) {
            if (line.rfind("Members:", 0) == 0) {
                in_members = true;
            }
            continue;
        }
        if (line.empty()) {
            continue;
        }
        // Member lines for list:set are bare set names (no spaces).
        const auto space = line.find(' ');
        members.push_back(space == std::string::npos ? line
                                                     : line.substr(0, space));
    }
    return members;
}

// --- Reset-surviving accumulation -----------------------------------------
//
// The kernel counters this endpoint reads are zeroed every time the firewall
// chain is rebuilt — which on Keenetic happens on every NDM netfilter event
// (VPN reconnects, interface flaps), not just on config applies. Raw counters
// therefore describe a random-length window and are useless for observation.
// Detect resets (a counter going backwards) and carry the accumulated total
// across them, so the API reports monotonic totals since daemon start.
//
// The detection is per key (set name / fwmark): if the current raw value is
// below the last seen raw value, a rebuild happened in between; fold the last
// seen value into the base and continue. Traffic that flowed between the
// rebuild and this poll is still counted; traffic between the previous poll
// and the rebuild is lost — an unavoidable floor for polling of resettable
// counters, and far better than silently restarting from zero.
struct CounterBaseline {
    uint64_t last_packets{0};
    uint64_t last_bytes{0};
    uint64_t base_packets{0};
    uint64_t base_bytes{0};

    // Feed the current raw readings; returns accumulated (packets, bytes).
    std::pair<uint64_t, uint64_t> advance(uint64_t packets, uint64_t bytes) {
        if (packets < last_packets || bytes < last_bytes) {
            base_packets += last_packets;
            base_bytes += last_bytes;
        }
        last_packets = packets;
        last_bytes = bytes;
        return {base_packets + packets, base_bytes + bytes};
    }
};

std::mutex g_baseline_mutex;
std::map<std::string, CounterBaseline> g_set_baselines;       // key: set name
std::map<uint32_t, CounterBaseline> g_outbound_baselines;     // key: fwmark

}  // namespace

void register_metrics_traffic_handler(ApiServer& server, ApiContext& ctx) {
    server.get("/api/metrics/traffic", [&ctx]() -> std::string {
        const Config config = ctx.get_visible_config();
        const auto mark_to_tag = build_mark_to_tag(config);

        nlohmann::json outbounds = nlohmann::json::array();
        nlohmann::json rules = nlohmann::json::array();

        static const std::vector<RouteRule> kNoRules;
        const std::vector<RouteRule>& route_rules =
            (config.route.has_value() && config.route->rules.has_value())
                ? *config.route->rules
                : kNoRules;

        // list name -> indices of enabled route rules referencing it. This is
        // the join key from a per-list kpbr set back to the config rules; a
        // list shared by several rules attributes to all of them (the kernel
        // counter genuinely can't be split further).
        std::map<std::string, std::vector<std::size_t>> list_to_rules;
        for (std::size_t i = 0; i < route_rules.size(); ++i) {
            if (!route_rule_enabled(route_rules[i])) {
                continue;
            }
            for (const auto& list_name : route_rule_lists(route_rules[i])) {
                list_to_rules[list_name].push_back(i);
            }
        }

        // Read the verbose, exact-counter listing of the mangle chain. -x keeps
        // packet/byte counts un-abbreviated; -n avoids DNS/service lookups.
        const auto capture = safe_exec_capture(
            {"iptables", "-t", "mangle", "-L", kMangleChain, "-v", "-x", "-n"},
            /*suppress_stderr=*/true);

        // On any exec failure (fork/exec failed -> exit_code -1, or iptables
        // returned non-zero) leave both arrays empty but still answer 200.
        if (capture.exit_code == 0) {
            {
                const std::lock_guard<std::mutex> lock(g_baseline_mutex);
                for (const auto& entry :
                     parse_outbound_traffic(capture.stdout_output, mark_to_tag)) {
                    const auto [packets, bytes] =
                        g_outbound_baselines[entry.fwmark].advance(
                            entry.packets, entry.bytes);
                    outbounds.push_back({
                        {"tag", entry.tag},
                        {"fwmark", entry.fwmark},
                        {"packets", packets},
                        {"bytes", bytes},
                    });
                }
            }

            // Attribute each counting set back to route rules. One
            // "attribution unit" is the group of rules a set's lists belong
            // to: sets resolving to the same rule group merge into one row
            // (e.g. kpbr4_wiz + kpbr4d_wiz both belong to the wiz rule; a
            // combined kpbrm_<N> spanning two rules that share an outbound
            // yields one row attributed to both rules).
            struct Attribution {
                std::vector<std::size_t> rule_indices;  // sorted, unique
                std::set<std::string> lists;            // lists actually counted
                std::set<std::string> sets;             // contributing set names
                uint64_t packets{0};
                uint64_t bytes{0};
            };
            // Keyed by the canonical rule-index vector so identical groups
            // merge; the odd unattributable set (stale kernel state, ipset
            // read failure) lands under the empty key and is still reported.
            std::map<std::vector<std::size_t>, Attribution> attributions;

            const std::lock_guard<std::mutex> lock(g_baseline_mutex);
            for (const auto& entry : parse_set_traffic(capture.stdout_output)) {
                const auto [acc_packets, acc_bytes] =
                    g_set_baselines[entry.set_name].advance(entry.packets,
                                                            entry.bytes);
                // Resolve the set to the list names it counts for.
                std::vector<std::string> lists;
                if (is_combined_set(entry.set_name)) {
                    for (const auto& member :
                         read_combined_members(entry.set_name)) {
                        if (auto list = list_name_from_set(member)) {
                            lists.push_back(std::move(*list));
                        }
                    }
                } else if (auto list = list_name_from_set(entry.set_name)) {
                    lists.push_back(std::move(*list));
                }

                std::set<std::size_t> indices;
                for (const auto& list_name : lists) {
                    const auto it = list_to_rules.find(list_name);
                    if (it == list_to_rules.end()) {
                        continue;
                    }
                    indices.insert(it->second.begin(), it->second.end());
                }

                const std::vector<std::size_t> key(indices.begin(),
                                                   indices.end());
                auto& attribution = attributions[key];
                attribution.rule_indices = key;
                attribution.lists.insert(lists.begin(), lists.end());
                attribution.sets.insert(entry.set_name);
                attribution.packets += acc_packets;
                attribution.bytes += acc_bytes;
            }

            for (const auto& [key, attribution] : attributions) {
                std::string outbound;
                for (const std::size_t idx : attribution.rule_indices) {
                    const std::string& tag = route_rules[idx].outbound;
                    if (outbound.empty()) {
                        outbound = tag;
                    } else if (outbound != tag) {
                        outbound += "+" + tag;
                    }
                }
                rules.push_back({
                    // Back-compat: "index" stays the row's primary rule.
                    {"index", key.empty() ? -1
                                          : static_cast<std::int64_t>(key[0])},
                    {"rule_indices", attribution.rule_indices},
                    {"outbound",
                     outbound.empty() ? "(unknown)" : outbound},
                    {"lists", std::vector<std::string>(
                                  attribution.lists.begin(),
                                  attribution.lists.end())},
                    {"sets", std::vector<std::string>(
                                 attribution.sets.begin(),
                                 attribution.sets.end())},
                    {"packets", attribution.packets},
                    {"bytes", attribution.bytes},
                });
            }
        }

        nlohmann::json response;
        response["outbounds"] = std::move(outbounds);
        response["rules"] = std::move(rules);
        response["note"] =
            "counters accumulate since daemon start (firewall rebuilds are "
            "bridged; traffic between the last poll and a rebuild is lost)";
        return response.dump();
    });
}

} // namespace keen_pbr3

#endif // WITH_API
