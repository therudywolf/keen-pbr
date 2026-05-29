#include "dns_split_marks.hpp"

#include <string_view>

#include "../config/routing_state.hpp"
#include "../dns/dnsmasq_gen.hpp"
#include "../lists/list_entry_visitor.hpp"
#include "../lists/list_streamer.hpp"

namespace keen_pbr3 {

std::map<std::string, uint32_t> build_dns_split_domain_marks(
    const Config& config,
    const OutboundMarkMap& outbound_marks,
    const std::map<std::string, std::string>& urltest_selections,
    const CacheManager& cache_manager) {
    std::map<std::string, uint32_t> domain_marks;

    const auto rule_states =
        build_fw_rule_states(config, outbound_marks, &urltest_selections);
    static const std::map<std::string, ListConfig> empty_lists;
    const auto& lists_map = config.lists ? *config.lists : empty_lists;

    ListStreamer streamer(cache_manager);
    for (const auto& rs : rule_states) {
        // Only marking rules with a real fwmark contribute a domain->mark
        // correlation; Drop/Pass/Skip rules and the unmarked default do not.
        if (rs.action_type != RuleActionType::Mark || rs.fwmark == 0) {
            continue;
        }
        for (const auto& list_name : rs.list_names) {
            auto it = lists_map.find(list_name);
            if (it == lists_map.end()) {
                continue;
            }
            const uint32_t mark = rs.fwmark;
            FunctionalVisitor collector([&](EntryType type, std::string_view entry) {
                if (type != EntryType::Domain) {
                    return;  // DNS-split keys on domains only; IP/CIDR use ipsets
                }
                std::string bare = DnsmasqGenerator::strip_wildcard(std::string(entry));
                if (!bare.empty()) {
                    domain_marks[bare] = mark;
                }
            });
            streamer.stream_list_preferring_cache(list_name, it->second, collector);
        }
    }
    return domain_marks;
}

}  // namespace keen_pbr3
