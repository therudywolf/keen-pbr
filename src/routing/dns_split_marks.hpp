#pragma once

#include <cstdint>
#include <map>
#include <string>

#include "../config/config.hpp"

namespace keen_pbr3 {

class CacheManager;

// Build the bare-domain -> outbound fwmark map that drives DNS-correlation split
// routing, from the live route rules.
//
// Reuses build_fw_rule_states() — the exact rule->mark resolution the firewall
// uses, honouring urltest selections — then streams every domain in each marking
// rule's lists (cache-preferring, wildcard-stripped) to that rule's fwmark.
// Rules are walked in config order, so a later rule listing the same domain
// overrides an earlier one, matching how the routing rules themselves resolve.
// Only Mark rules with a non-zero fwmark contribute; Drop/Pass/Skip rules and
// IP/CIDR list entries are skipped (those route by ipset, not by name).
//
// This is the table the daemon feeds into a SniClassifier so the observer can
// resolve domain -> mark for each dnsmasq reply line.
std::map<std::string, uint32_t> build_dns_split_domain_marks(
    const Config& config,
    const OutboundMarkMap& outbound_marks,
    const std::map<std::string, std::string>& urltest_selections,
    const CacheManager& cache_manager);

}  // namespace keen_pbr3
