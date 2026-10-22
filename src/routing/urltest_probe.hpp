#pragma once

#include "../config/config.hpp"

#include <map>
#include <string>
#include <vector>

namespace keen_pbr3 {

// Interface each urltest candidate's probe must be bound to, by child tag.
// Interface members are probed through their own device: a member whose
// link is down has an empty table, and a probe carrying only its fwmark
// falls through the ip rules to `main` and succeeds over another uplink.
// Table members (and unknown tags) are probed by fwmark only.
inline std::map<std::string, std::string> urltest_probe_interfaces(
    const Outbound& urltest,
    const std::vector<Outbound>& outbounds) {
    std::map<std::string, std::string> interfaces;
    for (const auto& group : urltest.outbound_groups.value_or(std::vector<OutboundGroup>{})) {
        for (const auto& child_tag : group.outbounds) {
            for (const auto& outbound : outbounds) {
                if (outbound.tag != child_tag) {
                    continue;
                }
                if (outbound.type == OutboundType::INTERFACE &&
                    outbound.interface.has_value() && !outbound.interface->empty()) {
                    interfaces[child_tag] = *outbound.interface;
                }
                break;
            }
        }
    }
    return interfaces;
}

} // namespace keen_pbr3
