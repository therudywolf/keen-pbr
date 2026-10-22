#pragma once

#include "../config/config.hpp"
#include "netlink.hpp"

#include <optional>
#include <string>
#include <sys/socket.h>
#include <vector>

namespace keen_pbr3 {

// True when `route` is the default route the daemon installs for interface
// outbound `outbound` (same device; same gateway when one is configured for
// the route's family).
inline bool route_matches_interface_outbound(const DumpedRoute& route, const Outbound& outbound) {
    if (route.destination != "default" || route.blackhole || route.unreachable) {
        return false;
    }
    if (outbound.type != OutboundType::INTERFACE) {
        return false;
    }
    if (route.interface != outbound.interface) {
        return false;
    }
    if (route.family == AF_INET && outbound.gateway.has_value()) {
        return route.gateway == outbound.gateway;
    }
    if (route.family == AF_INET6 && outbound.gateway6.has_value()) {
        return route.gateway == outbound.gateway6;
    }
    return !route.gateway.has_value();
}

// The child a URLTEST outbound currently routes through, read back from the
// metric-0 default routes of its table (the lower-priority fallback routes
// have metrics 1..N). Its IPv4 and IPv6 default routes must name the same
// child; anything ambiguous or unknown yields std::nullopt. The status
// command uses it because only the running daemon knows its selection.
inline std::optional<std::string> infer_urltest_selection_from_routes(
    const std::vector<Outbound>& outbounds,
    const Outbound& urltest,
    const std::vector<DumpedRoute>& routes) {
    std::optional<std::string> selected_tag;

    for (const auto& route : routes) {
        if (route.destination != "default" || route.blackhole || route.unreachable ||
            route.metric != 0) {
            continue;
        }

        std::optional<std::string> route_tag;
        for (const auto& group : urltest.outbound_groups.value_or(std::vector<OutboundGroup>{})) {
            for (const auto& child_tag : group.outbounds) {
                const Outbound* child = nullptr;
                for (const auto& outbound : outbounds) {
                    if (outbound.tag == child_tag) {
                        child = &outbound;
                        break;
                    }
                }
                if (child == nullptr || !route_matches_interface_outbound(route, *child)) {
                    continue;
                }
                if (route_tag.has_value() && *route_tag != child_tag) {
                    return std::nullopt;
                }
                route_tag = child_tag;
            }
        }

        if (!route_tag.has_value()) {
            return std::nullopt;
        }
        if (selected_tag.has_value() && *selected_tag != *route_tag) {
            return std::nullopt;
        }
        selected_tag = std::move(route_tag);
    }

    return selected_tag;
}

} // namespace keen_pbr3
