#include "dns_router.hpp"
#include "keenetic_dns.hpp"

#include <set>

namespace keen_pbr3 {

DnsServerRegistry::DnsServerRegistry(const DnsConfig& dns_config)
    : fallback_tags_(dns_config.fallback.value_or(std::vector<std::string>{})) {
    const std::vector<DnsServer> servers = dns_config.servers.value_or(std::vector<DnsServer>{});

    // Tags whose addresses something uses: the fallback list, enabled rules,
    // and servers with a detour (their traffic gets mark rules). A keenetic
    // server nothing uses is not resolved: resolving it is an RCI call, and
    // with NDM hung that call fails. On 2026-11-04 an unused keenetic server
    // made the daemon exit at start for exactly that reason.
    std::set<std::string> used_tags(fallback_tags_.begin(), fallback_tags_.end());
    for (const auto& rule : dns_config.rules.value_or(std::vector<DnsRule>{})) {
        if (dns_rule_enabled(rule)) {
            used_tags.insert(rule.server);
        }
    }
    for (const auto& server : servers) {
        if (server.detour.has_value()) {
            used_tags.insert(server.tag);
        }
    }

    // Parse all DNS server definitions into DnsServerConfig
    for (const auto& server : servers) {
        const auto server_type = server.type.value_or(api::DnsServerType::STATIC);
        if (server_type == api::DnsServerType::KEENETIC) {
            // A known tag even when unused, so lookups find it (with no addresses).
            auto& resolved_servers = servers_[server.tag];
            if (used_tags.count(server.tag) == 0) {
                continue;
            }
            for (const auto& resolved_address : resolve_keenetic_dns_addresses()) {
                resolved_servers.push_back(
                    parse_dns_server(server.tag, resolved_address, server.detour));
            }
        } else if (server_type == api::DnsServerType::STATIC) {
            if (!server.address.has_value()) {
                throw DnsError("DNS server '" + server.tag + "' is missing address");
            }
            servers_[server.tag].push_back(
                parse_dns_server(server.tag, *server.address, server.detour));
        } else {
            throw DnsError("DNS server '" + server.tag + "' has unsupported type");
        }
    }

    // Validate that fallback server tags exist
    for (const auto& fallback_tag : fallback_tags_) {
        if (servers_.find(fallback_tag) == servers_.end()) {
            throw DnsError("DNS fallback server tag not found: '" + fallback_tag + "'");
        }
    }

    // Validate that all rule server tags exist
    for (const auto& rule : dns_config.rules.value_or(std::vector<DnsRule>{})) {
        if (!dns_rule_enabled(rule)) {
            continue;
        }
        if (servers_.find(rule.server) == servers_.end()) {
            throw DnsError("DNS rule references unknown server tag: '" + rule.server + "'");
        }
    }
}

std::vector<const DnsServerConfig*> DnsServerRegistry::get_servers(const std::string& tag) const {
    std::vector<const DnsServerConfig*> resolved_servers;
    auto it = servers_.find(tag);
    if (it == servers_.end()) {
        return resolved_servers;
    }
    resolved_servers.reserve(it->second.size());
    for (const auto& server : it->second) {
        resolved_servers.push_back(&server);
    }
    return resolved_servers;
}

std::vector<const DnsServerConfig*> DnsServerRegistry::fallback_servers() const {
    std::vector<const DnsServerConfig*> fallback_servers;
    for (const auto& fallback_tag : fallback_tags_) {
        const auto resolved_servers = get_servers(fallback_tag);
        fallback_servers.insert(fallback_servers.end(),
                                resolved_servers.begin(),
                                resolved_servers.end());
    }
    return fallback_servers;
}

} // namespace keen_pbr3
