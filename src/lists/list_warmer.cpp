#include "list_warmer.hpp"

#include "../dns/dns_txt_client.hpp"
#include "../dns/dnsmasq_gen.hpp"
#include "../log/logger.hpp"
#include "../util/blocking_executor.hpp"
#include "../util/safe_exec.hpp"

#include <stdexcept>
#include <utility>

namespace keen_pbr3 {

namespace {

// Format the resolver target for the DNS helper functions, which expect a
// "ip" or "ip:port" string.
std::string format_resolver_address(const ListWarmer::Settings& settings) {
    if (settings.upstream_dns_port == 53) {
        return settings.upstream_dns_ip;
    }
    return settings.upstream_dns_ip + ":" + std::to_string(settings.upstream_dns_port);
}

} // namespace

bool default_ipset_add(const std::string& set_name,
                       const std::vector<std::string>& ips,
                       uint32_t timeout_seconds) {
    if (ips.empty()) {
        return true;
    }
    // Build a multi-line script and pipe to `ipset -! restore`. The `-!` is
    // the GLOBAL "ignore errors" flag (equivalent to per-command `-exist`)
    // and is the only form that ipset's restore parser actually accepts on
    // this kernel/ipset combo (busybox + Entware mipsel-3.4, ipset v7.24).
    // Per-line `-exist` is silently rejected with rc=2 in restore mode. Piping
    // the whole batch into ONE `ipset` subprocess collapses N forks into 1 —
    // critical for the weak MIPS routers this daemon targets.
    std::string script;
    script.reserve(ips.size() * 64);
    for (const auto& ip : ips) {
        script += "add ";
        script += set_name;
        script += ' ';
        script += ip;
        if (timeout_seconds > 0) {
            script += " timeout ";
            script += std::to_string(timeout_seconds);
        }
        script += '\n';
    }
    const int rc = safe_exec_pipe_stdin({"ipset", "-!", "restore"}, script);
    if (rc != 0) {
        // Log at warn so kernel/ipset breakage is visible. `ipset restore`
        // returning non-zero is rare on a healthy router; the named set being
        // absent or the kernel module unloaded would do it.
        Logger::instance().warn(
            "list_warmer: ipset restore failed set={} ips={} timeout={} rc={}",
            set_name, ips.size(), timeout_seconds, rc);
        return false;
    }
    return true;
}

ListWarmer::ListWarmer(Settings settings,
                       std::function<const Config&()> get_app_config,
                       BlockingExecutor* executor)
    : ListWarmer(std::move(settings),
                 std::move(get_app_config),
                 executor,
                 [](const std::string& server, const std::string& domain,
                    std::chrono::milliseconds timeout) {
                     return query_dns_a_records(server, domain, timeout, nullptr);
                 },
                 [](const std::string& server, const std::string& domain,
                    std::chrono::milliseconds timeout) {
                     return query_dns_aaaa_records(server, domain, timeout, nullptr);
                 },
                 &default_ipset_add) {}

ListWarmer::ListWarmer(Settings settings,
                       std::function<const Config&()> get_app_config,
                       BlockingExecutor* executor,
                       AResolver a_resolver,
                       AaaaResolver aaaa_resolver,
                       IpsetAdder ipset_adder)
    : settings_(std::move(settings)),
      get_app_config_(std::move(get_app_config)),
      executor_(executor),
      a_resolver_(std::move(a_resolver)),
      aaaa_resolver_(std::move(aaaa_resolver)),
      ipset_adder_(std::move(ipset_adder)) {
    if (!get_app_config_) {
        throw std::invalid_argument("ListWarmer requires a config accessor");
    }
    if (!a_resolver_ || !aaaa_resolver_ || !ipset_adder_) {
        throw std::invalid_argument("ListWarmer requires non-null resolver/adder hooks");
    }
}

int ListWarmer::warm_once() {
    const Config& cfg = get_app_config_();
    if (!cfg.lists.has_value()) {
        return 0;
    }

    // Resolve IPv6 enablement the same way the rest of the daemon does: an
    // explicit `false` in daemon.ipv6_enabled disables it; everything else is
    // treated as enabled for the purposes of warming (system-level support is
    // a runtime issue the AAAA query will surface as an empty result).
    const bool ipv6_enabled =
        !(cfg.daemon.has_value()
          && cfg.daemon->ipv6_enabled.has_value()
          && !*cfg.daemon->ipv6_enabled);

    int queued = 0;
    for (const auto& [list_name, list_cfg] : *cfg.lists) {
        // Lists without `domains` (pure IP/CIDR/file/url-backed) have nothing
        // for the warmer to do — their entries are static.
        if (!list_cfg.domains.has_value() || list_cfg.domains->empty()) {
            continue;
        }

        const std::string v4_set = DnsmasqGenerator::ipset_name_v4(list_name);
        const std::string v6_set = ipv6_enabled
            ? DnsmasqGenerator::ipset_name_v6(list_name)
            : std::string{};

        const int64_t ttl_ms = list_cfg.ttl_ms.value_or(0);
        const uint32_t ipset_timeout =
            ttl_ms >= 1000 ? static_cast<uint32_t>(ttl_ms / 1000) : 0u;

        for (const auto& raw_domain : *list_cfg.domains) {
            if (raw_domain.empty()) {
                continue;
            }
            // Domains in list configs are user-managed and sometimes carry the
            // dnsmasq wildcard prefix "*.example.com". Strip it: the recursive
            // resolver only answers for a concrete hostname.
            std::string domain = raw_domain;
            if (domain.size() > 2 && domain[0] == '*' && domain[1] == '.') {
                domain = domain.substr(2);
            }

            const bool enqueued = executor_->try_post(
                "list-warmer",
                [this, domain, v4_set, v6_set, ipset_timeout]() {
                    try {
                        warm_domain(domain, v4_set, v6_set, ipset_timeout);
                    } catch (const std::exception& e) {
                        // Worker threads must never let exceptions escape;
                        // pthread propagation would terminate the daemon.
                        Logger::instance().warn(
                            "list_warmer: domain warm failed domain={} error={}",
                            domain, e.what());
                    } catch (...) {
                        Logger::instance().warn(
                            "list_warmer: domain warm failed domain={} error=unknown",
                            domain);
                    }
                });

            if (!enqueued) {
                // Queue full or executor shut down. Skip the rest of the pass;
                // the next scheduled warm_once will retry from scratch.
                Logger::instance().verbose(
                    "list_warmer: executor full, deferring remaining domains");
                return queued;
            }
            ++queued;
        }
    }
    return queued;
}

void ListWarmer::warm_domain(const std::string& domain,
                             const std::string& v4_set_name,
                             const std::string& v6_set_name,
                             uint32_t ipset_timeout_seconds) {
    const std::string resolver = format_resolver_address(settings_);

    // IPv4 — one batched ipset call regardless of how many addresses come back.
    const auto v4_addresses = a_resolver_(resolver, domain, settings_.query_timeout);
    if (!v4_addresses.empty()) {
        ipset_adder_(v4_set_name, v4_addresses, ipset_timeout_seconds);
    }

    // IPv6 — only when the v6 set exists for this list. Caller passes an empty
    // string when ipv6 is disabled, which skips the AAAA query entirely (no
    // spurious upstream traffic when v6 is off).
    size_t v6_count = 0;
    if (!v6_set_name.empty()) {
        const auto v6_addresses = aaaa_resolver_(resolver, domain, settings_.query_timeout);
        if (!v6_addresses.empty()) {
            ipset_adder_(v6_set_name, v6_addresses, ipset_timeout_seconds);
        }
        v6_count = v6_addresses.size();
    }

    if (!v4_addresses.empty() || v6_count > 0) {
        Logger::instance().trace("list_warmer_domain_done",
                                 "domain={} v4={} v6={}",
                                 domain,
                                 v4_addresses.size(),
                                 v6_count);
    }
}

} // namespace keen_pbr3
