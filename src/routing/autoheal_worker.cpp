#include "autoheal_worker.hpp"

#include "autoheal.hpp"
#include "../log/logger.hpp"

#include <arpa/inet.h>

#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_set>
#include <vector>

namespace keen_pbr3 {

namespace {

constexpr const char* kDefaultList = "auto";
constexpr const char* kDefaultOutbound = "forestserver_ru";
constexpr int64_t kDefaultIntervalSeconds = 900;

// Mirror handler_autoheal.cpp's accessors so the worker reads the same config
// fields with the same defaults as the manual promote endpoint. Kept local
// (rather than shared) because they are trivial and the handler is WITH_API
// only, whereas the worker links in every build variant.
bool autoheal_enabled(const Config& config) {
    if (config.daemon.has_value() && config.daemon->autoheal_enabled.has_value()) {
        return *config.daemon->autoheal_enabled;
    }
    return false;
}

std::string autoheal_list_name(const Config& config) {
    if (config.daemon.has_value() && config.daemon->autoheal_list.has_value() &&
        !config.daemon->autoheal_list->empty()) {
        return *config.daemon->autoheal_list;
    }
    return kDefaultList;
}

std::string autoheal_outbound_tag(const Config& config) {
    if (config.daemon.has_value() && config.daemon->autoheal_outbound.has_value() &&
        !config.daemon->autoheal_outbound->empty()) {
        return *config.daemon->autoheal_outbound;
    }
    return kDefaultOutbound;
}

std::vector<std::string> autoheal_watchlist(const Config& config) {
    if (config.daemon.has_value() && config.daemon->autoheal_watchlist.has_value()) {
        return *config.daemon->autoheal_watchlist;
    }
    return {};
}

// Domains currently stored in the named list (empty when the list or its
// domains array is absent). Matches handler_autoheal.cpp::list_domains.
std::unordered_set<std::string> list_domains_set(const Config& config,
                                                 const std::string& list) {
    std::unordered_set<std::string> result;
    if (!config.lists.has_value()) {
        return result;
    }
    const auto it = config.lists->find(list);
    if (it == config.lists->end() || !it->second.domains.has_value()) {
        return result;
    }
    for (const auto& domain : *it->second.domains) {
        result.insert(domain);
    }
    return result;
}

bool is_ipv4_address(const std::string& value) {
    struct in_addr addr;
    return inet_pton(AF_INET, value.c_str(), &addr) == 1;
}

// A watchlist domain "leaks" when it resolves to at least one IPv4 address and
// that address's expected routing (per the same evaluation `forest-pbr
// test-routing` performs) does NOT go to the auto-heal outbound. We key off the
// config-derived `expected_outbound` so the decision is deterministic and does
// not depend on the live kernel ipset being populated yet — exactly the routing
// the user's config says the domain should get.
bool domain_is_leaking(const TestRoutingResult& result,
                       const std::string& autoheal_outbound) {
    for (const auto& entry : result.entries) {
        if (!is_ipv4_address(entry.ip)) {
            continue;  // skip IPv6 and synthetic "(no IPs resolved)" rows
        }
        if (entry.expected_outbound != autoheal_outbound) {
            return true;
        }
    }
    return false;
}

std::string join_domains(const std::vector<std::string>& domains) {
    std::ostringstream out;
    for (size_t i = 0; i < domains.size(); ++i) {
        if (i != 0) {
            out << ", ";
        }
        out << domains[i];
    }
    return out.str();
}

}  // namespace

AutohealWorker::AutohealWorker(std::function<const Config&()> get_app_config,
                               RoutingEvaluator routing_evaluator,
                               ConfigApplier config_applier)
    : get_app_config_(std::move(get_app_config)),
      routing_evaluator_(std::move(routing_evaluator)),
      config_applier_(std::move(config_applier)) {
    if (!get_app_config_ || !routing_evaluator_ || !config_applier_) {
        throw std::invalid_argument(
            "AutohealWorker requires non-null config/routing/apply hooks");
    }
}

int AutohealWorker::tick() noexcept {
    try {
        const Config& config = get_app_config_();

        // SAFETY GATE: re-read the live config every tick. Either condition
        // false => exact no-op (no DNS, no config change, no reapply). This is
        // the same default-off guarantee promised in the header and is checked
        // here in addition to the daemon declining to schedule the worker.
        if (!autoheal_enabled(config)) {
            return 0;
        }
        const std::vector<std::string> watchlist = autoheal_watchlist(config);
        if (watchlist.empty()) {
            return 0;
        }

        const std::string list = autoheal_list_name(config);
        const std::string outbound = autoheal_outbound_tag(config);
        const std::unordered_set<std::string> current_auto_domains =
            list_domains_set(config, list);

        // Evaluate every watchlist domain the way `forest-pbr test-routing`
        // does, and record whether it is leaking.
        std::vector<AutohealDomainStatus> statuses;
        statuses.reserve(watchlist.size());
        for (const auto& domain : watchlist) {
            if (domain.empty()) {
                continue;
            }
            AutohealDomainStatus status;
            status.domain = domain;
            try {
                const TestRoutingResult result = routing_evaluator_(domain);
                status.leaking = domain_is_leaking(result, outbound);
            } catch (const std::exception& e) {
                // A single domain's evaluation failing must not abort the pass
                // or trigger a promotion — treat it as not-leaking and move on.
                Logger::instance().warn(
                    "autoheal_worker: routing eval failed domain={} error={}",
                    domain, e.what());
                status.leaking = false;
            }
            statuses.push_back(std::move(status));
        }

        const std::vector<std::string> to_promote =
            select_autoheal_promotions(/*enabled=*/true, statuses, current_auto_domains);
        if (to_promote.empty()) {
            return 0;
        }

        // Apply the SAME transformation as POST /api/autoheal/promote, then hand
        // the result to the daemon's existing config-save path (persist +
        // reapply). promote_domains only adds; nothing else is touched.
        Config promoted = promote_domains(config, list, outbound, to_promote);
        config_applier_(std::move(promoted));

        Logger::instance().info(
            "autoheal_worker: promoted {} leaking domain(s) into list '{}' (outbound '{}'): {}",
            to_promote.size(), list, outbound, join_domains(to_promote));
        return static_cast<int>(to_promote.size());
    } catch (const std::exception& e) {
        Logger::instance().warn("autoheal_worker: tick failed error={}", e.what());
        return 0;
    } catch (...) {
        Logger::instance().warn("autoheal_worker: tick failed error=unknown");
        return 0;
    }
}

}  // namespace keen_pbr3
