#include "list_service.hpp"

#include "../log/logger.hpp"

#include <algorithm>

namespace keen_pbr3 {

namespace {

const std::map<std::string, ListConfig>& config_lists(const Config& config) {
    static const std::map<std::string, ListConfig> empty_lists;
    return config.lists ? *config.lists : empty_lists;
}

bool in_refresh_scope(const std::string& name,
                      const ListConfig& list_cfg,
                      const std::set<std::string>* target_lists) {
    return list_cfg.url.has_value() &&
           (target_lists == nullptr || target_lists->count(name) != 0);
}

// Identity of a refresh transaction: everything that decides what it
// downloads and how it reports the result. Built only from the URL-backed
// lists in scope (not from the whole config, which on a router can carry
// thousands of inline domains) so computing it stays cheap.
std::string refresh_flight_key(const Config& config,
                               const OutboundMarkMap& outbound_marks,
                               bool only_uncached,
                               const std::set<std::string>* relevant_lists,
                               const std::set<std::string>* target_lists) {
    std::string key = only_uncached ? "uncached" : "all";
    for (const auto& [name, list_cfg] : config_lists(config)) {
        if (!in_refresh_scope(name, list_cfg, target_lists)) {
            continue;
        }
        key += '\n';
        key += name;
        key += '\t';
        key += *list_cfg.url;
        key += '\t';
        if (list_cfg.detour.has_value()) {
            const auto it = outbound_marks.find(*list_cfg.detour);
            key += it != outbound_marks.end() ? std::to_string(it->second)
                                              : "?" + *list_cfg.detour;
        }
        key += '\t';
        key += relevant_lists != nullptr && relevant_lists->count(name) != 0 ? 'r' : '-';
    }
    return key;
}

} // namespace

RemoteListTargetSelection select_remote_list_targets(
    const Config& config,
    const std::optional<std::string>& requested_name) {
    RemoteListTargetSelection selection;
    const auto& lists = config_lists(config);

    if (requested_name.has_value()) {
        auto it = lists.find(*requested_name);
        if (it == lists.end()) {
            selection.error = RemoteListTargetSelectionError::NotFound;
            return selection;
        }
        if (!it->second.url.has_value()) {
            selection.error = RemoteListTargetSelectionError::NotRemote;
            return selection;
        }

        selection.list_names.push_back(it->first);
        return selection;
    }

    for (const auto& [name, list_cfg] : lists) {
        if (list_cfg.url.has_value()) {
            selection.list_names.push_back(name);
        }
    }

    return selection;
}

std::set<std::string> collect_relevant_list_names(const Config& config) {
    std::set<std::string> relevant_lists;

    for (const auto& rule : config.route.value_or(RouteConfig{}).rules.value_or(std::vector<RouteRule>{})) {
        if (!route_rule_enabled(rule)) {
            continue;
        }
        const auto& route_lists = route_rule_lists(rule);
        relevant_lists.insert(route_lists.begin(), route_lists.end());
    }

    for (const auto& rule : config.dns.value_or(DnsConfig{}).rules.value_or(std::vector<DnsRule>{})) {
        if (!dns_rule_enabled(rule)) {
            continue;
        }
        relevant_lists.insert(rule.list.begin(), rule.list.end());
    }

    return relevant_lists;
}

bool should_reload_runtime_after_list_refresh(
    bool routing_runtime_active,
    const RemoteListsRefreshResult& refresh_result) {
    return routing_runtime_active && refresh_result.any_relevant_changed();
}

std::map<std::string, api::ListRefreshStateValue> build_list_refresh_state_map(
    const Config& config,
    const CacheManager& cache_manager) {
    std::map<std::string, api::ListRefreshStateValue> refresh_state;

    for (const auto& [name, list_cfg] : config_lists(config)) {
        if (!list_cfg.url.has_value()) {
            continue;
        }

        api::ListRefreshStateValue state;
        const auto metadata = cache_manager.load_metadata(name);
        state.last_updated = metadata.download_time;
        refresh_state.emplace(name, std::move(state));
    }

    return refresh_state;
}

ListService::ListService(const std::filesystem::path& cache_dir,
                         size_t max_file_size_bytes)
    : cache_manager_(cache_dir, max_file_size_bytes) {}

void ListService::ensure_dir() {
    KPBR_LOCK_GUARD(mutex_);
    cache_manager_.ensure_dir();
}

const CacheManager& ListService::cache_manager() const {
    return cache_manager_;
}

RemoteListsRefreshResult ListService::download_uncached(
    const Config& config,
    const OutboundMarkMap& outbound_marks,
    const std::set<std::string>* relevant_lists) {
    return download_remote_lists(config, outbound_marks, true, relevant_lists, nullptr);
}

RemoteListsRefreshResult ListService::refresh_remote_lists(
    const Config& config,
    const OutboundMarkMap& outbound_marks,
    const std::set<std::string>* relevant_lists,
    const std::set<std::string>* target_lists) {
    return download_remote_lists(config, outbound_marks, false, relevant_lists, target_lists);
}

RemoteListsRefreshResult ListService::download_remote_lists(
    const Config& config,
    const OutboundMarkMap& outbound_marks,
    bool only_uncached,
    const std::set<std::string>* relevant_lists,
    const std::set<std::string>* target_lists) {
    // Nothing to download: no flight, no waiting on an unrelated one.
    const auto& lists = config_lists(config);
    const bool any_in_scope = std::any_of(
        lists.begin(), lists.end(), [target_lists](const auto& entry) {
            return in_refresh_scope(entry.first, entry.second, target_lists);
        });
    if (!any_in_scope) {
        return {};
    }

    // All entry points converge here. A caller asking for the refresh that is
    // already running joins it and receives its result; a different refresh
    // waits, so two transactions never write the same temporary cache files.
    const std::string flight_key = refresh_flight_key(
        config, outbound_marks, only_uncached, relevant_lists, target_lists);
    std::shared_ptr<RefreshFlight> flight;
    {
        std::unique_lock<std::mutex> lock(refresh_mutex_);
        while (refresh_flight_ && refresh_flight_->key != flight_key) {
            refresh_available_.wait(lock);
        }
        if (refresh_flight_) {
            flight = refresh_flight_;
            flight->completed.wait(lock, [&flight]() { return flight->done; });
            if (flight->error) {
                std::rethrow_exception(flight->error);
            }
            return flight->result;
        }
        flight = std::make_shared<RefreshFlight>();
        flight->key = flight_key;
        refresh_flight_ = flight;
    }

    RemoteListsRefreshResult result;
    std::exception_ptr error;
    try {
        result = run_refresh_transaction(
            config, outbound_marks, only_uncached, relevant_lists, target_lists);
    } catch (...) {
        error = std::current_exception();
    }

    {
        std::lock_guard<std::mutex> lock(refresh_mutex_);
        flight->result = result;
        flight->error = error;
        flight->done = true;
        refresh_flight_.reset();
    }
    flight->completed.notify_all();
    refresh_available_.notify_all();

    if (error) {
        std::rethrow_exception(error);
    }
    return result;
}

RemoteListsRefreshResult ListService::run_refresh_transaction(
    const Config& config,
    const OutboundMarkMap& outbound_marks,
    bool only_uncached,
    const std::set<std::string>* relevant_lists,
    const std::set<std::string>* target_lists) {
    RemoteListsRefreshResult result;

    for (const auto& [name, list_cfg] : config_lists(config)) {
        if (!in_refresh_scope(name, list_cfg, target_lists)) {
            continue;
        }

        if (only_uncached) {
            KPBR_LOCK_GUARD(mutex_);
            if (cache_manager_.has_cache(name)) {
                continue;
            }
        }

        result.refreshed_lists.push_back(name);

        uint32_t fwmark = 0;
        if (list_cfg.detour.has_value()) {
            auto it = outbound_marks.find(*list_cfg.detour);
            if (it != outbound_marks.end()) {
                fwmark = it->second;
            } else {
                Logger::instance().warn(
                    "List '{}': detour outbound '{}' not found, using default routing",
                    name,
                    *list_cfg.detour);
            }
        }

        const auto download_result = cache_manager_.download(
            name,
            *list_cfg.url,
            CacheDownloadOptions{fwmark});

        if (download_result.failed()) {
            result.failed_lists.push_back(name);
            Logger::instance().warn("List '{}': failed to refresh {}: {}",
                                    name,
                                    *list_cfg.url,
                                    download_result.error_message.empty()
                                        ? std::string("unknown error")
                                        : download_result.error_message);
            continue;
        }

        if (!download_result.updated()) {
            continue;
        }

        result.changed_lists.push_back(name);
        if (relevant_lists && relevant_lists->count(name) > 0) {
            result.relevant_changed_lists.push_back(name);
        }
    }

    return result;
}

} // namespace keen_pbr3
