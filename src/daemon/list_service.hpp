#pragma once

#include "../cache/cache_manager.hpp"
#include "../config/config.hpp"
#include "../util/traced_mutex.hpp"

#include <condition_variable>
#include <exception>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace keen_pbr3 {

struct RemoteListsRefreshResult {
    std::vector<std::string> refreshed_lists;
    std::vector<std::string> changed_lists;
    std::vector<std::string> relevant_changed_lists;
    std::vector<std::string> failed_lists;

    bool any_refreshed() const {
        return !refreshed_lists.empty();
    }

    bool any_changed() const {
        return !changed_lists.empty();
    }

    bool any_relevant_changed() const {
        return !relevant_changed_lists.empty();
    }

    bool any_failed() const {
        return !failed_lists.empty();
    }
};

enum class RemoteListTargetSelectionError {
    None,
    NotFound,
    NotRemote,
};

struct RemoteListTargetSelection {
    RemoteListTargetSelectionError error{RemoteListTargetSelectionError::None};
    std::vector<std::string> list_names;

    bool ok() const {
        return error == RemoteListTargetSelectionError::None;
    }
};

RemoteListTargetSelection select_remote_list_targets(
    const Config& config,
    const std::optional<std::string>& requested_name);

std::set<std::string> collect_relevant_list_names(const Config& config);

bool should_reload_runtime_after_list_refresh(
    bool routing_runtime_active,
    const RemoteListsRefreshResult& refresh_result);

std::map<std::string, api::ListRefreshStateValue> build_list_refresh_state_map(
    const Config& config,
    const CacheManager& cache_manager);

class ListService {
public:
    ListService(const std::filesystem::path& cache_dir,
                size_t max_file_size_bytes = kDefaultMaxFileSizeBytes);

    void ensure_dir();
    const CacheManager& cache_manager() const;

    // Download the URL-backed lists that have no cache yet.
    RemoteListsRefreshResult download_uncached(
        const Config& config,
        const OutboundMarkMap& outbound_marks,
        const std::set<std::string>* relevant_lists = nullptr);
    RemoteListsRefreshResult refresh_remote_lists(
        const Config& config,
        const OutboundMarkMap& outbound_marks,
        const std::set<std::string>* relevant_lists = nullptr,
        const std::set<std::string>* target_lists = nullptr);

private:
    // One list refresh transaction. Callers asking for the same refresh while
    // it runs join it and share its result (or its exception).
    struct RefreshFlight {
        std::string key;
        bool done{false};
        RemoteListsRefreshResult result;
        std::exception_ptr error;
        std::condition_variable completed;
    };

    RemoteListsRefreshResult download_remote_lists(
        const Config& config,
        const OutboundMarkMap& outbound_marks,
        bool only_uncached,
        const std::set<std::string>* relevant_lists,
        const std::set<std::string>* target_lists);
    RemoteListsRefreshResult run_refresh_transaction(
        const Config& config,
        const OutboundMarkMap& outbound_marks,
        bool only_uncached,
        const std::set<std::string>* relevant_lists,
        const std::set<std::string>* target_lists);

    mutable TracedMutex mutex_;
    // Serializes refresh transactions: startup, scheduled, API and config
    // apply refreshes all write the same deterministic cache temp paths.
    std::mutex refresh_mutex_;
    std::condition_variable refresh_available_;
    std::shared_ptr<RefreshFlight> refresh_flight_;
    CacheManager cache_manager_;
};

} // namespace keen_pbr3
