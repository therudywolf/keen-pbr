#pragma once

#include "../cache/cache_manager.hpp"
#include "../config/config.hpp"
#include "../config/list_parser.hpp"
#include "list_entry_visitor.hpp"

#include <cstddef>
#include <string>

namespace keen_pbr3 {

class ListStreamer {
public:
    // Longest accepted line of a list file; longer lines are skipped.
    static constexpr std::size_t kMaxLineBytes = ListParser::kMaxLineBytes;

    explicit ListStreamer(const CacheManager& cache);

    // Stream all sources for a named list (cache file, local file, inline entries)
    // through the visitor. Calls visitor.on_list_complete(name) when done.
    void stream_list(const std::string& name, const ListConfig& config, ListEntryVisitor& visitor);

    // Stream all sources for a named list, the same as stream_list(), but use
    // the cached file whenever it exists — even if the list no longer declares
    // a URL source. Calls visitor.on_list_complete(name) when done.
    void stream_list_preferring_cache(const std::string& name,
                                     const ListConfig& config,
                                     ListEntryVisitor& visitor);

    // Stream only the cached file for a named list through the visitor.
    void stream_cache(const std::string& name, ListEntryVisitor& visitor);

private:
    // Stream a list's local file and inline entries through the visitor,
    // optionally preceded by the cached file. Calls on_list_complete(name).
    void stream_all_sources(const std::string& name,
                            const ListConfig& config,
                            ListEntryVisitor& visitor,
                            bool include_cache);

    // Open a regular file and stream its entries through the visitor.
    // Malformed entries are skipped; they are logged only when
    // log_invalid_entries is set (local files, not downloaded caches).
    static void stream_file(const std::filesystem::path& path,
                            ListEntryVisitor& visitor,
                            bool log_invalid_entries);

    const CacheManager& cache_;
};

} // namespace keen_pbr3
