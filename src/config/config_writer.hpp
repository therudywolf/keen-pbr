#pragma once

#include "config.hpp"

#include <functional>
#include <string>

#include <nlohmann/json.hpp>

namespace keen_pbr3 {

// Serialize a Config to the canonical on-disk JSON form used when staging and
// saving config: empty objects are pruned (so absent optionals do not litter
// the file) and the document is tab-indented with a trailing newline.
//
// Shared by the config/autoheal API handlers and the auto-heal worker so every
// persisted config is formatted identically regardless of which path produced
// it. Defined here (rather than the WITH_API config_staging.hpp) so the daemon
// worker can reuse it in every build variant.
inline std::string serialize_config_pretty(const Config& config) {
    nlohmann::json json = config;
    std::function<bool(nlohmann::json&)> prune_json = [&](nlohmann::json& value) -> bool {
        if (value.is_object()) {
            for (auto it = value.begin(); it != value.end();) {
                if (prune_json(it.value())) {
                    it = value.erase(it);
                } else {
                    ++it;
                }
            }
            return value.empty();
        }

        if (value.is_array()) {
            for (auto& item : value) {
                (void)prune_json(item);
            }
            return false;
        }

        return value.is_null();
    };

    (void)prune_json(json);
    return json.dump(1, '\t') + "\n";
}

// Atomically replace the file at `config_path` with `body`.
// =========================================================
// Writes to `<config_path>.tmp`, fsyncs it, renames it over the target, then
// fsyncs the containing directory so the rename is durable. Throws
// std::runtime_error (with the errno reason) on any failure, leaving the
// previous file untouched and removing the temp file.
//
// This is the single canonical config writer shared by POST /api/config/save
// and the auto-heal worker, so every code path that persists config.json uses
// identical, crash-safe semantics.
void write_config_atomically(const std::string& config_path,
                             const std::string& body);

}  // namespace keen_pbr3
