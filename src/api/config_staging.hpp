#pragma once

#ifdef WITH_API

#include "../config/config.hpp"

#include <functional>
#include <string>

#include <nlohmann/json.hpp>

namespace keen_pbr3 {

// Serialize a Config to the canonical on-disk JSON form used when staging and
// saving config: empty objects are pruned (so absent optionals do not litter
// the file) and the document is tab-indented with a trailing newline.
//
// Shared by the config and autoheal handlers so every staged config is
// formatted identically regardless of which endpoint produced it.
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

}  // namespace keen_pbr3

#endif  // WITH_API
