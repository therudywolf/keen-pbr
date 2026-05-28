#ifdef WITH_API

#include "handler_autoheal.hpp"

#include "config_staging.hpp"
#include "../config/config.hpp"
#include "../routing/autoheal.hpp"

#include <string>
#include <unordered_set>
#include <vector>

#include <nlohmann/json.hpp>

namespace keen_pbr3 {

namespace {

constexpr const char* kDefaultList = "auto";
constexpr const char* kDefaultOutbound = "forestserver_ru";

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

bool autoheal_enabled(const Config& config) {
    if (config.daemon.has_value() && config.daemon->autoheal_enabled.has_value()) {
        return *config.daemon->autoheal_enabled;
    }
    return false;
}

// Domains currently stored in the named list (empty when the list or its
// domains array is absent).
std::vector<std::string> list_domains(const Config& config, const std::string& list) {
    if (!config.lists.has_value()) {
        return {};
    }
    const auto it = config.lists->find(list);
    if (it == config.lists->end() || !it->second.domains.has_value()) {
        return {};
    }
    return *it->second.domains;
}

} // namespace

void register_autoheal_handler(ApiServer& server, ApiContext& ctx) {
    // GET /api/autoheal - report settings and the current auto-list domains.
    server.get("/api/autoheal", [&ctx]() -> std::string {
        const Config config = ctx.get_visible_config();
        const std::string list = autoheal_list_name(config);

        nlohmann::json response;
        response["enabled"] = autoheal_enabled(config);
        response["list"] = list;
        response["outbound"] = autoheal_outbound_tag(config);
        response["domains"] = list_domains(config, list);
        return response.dump();
    });

    // POST /api/autoheal/promote - body {"domains":[...]}. Promote the domains
    // into the auto list, guarantee a top-priority route rule, and STAGE the
    // resulting config via the same validate+serialize path as POST /api/config.
    server.post("/api/autoheal/promote", [&ctx](const std::string& body) -> std::string {
        std::vector<std::string> domains;
        try {
            const nlohmann::json parsed = nlohmann::json::parse(body);
            if (!parsed.is_object() || !parsed.contains("domains") ||
                !parsed.at("domains").is_array()) {
                throw ApiError("Body must be an object with a \"domains\" array", 400);
            }
            for (const auto& item : parsed.at("domains")) {
                if (!item.is_string()) {
                    throw ApiError("\"domains\" must be an array of strings", 400);
                }
                domains.push_back(item.get<std::string>());
            }
        } catch (const ApiError&) {
            throw;
        } catch (const nlohmann::json::exception& e) {
            throw ApiError(std::string("Invalid JSON body: ") + e.what(), 400);
        }

        const Config current = ctx.get_visible_config();
        const std::string list = autoheal_list_name(current);
        const std::string outbound = autoheal_outbound_tag(current);

        // Snapshot the pre-promotion domains so we can report exactly which were
        // newly added (deduped against what was already present).
        const std::vector<std::string> before = list_domains(current, list);
        const std::unordered_set<std::string> before_set(before.begin(), before.end());

        Config promoted = promote_domains(current, list, outbound, domains);

        std::vector<std::string> added;
        {
            std::unordered_set<std::string> emitted;
            for (const std::string& domain : domains) {
                if (domain.empty() || before_set.count(domain) != 0) {
                    continue;
                }
                if (emitted.insert(domain).second) {
                    added.push_back(domain);
                }
            }
        }

        // Stage via the same path POST /api/config uses: re-validate the mutated
        // config and stage its canonical serialization. The global Apply banner
        // then commits it; this endpoint never applies routing on its own.
        try {
            validate_config(promoted);
        } catch (const ConfigError& e) {
            throw ApiError(std::string("Promoted config failed validation: ") + e.what(), 500);
        }

        std::string formatted = serialize_config_pretty(promoted);
        ctx.stage_config(std::move(promoted), std::move(formatted));

        nlohmann::json response;
        response["added"] = added;
        response["list"] = list;
        response["staged"] = true;
        return response.dump();
    });
}

} // namespace keen_pbr3

#endif // WITH_API
