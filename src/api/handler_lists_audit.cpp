#ifdef WITH_API

#include "handler_lists_audit.hpp"

#include "../config/list_audit.hpp"

#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace keen_pbr3 {

void register_lists_audit_handler(ApiServer& server, ApiContext& ctx) {
    server.get("/api/lists/audit", [&ctx]() -> std::string {
        const Config config = ctx.get_visible_config();

        nlohmann::json advisories = nlohmann::json::array();
        for (const auto& advisory : audit_lists(config)) {
            nlohmann::json entry{
                {"kind", ListAdvisory::kind_name(advisory.kind)},
                {"list", advisory.list},
                {"entry", advisory.entry},
                {"message", advisory.message},
            };
            switch (advisory.kind) {
                case ListAdvisory::Kind::OversizedRange:
                    entry["addresses"] = advisory.addresses;
                    entry["prefix_length"] = advisory.prefix_length;
                    break;
                case ListAdvisory::Kind::ShadowedDomain:
                    entry["other_list"] = advisory.other_list;
                    entry["other_entry"] = advisory.other_entry;
                    break;
                case ListAdvisory::Kind::UnusedList:
                    entry["entry_count"] = advisory.entry_count;
                    break;
            }
            advisories.push_back(std::move(entry));
        }

        nlohmann::json response;
        response["advisories"] = std::move(advisories);
        response["note"] =
            "advisory only — these never block a config save";
        return response.dump();
    });
}

} // namespace keen_pbr3

#endif // WITH_API
