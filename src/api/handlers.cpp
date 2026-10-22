#ifdef WITH_API

#include "handlers.hpp"
#include "handler_health_service.hpp"
#include "handler_lists_refresh.hpp"
#include "handler_reload.hpp"
#include "handler_config.hpp"
#include "handler_health_routing.hpp"
#include "handler_runtime_interfaces.hpp"
#include "handler_runtime_outbounds.hpp"
#include "handler_lists_audit.hpp"
#include "handler_metrics_traffic.hpp"
#include "handler_autoheal.hpp"
#include "handler_test_routing.hpp"
#include "handler_dns_test.hpp"

#include "../util/safe_exec.hpp"

#include <fstream>
#include <httplib.h>
#include <iterator>
#include <string>

namespace keen_pbr3 {

namespace {

// GET /api/diagnostics/command-failure - the last failed piped command
// (ipset/iptables-restore, nft) with its input and output as plain text;
// 204 when nothing has failed since boot. The record is replaced
// atomically, so an open stream always reads one consistent record.
void register_command_failure_handler(ApiServer& server) {
    server.get_stream("/api/diagnostics/command-failure",
                      [](const httplib::Request&, httplib::Response& res) {
        std::ifstream input(command_failure_log_path(), std::ios::binary);
        std::string body;
        if (input) {
            body.assign(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
        }
        if (body.empty()) {
            res.status = 204;
            return;
        }
        res.set_content(body, "text/plain; charset=utf-8");
    });
}

} // namespace

void register_api_handlers(ApiServer& server, ApiContext& ctx) {
    register_health_service_handler(server, ctx);
    register_reload_handler(server, ctx);
    register_lists_refresh_handler(server, ctx);
    register_config_handler(server, ctx);
    register_health_routing_handler(server, ctx);
    register_runtime_interfaces_handler(server, ctx);
    register_runtime_outbounds_handler(server, ctx);
    register_metrics_traffic_handler(server, ctx);
    register_lists_audit_handler(server, ctx);
    register_autoheal_handler(server, ctx);
    register_test_routing_handler(server, ctx);
    register_dns_test_handler(server, ctx);
    register_command_failure_handler(server);
}

} // namespace keen_pbr3

#endif // WITH_API
