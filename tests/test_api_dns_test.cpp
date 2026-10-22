#ifdef WITH_API

#include <doctest/doctest.h>
#include <httplib.h>

#include "../src/api/handler_dns_test.hpp"
#include "../src/api/handlers.hpp"
#include "../src/api/server.hpp"
#include "../src/api/sse_broadcaster.hpp"

#include <chrono>
#include <string>

namespace keen_pbr3 {

namespace {

const std::string kDnsTestConfigPath = "/tmp/forest-pbr-dns-test-config.json";

ApiContext make_dns_test_context(SseBroadcaster& broadcaster) {
    return ApiContext{
        kDnsTestConfigPath,
        broadcaster,
        []() { return Config{}; },
        []() { return false; },
        [](Config, std::string) {},
        []() -> std::optional<std::pair<Config, std::string>> { return std::nullopt; },
        []() {},
        [](const Config&) {},
        []() { return ServiceHealthState{}; },
        []() { return RoutingHealthReport{}; },
        []() { return api::RuntimeOutboundsResponse{}; },
        []() { return api::RuntimeInterfaceInventoryResponse{}; },
        [](const Config&) { return std::map<std::string, api::ListRefreshStateValue>{}; },
        [](const std::string&) { return TestRoutingResult{}; },
        []() {},
        []() {},
        [](Config, std::string) { return ConfigApplyResult{}; },
        []() {},
        []() {},
        []() {},
        [](std::optional<std::string>) { return ListRefreshOperationResult{}; },
    };
}

} // namespace

TEST_CASE("dns test SSE notices a client disconnect without a DNS event") {
    SseBroadcaster broadcaster;
    auto context = make_dns_test_context(broadcaster);
    ApiConfig config;
    config.listen = std::string("127.0.0.1:18199");
    ApiServer server(config);
    register_dns_test_handler(server, context);
    server.start();

    int status = 0;
    std::string content_type;
    std::string body;
    httplib::Client client("127.0.0.1", 18199);
    (void)client.Get(
        "/api/dns/test",
        [&status, &content_type](const httplib::Response& response) {
            status = response.status;
            content_type = response.get_header_value("Content-Type");
            return true;
        },
        [&body](const char* data, size_t length) {
            body.append(data, length);
            return false; // the browser tab is closed right after HELLO
        });

    // Without heartbeats the handler thread waited for the next DNS event
    // forever, and stopping the server hung on it.
    const auto stop_started = std::chrono::steady_clock::now();
    server.stop();
    const auto stop_duration = std::chrono::steady_clock::now() - stop_started;

    CHECK(status == 200);
    CHECK(content_type.find("text/event-stream") != std::string::npos);
    CHECK(body == "data: {\"type\":\"HELLO\"}\n\n");
    CHECK(stop_duration < std::chrono::seconds{5});
}

TEST_CASE("dns test SSE sends heartbeats while idle and events when published") {
    SseBroadcaster broadcaster;
    auto context = make_dns_test_context(broadcaster);
    ApiConfig config;
    config.listen = std::string("127.0.0.1:18200");
    ApiServer server(config);
    register_dns_test_handler(server, context);
    server.start();

    std::string body;
    bool published = false;
    httplib::Client client("127.0.0.1", 18200);
    client.set_read_timeout(std::chrono::seconds{10});
    const auto started = std::chrono::steady_clock::now();
    (void)client.Get(
        "/api/dns/test",
        [](const httplib::Response&) { return true; },
        [&](const char* data, size_t length) {
            body.append(data, length);
            if (!published && body.find(": heartbeat\n\n") != std::string::npos) {
                published = true;
                broadcaster.publish(R"({"type":"DNS","domain":"probe.example"})");
            }
            return body.find("probe.example") == std::string::npos;
        });
    const auto elapsed = std::chrono::steady_clock::now() - started;
    server.stop();

    CHECK(body.rfind("data: {\"type\":\"HELLO\"}\n\n", 0) == 0);
    CHECK(body.find(": heartbeat\n\n") != std::string::npos);
    CHECK(body.find("data: {\"type\":\"DNS\",\"domain\":\"probe.example\"}\n\n") !=
          std::string::npos);
    CHECK(elapsed < std::chrono::seconds{8});
}

} // namespace keen_pbr3

#endif // WITH_API
