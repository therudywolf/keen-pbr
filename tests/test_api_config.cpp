#ifdef WITH_API

#include <doctest/doctest.h>
#include <httplib.h>
#include <nlohmann/json.hpp>

#include "../src/api/handler_config.hpp"
#include "../src/api/server.hpp"
#include "../src/api/sse_broadcaster.hpp"

#include <filesystem>
#include <fstream>
#include <iterator>
#include <optional>
#include <stdexcept>
#include <string>
#include <unistd.h>
#include <utility>

namespace keen_pbr3 {

namespace {

class TempDir {
public:
    TempDir() {
        char pattern[] = "/tmp/forest-pbr-api-config-XXXXXX";
        const char* created = ::mkdtemp(pattern);
        if (created == nullptr) throw std::runtime_error("mkdtemp failed");
        path = created;
    }
    ~TempDir() {
        std::error_code ec;
        std::filesystem::remove_all(path, ec);
    }
    std::filesystem::path path;
};

std::string read_file(const std::filesystem::path& path) {
    std::ifstream input(path);
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

// Minimal stand-in for the daemon side of the config endpoints: a staged
// draft, and an apply callback whose outcome a test can choose.
struct FakeConfigDaemon {
    std::string config_path;
    std::optional<std::pair<Config, std::string>> staged;
    ConfigApplyResult next_apply_result;
    std::string file_at_apply_time;
    int apply_calls{0};

    ApiContext make_context(SseBroadcaster& broadcaster) {
        return ApiContext{
            config_path,
            broadcaster,
            []() { return Config{}; },
            [this]() { return staged.has_value(); },
            [this](Config config, std::string json) { staged = std::make_pair(std::move(config), std::move(json)); },
            [this]() { return staged; },
            [this]() { staged.reset(); },
            [](const Config&) {},
            []() { return ServiceHealthState{}; },
            []() { return RoutingHealthReport{}; },
            []() { return api::RuntimeOutboundsResponse{}; },
            []() { return api::RuntimeInterfaceInventoryResponse{}; },
            [](const Config&) { return std::map<std::string, api::ListRefreshStateValue>{}; },
            [](const std::string&) { return TestRoutingResult{}; },
            []() {},
            []() {},
            [this](Config, std::string json) {
                ++apply_calls;
                file_at_apply_time = read_file(config_path);
                if (next_apply_result.applied) {
                    // The daemon clears the draft it just applied.
                    if (staged.has_value() && staged->second == json) staged.reset();
                }
                return next_apply_result;
            },
            []() {},
            []() {},
            []() {},
            [](std::optional<std::string>) { return ListRefreshOperationResult{}; },
        };
    }
};

ConfigApplyResult applied_result() {
    ConfigApplyResult result;
    result.applied = true;
    return result;
}

} // namespace

TEST_CASE("POST /api/config/save writes config.json only after a successful apply") {
    TempDir dir;
    FakeConfigDaemon daemon;
    daemon.config_path = (dir.path / "config.json").string();
    { std::ofstream(daemon.config_path) << "old\n"; }
    daemon.staged = std::make_pair(Config{}, std::string("{\n\t\"new\": true\n}\n"));
    daemon.next_apply_result = applied_result();

    SseBroadcaster broadcaster;
    auto ctx = daemon.make_context(broadcaster);
    ApiConfig api_config;
    api_config.listen = std::string("127.0.0.1:18195");
    ApiServer server(api_config);
    register_config_handler(server, ctx);
    server.start();

    httplib::Client client("127.0.0.1", 18195);
    const auto response = client.Post("/api/config/save", "", "application/json");
    server.stop();

    REQUIRE(response != nullptr);
    CHECK(response->status == 200);
    const auto body = nlohmann::json::parse(response->body);
    CHECK(body["saved"] == true);
    CHECK(body["applied"] == true);
    CHECK(daemon.apply_calls == 1);
    // The file still held the old config while the runtime applied the new one.
    CHECK(daemon.file_at_apply_time == "old\n");
    CHECK(read_file(daemon.config_path) == "{\n\t\"new\": true\n}\n");
}

TEST_CASE("POST /api/config/save leaves config.json untouched when the apply is rolled back") {
    TempDir dir;
    FakeConfigDaemon daemon;
    daemon.config_path = (dir.path / "config.json").string();
    { std::ofstream(daemon.config_path) << "old\n"; }
    daemon.staged = std::make_pair(Config{}, std::string("{\n\t\"broken\": true\n}\n"));
    daemon.next_apply_result.applied = false;
    daemon.next_apply_result.rolled_back = true;
    daemon.next_apply_result.error = "iptables-restore exited with status 1";

    SseBroadcaster broadcaster;
    auto ctx = daemon.make_context(broadcaster);
    ApiConfig api_config;
    api_config.listen = std::string("127.0.0.1:18196");
    ApiServer server(api_config);
    register_config_handler(server, ctx);
    server.start();

    httplib::Client client("127.0.0.1", 18196);
    const auto response = client.Post("/api/config/save", "", "application/json");
    server.stop();

    REQUIRE(response != nullptr);
    CHECK(response->status == 500);
    const auto body = nlohmann::json::parse(response->body);
    CHECK(body["saved"] == false);
    CHECK(body["applied"] == false);
    CHECK(body["rolled_back"] == true);
    CHECK(read_file(daemon.config_path) == "old\n");
    // The draft stays staged so it can be fixed or discarded.
    CHECK(daemon.staged.has_value());
}

TEST_CASE("POST /api/config/save keeps the draft when the applied config cannot be written") {
    TempDir dir;
    FakeConfigDaemon daemon;
    // The config path is a symlink: the writer refuses to replace it.
    const auto target = dir.path / "real.json";
    { std::ofstream(target) << "old\n"; }
    daemon.config_path = (dir.path / "config.json").string();
    REQUIRE(::symlink(target.c_str(), daemon.config_path.c_str()) == 0);
    daemon.staged = std::make_pair(Config{}, std::string("{}\n"));
    daemon.next_apply_result = applied_result();

    SseBroadcaster broadcaster;
    auto ctx = daemon.make_context(broadcaster);
    ApiConfig api_config;
    api_config.listen = std::string("127.0.0.1:18197");
    ApiServer server(api_config);
    register_config_handler(server, ctx);
    server.start();

    httplib::Client client("127.0.0.1", 18197);
    const auto response = client.Post("/api/config/save", "", "application/json");
    server.stop();

    REQUIRE(response != nullptr);
    CHECK(response->status == 500);
    const auto body = nlohmann::json::parse(response->body);
    CHECK(body["saved"] == false);
    CHECK(body["applied"] == true);
    CHECK(read_file(target) == "old\n");
    REQUIRE(daemon.staged.has_value());
    CHECK(daemon.staged->second == "{}\n");
}

} // namespace keen_pbr3

#endif // WITH_API
