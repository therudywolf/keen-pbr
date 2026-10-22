#ifdef WITH_API

#include <doctest/doctest.h>
#include <httplib.h>

#include "../src/api/server.hpp"

#include <filesystem>
#include <fstream>
#include <string>
#include <unistd.h>
#include <vector>

namespace keen_pbr3 {

namespace {

std::filesystem::path make_temp_static_root() {
    const auto base = std::filesystem::temp_directory_path();
    for (int i = 0; i < 100; ++i) {
        auto path = base / ("keen-pbr-static-test-" + std::to_string(::getpid()) + "-" + std::to_string(i));
        std::error_code ec;
        if (std::filesystem::create_directory(path, ec)) {
            return path;
        }
    }
    throw std::runtime_error("failed to create temporary static root");
}

void write_file(const std::filesystem::path& path, const std::string& content) {
    std::ofstream file(path, std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("failed to open test file: " + path.string());
    }
    file << content;
}

} // namespace

TEST_CASE("static frontend gzip response does not duplicate compression headers") {
    const auto root = make_temp_static_root();
    write_file(root / "index.html", "<!doctype html><title>keen-pbr</title>");
    write_file(root / "index.html.gz", "pretend-gzip-bytes");

    ApiConfig api_config;
    api_config.listen = std::string("127.0.0.1:18190");

    ApiServer server(api_config);
    REQUIRE(server.register_static_root(root.string()));
    server.start();

    httplib::Client client("127.0.0.1", 18190);
    client.set_decompress(false);
    const httplib::Headers headers{{"Accept-Encoding", "gzip"}};
    const auto response = client.Get("/", headers);
    server.stop();

    std::filesystem::remove_all(root);

    REQUIRE(response != nullptr);
    CHECK(response->status == 200);
    CHECK(response->get_header_value_count("Content-Encoding") == 1);
    CHECK(response->get_header_value("Content-Encoding") == "gzip");
    CHECK(response->get_header_value_count("Vary") == 1);
    CHECK(response->get_header_value("Vary") == "Accept-Encoding");
    CHECK(response->get_header_value("Content-Length") == "18");
    CHECK(response->body == "pretend-gzip-bytes");
}

TEST_CASE("static frontend gzip variant is skipped without gzip accept header") {
    const auto root = make_temp_static_root();
    write_file(root / "index.html", "<!doctype html><title>keen-pbr</title>");
    write_file(root / "index.html.gz", "pretend-gzip-bytes");

    ApiConfig api_config;
    api_config.listen = std::string("127.0.0.1:18191");

    ApiServer server(api_config);
    REQUIRE(server.register_static_root(root.string()));
    server.start();

    httplib::Client client("127.0.0.1", 18191);
    client.set_decompress(false);
    const httplib::Headers headers{{"Accept-Encoding", "identity"}};
    const auto response = client.Get("/", headers);
    server.stop();

    std::filesystem::remove_all(root);

    REQUIRE(response != nullptr);
    CHECK(response->status == 200);
    CHECK(response->get_header_value_count("Content-Encoding") == 0);
    CHECK(response->get_header_value_count("Vary") == 0);
    CHECK(response->body == "<!doctype html><title>keen-pbr</title>");
}

TEST_CASE("static frontend gzip variant respects explicit q zero") {
    const auto root = make_temp_static_root();
    write_file(root / "index.html", "<!doctype html><title>keen-pbr</title>");
    write_file(root / "index.html.gz", "pretend-gzip-bytes");

    ApiConfig api_config;
    api_config.listen = std::string("127.0.0.1:18192");

    ApiServer server(api_config);
    REQUIRE(server.register_static_root(root.string()));
    server.start();

    httplib::Client client("127.0.0.1", 18192);
    client.set_decompress(false);
    const httplib::Headers headers{{"Accept-Encoding", "gzip;q=0, *;q=1"}};
    const auto response = client.Get("/", headers);
    server.stop();

    std::filesystem::remove_all(root);

    REQUIRE(response != nullptr);
    CHECK(response->status == 200);
    CHECK(response->get_header_value_count("Content-Encoding") == 0);
    CHECK(response->body == "<!doctype html><title>keen-pbr</title>");
}

TEST_CASE("API server limits use secure defaults and configured values") {
    ApiConfig defaults;
    const auto default_limits = api_server_limits(defaults);
    CHECK(default_limits.max_request_body_bytes == 1024U * 1024U);
    CHECK(default_limits.read_timeout_seconds == 15);
    CHECK(default_limits.write_timeout_seconds == 15);
    CHECK(default_limits.keep_alive_timeout_seconds == 20);

    ApiConfig configured;
    configured.max_request_body_bytes = 2048;
    configured.read_timeout_seconds = 3;
    configured.write_timeout_seconds = 4;
    configured.keep_alive_timeout_seconds = 5;
    const auto limits = api_server_limits(configured);
    CHECK(limits.max_request_body_bytes == 2048);
    CHECK(limits.read_timeout_seconds == 3);
    CHECK(limits.write_timeout_seconds == 4);
    CHECK(limits.keep_alive_timeout_seconds == 5);
}

TEST_CASE("API origin check accepts same-origin, allowlisted and Origin-less requests") {
    const std::vector<std::string> none;
    const std::vector<std::string> allowed{"http://192.168.1.10:5173"};
    bool cross = true;

    CHECK(api_request_origin_allowed("", "10.77.77.1:12121", none, cross));
    CHECK_FALSE(cross);
    CHECK(api_request_origin_allowed("http://10.77.77.1:12121", "10.77.77.1:12121", none, cross));
    CHECK(api_request_origin_allowed("https://10.77.77.1:12121", "10.77.77.1:12121", none, cross));
    CHECK(api_request_origin_allowed("http://My.Router:12121", "my.router:12121", none, cross));
    CHECK_FALSE(cross);

    CHECK_FALSE(api_request_origin_allowed("http://evil.example", "10.77.77.1:12121", none, cross));
    CHECK_FALSE(api_request_origin_allowed("null", "10.77.77.1:12121", none, cross));
    CHECK_FALSE(api_request_origin_allowed("http://10.77.77.1", "10.77.77.1:12121", none, cross));
    CHECK_FALSE(api_request_origin_allowed("http://10.77.77.1:12121", "", none, cross));

    CHECK(api_request_origin_allowed("http://192.168.1.10:5173", "10.77.77.1:12121", allowed, cross));
    CHECK(cross);
    CHECK_FALSE(api_request_origin_allowed("http://192.168.1.10:5174", "10.77.77.1:12121", allowed, cross));
}

TEST_CASE("API server rejects cross-origin requests and enforces the body limit") {
    ApiConfig api_config;
    api_config.listen = std::string("127.0.0.1:18193");
    api_config.max_request_body_bytes = 1024;
    api::Cors cors;
    cors.allowed_origins = std::vector<std::string>{"http://dev.example:5173"};
    api_config.cors = cors;

    ApiServer server(api_config);
    server.post("/api/echo", [](const std::string& body) -> std::string {
        return "{\"bytes\":" + std::to_string(body.size()) + "}";
    });
    server.get("/api/ping", []() -> std::string { return "{\"ok\":true}"; });
    server.start();

    httplib::Client client("127.0.0.1", 18193);
    const std::string body = "{}";
    // curl and the router scripts send no Origin header.
    const auto plain = client.Post("/api/echo", body, "application/json");
    // The UI served by the daemon itself.
    const auto same_origin = client.Post(
        "/api/echo", httplib::Headers{{"Origin", "http://127.0.0.1:18193"}}, body,
        "application/json");
    // A page on another site posting into the LAN (CSRF).
    const auto cross_site = client.Post(
        "/api/echo", httplib::Headers{{"Origin", "http://evil.example"}}, body,
        "application/json");
    const auto cross_site_get = client.Get(
        "/api/ping", httplib::Headers{{"Origin", "http://evil.example"}});
    const auto preflight_denied = client.Options(
        "/api/echo", httplib::Headers{{"Origin", "http://evil.example"}});
    const auto allowlisted = client.Post(
        "/api/echo", httplib::Headers{{"Origin", "http://dev.example:5173"}}, body,
        "application/json");
    const auto preflight_allowed = client.Options(
        "/api/echo", httplib::Headers{{"Origin", "http://dev.example:5173"},
                                      {"Access-Control-Request-Method", "POST"}});
    const auto oversized = client.Post("/api/echo", std::string(2048, 'x'), "application/json");
    server.stop();

    REQUIRE(plain != nullptr);
    CHECK(plain->status == 200);
    CHECK(plain->body == "{\"bytes\":2}");
    CHECK(plain->get_header_value_count("Access-Control-Allow-Origin") == 0);

    REQUIRE(same_origin != nullptr);
    CHECK(same_origin->status == 200);
    CHECK(same_origin->get_header_value_count("Access-Control-Allow-Origin") == 0);

    REQUIRE(cross_site != nullptr);
    CHECK(cross_site->status == 403);
    CHECK(cross_site->body == "{\"error\":\"origin not allowed\"}");
    REQUIRE(cross_site_get != nullptr);
    CHECK(cross_site_get->status == 403);
    REQUIRE(preflight_denied != nullptr);
    CHECK(preflight_denied->status == 403);

    REQUIRE(allowlisted != nullptr);
    CHECK(allowlisted->status == 200);
    CHECK(allowlisted->get_header_value("Access-Control-Allow-Origin") == "http://dev.example:5173");
    REQUIRE(preflight_allowed != nullptr);
    CHECK(preflight_allowed->status == 204);
    CHECK(preflight_allowed->get_header_value("Access-Control-Allow-Origin") ==
          "http://dev.example:5173");
    CHECK(preflight_allowed->get_header_value("Access-Control-Allow-Methods") ==
          "GET, POST, OPTIONS");

    REQUIRE(oversized != nullptr);
    CHECK(oversized->status == 413);
}

TEST_CASE("API origin check also covers the static UI") {
    const auto root = make_temp_static_root();
    write_file(root / "index.html", "<!doctype html><title>forest-pbr</title>");

    ApiConfig api_config;
    api_config.listen = std::string("127.0.0.1:18194");

    ApiServer server(api_config);
    REQUIRE(server.register_static_root(root.string()));
    server.start();

    httplib::Client client("127.0.0.1", 18194);
    const auto module_script = client.Get(
        "/", httplib::Headers{{"Origin", "http://127.0.0.1:18194"}});
    const auto foreign = client.Get("/", httplib::Headers{{"Origin", "http://evil.example"}});
    server.stop();
    std::filesystem::remove_all(root);

    REQUIRE(module_script != nullptr);
    CHECK(module_script->status == 200);
    REQUIRE(foreign != nullptr);
    CHECK(foreign->status == 403);
}

} // namespace keen_pbr3

#endif // WITH_API
