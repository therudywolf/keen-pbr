#include <doctest/doctest.h>

#include "../src/health/url_tester.hpp"
#include "../src/routing/urltest_probe.hpp"

#include <chrono>
#include <curl/curl.h>
#include <string>
#include <vector>

using namespace keen_pbr3;

namespace {

Outbound interface_outbound(const std::string& tag, const std::string& iface) {
    Outbound outbound;
    outbound.tag = tag;
    outbound.type = OutboundType::INTERFACE;
    outbound.interface = iface;
    return outbound;
}

Outbound table_outbound(const std::string& tag, int64_t table) {
    Outbound outbound;
    outbound.tag = tag;
    outbound.type = OutboundType::TABLE;
    outbound.table = table;
    return outbound;
}

struct CurlGlobalGuard {
    CurlGlobalGuard() { curl_global_init(CURL_GLOBAL_DEFAULT); }
    ~CurlGlobalGuard() { curl_global_cleanup(); }
};

} // namespace

TEST_CASE("urltest_probe_interfaces: interface members are bound, table members are not") {
    Outbound urltest;
    urltest.tag = "forestserver_auto";
    urltest.type = OutboundType::URLTEST;
    OutboundGroup first;
    first.outbounds = {"forestserver_ru_awg3_1", "wan"};
    OutboundGroup second;
    second.outbounds = {"rostelecom", "missing"};
    urltest.outbound_groups = std::vector<OutboundGroup>{first, second};

    const std::vector<Outbound> outbounds{
        interface_outbound("forestserver_ru_awg3_1", "nwg3"),
        table_outbound("wan", 254),
        interface_outbound("rostelecom", "ppp0"),
        urltest,
    };

    const auto interfaces = urltest_probe_interfaces(urltest, outbounds);
    CHECK(interfaces.size() == 2);
    CHECK(interfaces.at("forestserver_ru_awg3_1") == "nwg3");
    CHECK(interfaces.at("rostelecom") == "ppp0");
    CHECK(interfaces.count("wan") == 0);
    CHECK(interfaces.count("missing") == 0);
}

TEST_CASE("probe_interface_unavailable: missing interface fails, a live one passes") {
    CHECK_FALSE(probe_interface_unavailable("").has_value());
    CHECK_FALSE(probe_interface_unavailable("lo").has_value());
    const auto missing = probe_interface_unavailable("kpbrnoif0");
    REQUIRE(missing.has_value());
    CHECK(*missing == "interface kpbrnoif0 does not exist");
}

TEST_CASE("URLTester: a probe bound to a missing interface fails on the bind, without retries") {
    CurlGlobalGuard curl_guard;
    URLTester tester;
    RetryConfig retry;
    retry.attempts = 3;
    retry.interval_ms = 2000;

    const auto started = std::chrono::steady_clock::now();
    const auto result = tester.test("http://127.0.0.1:9/generate_204", 0, 1000, retry, "kpbrnoif0");
    const auto elapsed = std::chrono::steady_clock::now() - started;

    CHECK_FALSE(result.success);
    CHECK(result.error.find("cannot bind probe to kpbrnoif0") == 0);
    // No retry interval was slept: a missing device does not come back
    // within one round.
    CHECK(elapsed < std::chrono::milliseconds{1500});
}

TEST_CASE("URLTester: binding to an existing interface reaches the connect step") {
    CurlGlobalGuard curl_guard;
    URLTester tester;
    RetryConfig retry;
    retry.attempts = 1;

    // Port 9 (discard) is closed in the test container: the connect fails,
    // but only after the socket was bound to lo.
    const auto result = tester.test("http://127.0.0.1:9/generate_204", 0, 1000, retry, "lo");
    CHECK_FALSE(result.success);
    CHECK(result.error.find("cannot bind probe") == std::string::npos);
}
