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

TEST_CASE("ProbeFailureLog: first failure, changed error, every 10 minutes, recovery") {
    ProbeFailureLog log(std::chrono::minutes{10});
    using Action = ProbeFailureLog::Action;
    const auto t0 = ProbeFailureLog::Clock::time_point{} + std::chrono::hours{1};

    CHECK(log.record("auto/nwg2", true, "", t0) == Action::none);
    CHECK(log.record("auto/nwg2", false, "Timeout was reached after 5001 ms", t0) ==
          Action::log_failure);
    // The same failure (numbers aside) every 20 s stays quiet...
    CHECK(log.record("auto/nwg2", false, "Timeout was reached after 5003 ms",
                     t0 + std::chrono::seconds{20}) == Action::none);
    CHECK(log.record("auto/nwg2", false, "Timeout was reached after 5000 ms",
                     t0 + std::chrono::minutes{9}) == Action::none);
    // ...a different error is logged at once...
    CHECK(log.record("auto/nwg2", false, "interface nwg2 is down",
                     t0 + std::chrono::minutes{9} + std::chrono::seconds{20}) ==
          Action::log_failure);
    // ...and a persisting one again after 10 minutes.
    CHECK(log.record("auto/nwg2", false, "interface nwg2 is down",
                     t0 + std::chrono::minutes{15}) == Action::none);
    CHECK(log.record("auto/nwg2", false, "interface nwg2 is down",
                     t0 + std::chrono::minutes{20}) == Action::log_failure);

    // Children are tracked separately.
    CHECK(log.record("auto/ppp0", false, "HTTP 503", t0 + std::chrono::minutes{20}) ==
          Action::log_failure);

    CHECK(log.record("auto/nwg2", true, "", t0 + std::chrono::minutes{21}) == Action::log_recovery);
    CHECK(log.record("auto/nwg2", true, "", t0 + std::chrono::minutes{22}) == Action::none);
    CHECK(log.record("auto/nwg2", false, "interface nwg2 is down",
                     t0 + std::chrono::minutes{23}) == Action::log_failure);
}

TEST_CASE("normalize_probe_error: numbers do not make a new error") {
    CHECK(normalize_probe_error("Connection timed out after 5001 milliseconds") ==
          normalize_probe_error("Connection timed out after 999 milliseconds"));
    CHECK(normalize_probe_error("HTTP 503") != normalize_probe_error("Couldn't connect to server"));
}

TEST_CASE("probe_interface_unavailable: missing interface fails, a live one passes") {
    CHECK_FALSE(probe_interface_unavailable("").has_value());
    CHECK_FALSE(probe_interface_unavailable("lo").has_value());
    const auto missing = probe_interface_unavailable("kpbrnoif0");
    REQUIRE(missing.has_value());
    CHECK(*missing == "interface kpbrnoif0 does not exist");
}

TEST_CASE("probe_ip_families: a bound probe tries only the families its interface has") {
    // sbtun0 (sing-box) and nwg3 (AWG) have IPv4 and at most a link-local
    // IPv6 address.
    CHECK(probe_ip_families(true, false) == ProbeIpFamilies::ipv4_only);
    CHECK(probe_ip_families(false, true) == ProbeIpFamilies::ipv6_only);
    CHECK(probe_ip_families(true, true) == ProbeIpFamilies::any);
    CHECK(probe_ip_families(false, false) == ProbeIpFamilies::any);
}

TEST_CASE("probe_interface_ip_families: unnamed and missing interfaces are not restricted") {
    CHECK(probe_interface_ip_families("") == ProbeIpFamilies::any);
    CHECK(probe_interface_ip_families("kpbrnoif0") == ProbeIpFamilies::any);
    // lo always has 127.0.0.1; ::1 exists only where IPv6 is enabled.
    CHECK(probe_interface_ip_families("lo") != ProbeIpFamilies::ipv6_only);
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
