#include <doctest/doctest.h>

#include "../src/routing/urltest_routes.hpp"
#include "../src/routing/urltest_switch.hpp"
#include "../src/routing/urltest_stall.hpp"

#include <chrono>
#include <string>
#include <sys/socket.h>
#include <vector>

using namespace keen_pbr3;

TEST_CASE("classify_urltest_switch: first selection, failed path, healthy change") {
    CHECK(classify_urltest_switch(false, false) == UrltestSwitchReason::initial);
    CHECK(classify_urltest_switch(false, true) == UrltestSwitchReason::initial);
    CHECK(classify_urltest_switch(true, false) == UrltestSwitchReason::selected_path_unhealthy);
    CHECK(classify_urltest_switch(true, true) == UrltestSwitchReason::healthy_policy_change);
}

TEST_CASE("urltest_switch_reason_name: stable log names") {
    CHECK(std::string(urltest_switch_reason_name(UrltestSwitchReason::initial)) == "initial");
    CHECK(std::string(urltest_switch_reason_name(UrltestSwitchReason::selected_path_unhealthy)) ==
          "selected-path-unhealthy");
    CHECK(std::string(urltest_switch_reason_name(UrltestSwitchReason::healthy_policy_change)) ==
          "healthy-policy-change");
}

TEST_CASE("urltest_flush_retry_delay: bounded backoff") {
    CHECK(kMaxUrltestFlushRetries == 3);
    CHECK(urltest_flush_retry_delay(0) == std::chrono::seconds{5});
    CHECK(urltest_flush_retry_delay(1) == std::chrono::seconds{15});
    CHECK(urltest_flush_retry_delay(2) == std::chrono::seconds{45});
    // Never grows past the last retry's delay.
    CHECK(urltest_flush_retry_delay(10) == std::chrono::seconds{135});
}

namespace {

DumpedRoute default_route(int family, const std::string& iface, uint32_t metric,
                          std::optional<std::string> gateway = std::nullopt) {
    DumpedRoute route;
    route.destination = "default";
    route.table = 152;
    route.family = family;
    route.interface = iface;
    route.metric = metric;
    route.gateway = std::move(gateway);
    return route;
}

Outbound iface_outbound(const std::string& tag, const std::string& iface) {
    Outbound outbound;
    outbound.tag = tag;
    outbound.type = OutboundType::INTERFACE;
    outbound.interface = iface;
    return outbound;
}

} // namespace

TEST_CASE("infer_urltest_selection_from_routes: dual-stack default routes of one child") {
    Outbound urltest;
    urltest.tag = "forestserver_auto";
    urltest.type = OutboundType::URLTEST;
    OutboundGroup primary;
    primary.outbounds = {"awg3"};
    OutboundGroup backup;
    backup.outbounds = {"rostelecom"};
    urltest.outbound_groups = std::vector<OutboundGroup>{primary, backup};
    Outbound rostelecom = iface_outbound("rostelecom", "ppp0");
    rostelecom.gateway = "100.64.0.1";
    const std::vector<Outbound> outbounds{iface_outbound("awg3", "nwg3"), rostelecom, urltest};

    // Selected child at metric 0 for both families, fallbacks at 1..N.
    const std::vector<DumpedRoute> selected_awg3{
        default_route(AF_INET, "nwg3", 0),
        default_route(AF_INET6, "nwg3", 0),
        default_route(AF_INET, "nwg3", 1),
        default_route(AF_INET, "ppp0", 2, std::string("100.64.0.1")),
    };
    CHECK(infer_urltest_selection_from_routes(outbounds, urltest, selected_awg3) ==
          std::optional<std::string>{"awg3"});

    const std::vector<DumpedRoute> selected_wan{
        default_route(AF_INET, "ppp0", 0, std::string("100.64.0.1")),
        default_route(AF_INET, "nwg3", 1),
    };
    CHECK(infer_urltest_selection_from_routes(outbounds, urltest, selected_wan) ==
          std::optional<std::string>{"rostelecom"});

    // Different children at metric 0, a foreign route, or no route: unknown.
    const std::vector<DumpedRoute> ambiguous{
        default_route(AF_INET, "nwg3", 0),
        default_route(AF_INET6, "ppp0", 0),
    };
    CHECK_FALSE(infer_urltest_selection_from_routes(outbounds, urltest, ambiguous).has_value());
    CHECK_FALSE(infer_urltest_selection_from_routes(
                    outbounds, urltest, {default_route(AF_INET, "eth9", 0)})
                    .has_value());
    CHECK_FALSE(infer_urltest_selection_from_routes(outbounds, urltest, {}).has_value());
    // The configured gateway must match.
    CHECK_FALSE(infer_urltest_selection_from_routes(
                    outbounds, urltest,
                    {default_route(AF_INET, "ppp0", 0, std::string("100.64.0.9"))})
                    .has_value());
}

namespace {

using StallClock = UrltestStallGuard::Clock;
using StallVerdict = UrltestStallGuard::Verdict;

StallClock::time_point stall_at(int seconds) {
    return StallClock::time_point{} + std::chrono::hours{1} + std::chrono::seconds{seconds};
}

} // namespace

TEST_CASE("urltest stall window and hold limit follow the probe interval, within bounds") {
    CHECK(urltest_stall_window(std::chrono::seconds{20}) == std::chrono::seconds{60});
    CHECK(urltest_stall_window(std::chrono::seconds{180}) == std::chrono::seconds{540});
    CHECK(urltest_stall_window(std::chrono::seconds{3600}) == std::chrono::seconds{900});
    CHECK(urltest_stall_max_hold(std::chrono::seconds{20}) == std::chrono::seconds{180});
    CHECK(urltest_stall_max_hold(std::chrono::seconds{180}) == std::chrono::seconds{360});
    CHECK(urltest_stall_max_hold(std::chrono::seconds{3600}) == std::chrono::seconds{600});

    const UrltestStallGuard defaults{};
    CHECK(defaults.window() == std::chrono::seconds{60});
    CHECK(defaults.max_hold() == std::chrono::seconds{180});
    CHECK_FALSE(defaults.holding());
}

TEST_CASE("UrltestStallGuard: a failure of the applied member alone switches at once") {
    UrltestStallGuard guard(std::chrono::seconds{60}, std::chrono::seconds{180});
    guard.record("awg", true, stall_at(0));
    guard.record("xeovo", true, stall_at(0));
    guard.record("https", true, stall_at(0));
    guard.record("awg", false, stall_at(20));
    guard.record("xeovo", true, stall_at(20));
    guard.record("https", true, stall_at(20));

    CHECK(guard.on_unhealthy_switch("awg", false, stall_at(20)) == StallVerdict::switch_now);
    CHECK_FALSE(guard.holding());
    CHECK(guard.correlated_with().empty());
}

TEST_CASE("UrltestStallGuard: a member that just failed too makes it a stall, and the applied one is held") {
    UrltestStallGuard guard(std::chrono::seconds{60}, std::chrono::seconds{180});
    // 2026-11-04: the reserve flapped, then the primary timed out.
    guard.record("awg", true, stall_at(0));
    guard.record("xeovo", true, stall_at(0));
    guard.record("xeovo", false, stall_at(20));
    guard.record("awg", true, stall_at(20));
    guard.record("xeovo", true, stall_at(40));
    guard.record("awg", false, stall_at(60));

    CHECK(guard.on_unhealthy_switch("awg", false, stall_at(60)) == StallVerdict::hold_started);
    CHECK(guard.holding());
    CHECK(guard.correlated_with() == "xeovo");

    // The next round of the stall keeps holding...
    guard.record("xeovo", false, stall_at(100));
    guard.record("awg", false, stall_at(100));
    CHECK(guard.on_unhealthy_switch("awg", false, stall_at(100)) == StallVerdict::hold_continued);

    // ...and the applied member working again ends the hold without a switch.
    CHECK(guard.end_hold());
    CHECK_FALSE(guard.holding());
    CHECK_FALSE(guard.end_hold());
}

TEST_CASE("UrltestStallGuard: a stall that outlasts the hold limit switches after all") {
    UrltestStallGuard guard(std::chrono::seconds{60}, std::chrono::seconds{180});
    guard.record("xeovo", true, stall_at(0));
    guard.record("xeovo", false, stall_at(10));
    guard.record("awg", false, stall_at(20));
    CHECK(guard.on_unhealthy_switch("awg", false, stall_at(20)) == StallVerdict::hold_started);

    // The reserve keeps flapping and the primary keeps failing.
    for (int t = 40; t < 200; t += 20) {
        guard.record("xeovo", true, stall_at(t - 5));
        guard.record("xeovo", false, stall_at(t));
        guard.record("awg", false, stall_at(t));
        CHECK(guard.on_unhealthy_switch("awg", false, stall_at(t)) == StallVerdict::hold_continued);
    }
    guard.record("xeovo", true, stall_at(195));
    guard.record("xeovo", false, stall_at(200));
    guard.record("awg", false, stall_at(200));
    CHECK(guard.on_unhealthy_switch("awg", false, stall_at(200)) == StallVerdict::hold_expired);
    CHECK_FALSE(guard.holding());
}

TEST_CASE("UrltestStallGuard: a reserve that has been dead for a while does not hold a failing primary") {
    UrltestStallGuard guard(std::chrono::seconds{60}, std::chrono::seconds{180});
    // The reserve last worked ten minutes ago and has failed every round since.
    guard.record("xeovo", true, stall_at(0));
    for (int t = 20; t <= 600; t += 20) {
        guard.record("xeovo", false, stall_at(t));
        guard.record("awg", true, stall_at(t));
    }
    guard.record("xeovo", false, stall_at(620));
    guard.record("awg", false, stall_at(620));

    CHECK(guard.on_unhealthy_switch("awg", false, stall_at(620)) == StallVerdict::switch_now);
    CHECK_FALSE(guard.holding());
}

TEST_CASE("UrltestStallGuard: an applied member whose device is gone is never held") {
    UrltestStallGuard guard(std::chrono::seconds{60}, std::chrono::seconds{180});
    guard.record("xeovo", true, stall_at(0));
    guard.record("xeovo", false, stall_at(10));
    guard.record("awg", false, stall_at(20));

    CHECK(guard.on_unhealthy_switch("awg", true, stall_at(20)) == StallVerdict::switch_now);
    CHECK_FALSE(guard.holding());

    // Not even in the middle of a hold.
    CHECK(guard.on_unhealthy_switch("awg", false, stall_at(20)) == StallVerdict::hold_started);
    CHECK(guard.on_unhealthy_switch("awg", true, stall_at(40)) == StallVerdict::switch_now);
    CHECK_FALSE(guard.holding());
}

TEST_CASE("UrltestStallGuard: the applied member's own flapping is not a stall") {
    UrltestStallGuard guard(std::chrono::seconds{60}, std::chrono::seconds{180});
    guard.record("awg", true, stall_at(0));
    guard.record("awg", false, stall_at(10));
    guard.record("awg", true, stall_at(20));
    guard.record("xeovo", true, stall_at(20));
    guard.record("awg", false, stall_at(40));

    CHECK(guard.on_unhealthy_switch("awg", false, stall_at(40)) == StallVerdict::switch_now);
}
