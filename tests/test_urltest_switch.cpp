#include <doctest/doctest.h>

#include "../src/routing/urltest_routes.hpp"
#include "../src/routing/urltest_switch.hpp"

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
