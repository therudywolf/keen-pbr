#include <doctest/doctest.h>

#include "../src/config/config.hpp"
#include "../src/config/routing_state.hpp"

#include <algorithm>
#include <string>
#include <vector>

using namespace keen_pbr3;

namespace {

// Fill in the DNS block the validator insists on, so each case can state only
// the lists/rules it actually cares about.
Config cfg_from(const char* json) {
    Config cfg = parse_config(json);
    if (!cfg.dns.has_value()) {
        cfg.dns = DnsConfig{};
    }
    if (!cfg.dns->servers.has_value()) {
        DnsServer fallback_server;
        fallback_server.tag = "default_dns";
        fallback_server.address = "127.0.0.1";
        cfg.dns->servers = std::vector<DnsServer>{fallback_server};
    }
    if (!cfg.dns->fallback.has_value()) {
        cfg.dns->fallback = std::vector<std::string>{"default_dns"};
    }
    if (!cfg.dns->system_resolver.has_value()) {
        api::SystemResolver resolver;
        resolver.address = "127.0.0.1";
        cfg.dns->system_resolver = resolver;
    }
    validate_config(cfg);
    return cfg;
}

bool has_set(const std::vector<std::string>& v, const std::string& name) {
    return std::find(v.begin(), v.end(), name) != v.end();
}

// A list whose sets appear at all (any of the four spellings).
bool mentions_list(const std::vector<std::string>& v, const std::string& list) {
    return has_set(v, "kpbr4_" + list) || has_set(v, "kpbr4d_" + list) ||
           has_set(v, "kpbr6_" + list) || has_set(v, "kpbr6d_" + list);
}

constexpr const char* kBase = R"({
    "outbounds":[
        {"tag":"vpn","type":"ignore"},
        {"tag":"direct","type":"ignore"}
    ],
    "lists":{
        "youtube":{"domains":["youtube.com"]},
        "iot":{"ip_cidrs":["3.0.0.0/9"]}
    },
    "route":{
        "rules":[
            {"list":["youtube"],"outbound":"vpn"},
            {"list":["iot"],"outbound":"direct"}
        ]
    }
})";

}  // namespace

TEST_CASE("changed_kpbr_set_names: identical configs report no change") {
    // The whole point of scoping: an apply that changes nothing routing-
    // relevant must not disconnect a single flow.
    const auto before = cfg_from(kBase);
    const auto after = cfg_from(kBase);
    CHECK(changed_kpbr_set_names(before, after).empty());
}

TEST_CASE("changed_kpbr_set_names: editing one list scopes to that list only") {
    const auto before = cfg_from(kBase);
    const auto after = cfg_from(R"({
        "outbounds":[
            {"tag":"vpn","type":"ignore"},
            {"tag":"direct","type":"ignore"}
        ],
        "lists":{
            "youtube":{"domains":["youtube.com","youtu.be"]},
            "iot":{"ip_cidrs":["3.0.0.0/9"]}
        },
        "route":{
            "rules":[
                {"list":["youtube"],"outbound":"vpn"},
                {"list":["iot"],"outbound":"direct"}
            ]
        }
    })");

    const auto changed = changed_kpbr_set_names(before, after);
    CHECK(mentions_list(changed, "youtube"));
    // The IoT list is untouched — its MQTT keepalives must survive the edit.
    CHECK_FALSE(mentions_list(changed, "iot"));
}

TEST_CASE("changed_kpbr_set_names: all four set spellings are emitted") {
    const auto before = cfg_from(kBase);
    const auto after = cfg_from(R"({
        "outbounds":[{"tag":"vpn","type":"ignore"},{"tag":"direct","type":"ignore"}],
        "lists":{
            "youtube":{"domains":["youtube.com","youtu.be"]},
            "iot":{"ip_cidrs":["3.0.0.0/9"]}
        },
        "route":{"rules":[
            {"list":["youtube"],"outbound":"vpn"},
            {"list":["iot"],"outbound":"direct"}
        ]}
    })");

    const auto changed = changed_kpbr_set_names(before, after);
    CHECK(has_set(changed, "kpbr4_youtube"));
    CHECK(has_set(changed, "kpbr6_youtube"));
    CHECK(has_set(changed, "kpbr4d_youtube"));
    CHECK(has_set(changed, "kpbr6d_youtube"));
}

TEST_CASE("changed_kpbr_set_names: rerouting a rule flushes its lists") {
    // List contents are identical; only the outbound moved. Those flows are
    // exactly the ones holding a stale fwmark, so they must be flushed.
    const auto before = cfg_from(kBase);
    const auto after = cfg_from(R"({
        "outbounds":[{"tag":"vpn","type":"ignore"},{"tag":"direct","type":"ignore"}],
        "lists":{
            "youtube":{"domains":["youtube.com"]},
            "iot":{"ip_cidrs":["3.0.0.0/9"]}
        },
        "route":{"rules":[
            {"list":["youtube"],"outbound":"direct"},
            {"list":["iot"],"outbound":"direct"}
        ]}
    })");

    const auto changed = changed_kpbr_set_names(before, after);
    CHECK(mentions_list(changed, "youtube"));
    CHECK_FALSE(mentions_list(changed, "iot"));
}

TEST_CASE("changed_kpbr_set_names: disabling a rule flushes its lists") {
    const auto before = cfg_from(kBase);
    const auto after = cfg_from(R"({
        "outbounds":[{"tag":"vpn","type":"ignore"},{"tag":"direct","type":"ignore"}],
        "lists":{
            "youtube":{"domains":["youtube.com"]},
            "iot":{"ip_cidrs":["3.0.0.0/9"]}
        },
        "route":{"rules":[
            {"list":["youtube"],"outbound":"vpn","enabled":false},
            {"list":["iot"],"outbound":"direct"}
        ]}
    })");

    const auto changed = changed_kpbr_set_names(before, after);
    CHECK(mentions_list(changed, "youtube"));
    CHECK_FALSE(mentions_list(changed, "iot"));
}

TEST_CASE("changed_kpbr_set_names: removing a list still flushes it") {
    // Its sets may be gone, but conntrack entries pinned to those destinations
    // are still live and still carry the old mark.
    const auto before = cfg_from(kBase);
    const auto after = cfg_from(R"({
        "outbounds":[{"tag":"vpn","type":"ignore"},{"tag":"direct","type":"ignore"}],
        "lists":{
            "iot":{"ip_cidrs":["3.0.0.0/9"]}
        },
        "route":{"rules":[
            {"list":["iot"],"outbound":"direct"}
        ]}
    })");

    const auto changed = changed_kpbr_set_names(before, after);
    CHECK(mentions_list(changed, "youtube"));
    CHECK_FALSE(mentions_list(changed, "iot"));
}

TEST_CASE("changed_kpbr_set_names: changing a selector flushes the rule's lists") {
    const auto before = cfg_from(kBase);
    const auto after = cfg_from(R"({
        "outbounds":[{"tag":"vpn","type":"ignore"},{"tag":"direct","type":"ignore"}],
        "lists":{
            "youtube":{"domains":["youtube.com"]},
            "iot":{"ip_cidrs":["3.0.0.0/9"]}
        },
        "route":{"rules":[
            {"list":["youtube"],"outbound":"vpn","src_addr":"10.77.77.0/24"},
            {"list":["iot"],"outbound":"direct"}
        ]}
    })");

    const auto changed = changed_kpbr_set_names(before, after);
    CHECK(mentions_list(changed, "youtube"));
    CHECK_FALSE(mentions_list(changed, "iot"));
}

TEST_CASE("kpbr_set_names_for_outbound: returns only that outbound's lists") {
    const auto cfg = cfg_from(kBase);
    const auto vpn = kpbr_set_names_for_outbound(cfg, "vpn");
    CHECK(mentions_list(vpn, "youtube"));
    CHECK_FALSE(mentions_list(vpn, "iot"));

    const auto direct = kpbr_set_names_for_outbound(cfg, "direct");
    CHECK(mentions_list(direct, "iot"));
    CHECK_FALSE(mentions_list(direct, "youtube"));
}

TEST_CASE("kpbr_set_names_for_outbound: unknown tag yields nothing") {
    const auto cfg = cfg_from(kBase);
    CHECK(kpbr_set_names_for_outbound(cfg, "nope").empty());
}

TEST_CASE("kpbr_set_names_for_outbound: disabled rules are excluded") {
    const auto cfg = cfg_from(R"({
        "outbounds":[{"tag":"vpn","type":"ignore"}],
        "lists":{"youtube":{"domains":["youtube.com"]}},
        "route":{"rules":[
            {"list":["youtube"],"outbound":"vpn","enabled":false}
        ]}
    })");
    CHECK(kpbr_set_names_for_outbound(cfg, "vpn").empty());
}
