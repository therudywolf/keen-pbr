#include <doctest/doctest.h>

#include "../src/config/config.hpp"
#include "../src/config/list_audit.hpp"

#include <algorithm>
#include <string>
#include <vector>

using namespace keen_pbr3;

namespace {

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

bool has(const std::vector<ListAdvisory>& v, ListAdvisory::Kind kind,
         const std::string& list, const std::string& entry) {
    return std::any_of(v.begin(), v.end(), [&](const ListAdvisory& a) {
        return a.kind == kind && a.list == list && a.entry == entry;
    });
}

std::size_t count_of(const std::vector<ListAdvisory>& v,
                     ListAdvisory::Kind kind) {
    return static_cast<std::size_t>(
        std::count_if(v.begin(), v.end(),
                      [&](const ListAdvisory& a) { return a.kind == kind; }));
}

}  // namespace

// --- oversized ranges ------------------------------------------------------

TEST_CASE("list_audit: flags the cloud-sized ranges that misrouted smart home") {
    // Condensed from the real list that broke this network: a messenger list
    // carrying AWS and Google blocks. 18.128.0.0/9 is what pulled one of three
    // DNS answers for the bulbs' cloud into the tunnel.
    const auto cfg = cfg_from(R"({
        "outbounds":[{"tag":"vpn","type":"ignore"}],
        "lists":{
            "signal":{
                "domains":["signal.org"],
                "ip_cidrs":["18.128.0.0/9","142.250.0.0/15","13.248.0.0/14"]
            }
        },
        "route":{"rules":[{"list":["signal"],"outbound":"vpn"}]}
    })");

    const auto found = audit_lists(cfg);
    CHECK(count_of(found, ListAdvisory::Kind::OversizedRange) == 3);
    CHECK(has(found, ListAdvisory::Kind::OversizedRange, "signal", "18.128.0.0/9"));

    const auto it = std::find_if(found.begin(), found.end(),
                                 [](const ListAdvisory& a) {
                                     return a.entry == "18.128.0.0/9";
                                 });
    REQUIRE(it != found.end());
    CHECK(it->addresses == 8388608u);
    CHECK(it->prefix_length == 9);
}

TEST_CASE("list_audit: a service's own /24s are not flagged") {
    const auto cfg = cfg_from(R"({
        "outbounds":[{"tag":"vpn","type":"ignore"}],
        "lists":{"openai":{"ip_cidrs":["24.199.123.0/24","8.47.69.0/24"]}},
        "route":{"rules":[{"list":["openai"],"outbound":"vpn"}]}
    })");
    CHECK(audit_lists(cfg).empty());
}

TEST_CASE("list_audit: /16 sits exactly on the threshold and is not flagged") {
    // 65536 addresses == the default threshold; only strictly wider reports.
    const auto cfg = cfg_from(R"({
        "outbounds":[{"tag":"vpn","type":"ignore"}],
        "lists":{"svc":{"ip_cidrs":["10.0.0.0/16","10.1.0.0/15"]}},
        "route":{"rules":[{"list":["svc"],"outbound":"vpn"}]}
    })");
    const auto found = audit_lists(cfg);
    REQUIRE(found.size() == 1);
    CHECK(found[0].entry == "10.1.0.0/15");
}

TEST_CASE("list_audit: threshold is configurable") {
    const auto cfg = cfg_from(R"({
        "outbounds":[{"tag":"vpn","type":"ignore"}],
        "lists":{"svc":{"ip_cidrs":["10.0.0.0/24"]}},
        "route":{"rules":[{"list":["svc"],"outbound":"vpn"}]}
    })");
    CHECK(audit_lists(cfg).empty());
    CHECK(audit_lists(cfg, /*threshold=*/100).size() == 1);
}

TEST_CASE("list_audit: an unreferenced list's contents are not content-audited") {
    // It routes nothing, so its broad range misroutes nothing. The only
    // finding should be that the list is unused at all.
    const auto cfg = cfg_from(R"({
        "outbounds":[{"tag":"vpn","type":"ignore"}],
        "lists":{
            "used":{"ip_cidrs":["10.0.0.0/24"]},
            "parked":{"ip_cidrs":["3.0.0.0/9"]}
        },
        "route":{"rules":[{"list":["used"],"outbound":"vpn"}]}
    })");
    const auto found = audit_lists(cfg);
    CHECK(count_of(found, ListAdvisory::Kind::OversizedRange) == 0);
    REQUIRE(count_of(found, ListAdvisory::Kind::UnusedList) == 1);
    CHECK(found[0].list == "parked");
}

TEST_CASE("list_audit: disabled rules do not bring their lists into scope") {
    // The list is out of scope for content checks, and separately reported as
    // unused — a disabled rule routes nothing.
    const auto cfg = cfg_from(R"({
        "outbounds":[{"tag":"vpn","type":"ignore"}],
        "lists":{"big":{"ip_cidrs":["3.0.0.0/9"]}},
        "route":{"rules":[{"list":["big"],"outbound":"vpn","enabled":false}]}
    })");
    const auto found = audit_lists(cfg);
    CHECK(count_of(found, ListAdvisory::Kind::OversizedRange) == 0);
    CHECK(count_of(found, ListAdvisory::Kind::UnusedList) == 1);
}

TEST_CASE("list_audit: short IPv6 prefixes are flagged, /48 and longer are not") {
    const auto cfg = cfg_from(R"({
        "outbounds":[{"tag":"vpn","type":"ignore"}],
        "lists":{"svc":{"ip_cidrs":["2a03:2880::/32","2001:b28:f23d::/48"]}},
        "route":{"rules":[{"list":["svc"],"outbound":"vpn"}]}
    })");
    const auto found = audit_lists(cfg);
    REQUIRE(found.size() == 1);
    CHECK(found[0].entry == "2a03:2880::/32");
    // IPv6 counts overflow 64 bits, so the prefix length carries the meaning.
    CHECK(found[0].addresses == 0u);
    CHECK(found[0].prefix_length == 32);
}

TEST_CASE("list_audit: bare IPs and malformed entries are skipped, not crashed on") {
    const auto cfg = cfg_from(R"({
        "outbounds":[{"tag":"vpn","type":"ignore"}],
        "lists":{"svc":{"ip_cidrs":["1.1.1.1","8.8.8.8","not-a-cidr","10.0.0.0/","10.0.0.0/abc"]}},
        "route":{"rules":[{"list":["svc"],"outbound":"vpn"}]}
    })");
    CHECK(audit_lists(cfg).empty());
}

// --- shadowed domains ------------------------------------------------------

TEST_CASE("list_audit: flags the bare domain that hijacked Google Drive") {
    // The real case: a bare `googleapis.com` sitting in the discord list
    // captured every *.googleapis.com, including Drive's endpoint, and sent it
    // to the VPN while the drive list pointed the other way.
    const auto cfg = cfg_from(R"({
        "outbounds":[
            {"tag":"vpn","type":"ignore"},
            {"tag":"direct","type":"ignore"}
        ],
        "lists":{
            "discord":{"domains":["discord.com","googleapis.com"]},
            "drive":{"domains":["www.googleapis.com","drive.google.com"]}
        },
        "route":{"rules":[
            {"list":["discord"],"outbound":"vpn"},
            {"list":["drive"],"outbound":"direct"}
        ]}
    })");

    const auto found = audit_lists(cfg);
    REQUIRE(count_of(found, ListAdvisory::Kind::ShadowedDomain) == 1);
    const auto& a = found[0];
    CHECK(a.list == "discord");
    CHECK(a.entry == "googleapis.com");
    CHECK(a.other_list == "drive");
    CHECK(a.other_entry == "www.googleapis.com");
}

TEST_CASE("list_audit: wildcard and bare spellings shadow identically") {
    // dnsmasq strips the "*." prefix, so "*.googleapis.com" is the same
    // directive as "googleapis.com" and must be reported the same way.
    const auto cfg = cfg_from(R"({
        "outbounds":[{"tag":"vpn","type":"ignore"},{"tag":"direct","type":"ignore"}],
        "lists":{
            "a":{"domains":["*.googleapis.com"]},
            "b":{"domains":["www.googleapis.com"]}
        },
        "route":{"rules":[
            {"list":["a"],"outbound":"vpn"},
            {"list":["b"],"outbound":"direct"}
        ]}
    })");
    const auto found = audit_lists(cfg);
    REQUIRE(found.size() == 1);
    CHECK(found[0].entry == "*.googleapis.com");
}

TEST_CASE("list_audit: same outbound means the shadow changes nothing") {
    const auto cfg = cfg_from(R"({
        "outbounds":[{"tag":"vpn","type":"ignore"}],
        "lists":{
            "a":{"domains":["googleapis.com"]},
            "b":{"domains":["www.googleapis.com"]}
        },
        "route":{"rules":[
            {"list":["a"],"outbound":"vpn"},
            {"list":["b"],"outbound":"vpn"}
        ]}
    })");
    CHECK(audit_lists(cfg).empty());
}

TEST_CASE("list_audit: a partial suffix is not a parent domain") {
    // "oogle.com" must not be treated as covering "google.com" — dnsmasq
    // matches on label boundaries, not raw string suffixes.
    const auto cfg = cfg_from(R"({
        "outbounds":[{"tag":"vpn","type":"ignore"},{"tag":"direct","type":"ignore"}],
        "lists":{
            "a":{"domains":["oogle.com"]},
            "b":{"domains":["google.com"]}
        },
        "route":{"rules":[
            {"list":["a"],"outbound":"vpn"},
            {"list":["b"],"outbound":"direct"}
        ]}
    })");
    CHECK(audit_lists(cfg).empty());
}

TEST_CASE("list_audit: identical entries in two lists are left to the duplicate checker") {
    const auto cfg = cfg_from(R"({
        "outbounds":[{"tag":"vpn","type":"ignore"},{"tag":"direct","type":"ignore"}],
        "lists":{
            "a":{"domains":["example.com"]},
            "b":{"domains":["example.com"]}
        },
        "route":{"rules":[
            {"list":["a"],"outbound":"vpn"},
            {"list":["b"],"outbound":"direct"}
        ]}
    })");
    CHECK(count_of(audit_lists(cfg), ListAdvisory::Kind::ShadowedDomain) == 0);
}

TEST_CASE("list_audit: shadowing within one list is not reported") {
    // One list routes to one place; a broad entry beside a specific one there
    // is redundant, not a misroute.
    const auto cfg = cfg_from(R"({
        "outbounds":[{"tag":"vpn","type":"ignore"}],
        "lists":{"a":{"domains":["googleapis.com","www.googleapis.com"]}},
        "route":{"rules":[{"list":["a"],"outbound":"vpn"}]}
    })");
    CHECK(audit_lists(cfg).empty());
}

TEST_CASE("list_audit: case differences still shadow") {
    const auto cfg = cfg_from(R"({
        "outbounds":[{"tag":"vpn","type":"ignore"},{"tag":"direct","type":"ignore"}],
        "lists":{
            "a":{"domains":["GoogleAPIs.com"]},
            "b":{"domains":["www.googleapis.com"]}
        },
        "route":{"rules":[
            {"list":["a"],"outbound":"vpn"},
            {"list":["b"],"outbound":"direct"}
        ]}
    })");
    CHECK(count_of(audit_lists(cfg), ListAdvisory::Kind::ShadowedDomain) == 1);
}

TEST_CASE("list_audit: results are deterministically ordered") {
    const auto cfg = cfg_from(R"({
        "outbounds":[{"tag":"vpn","type":"ignore"},{"tag":"direct","type":"ignore"}],
        "lists":{
            "zeta":{"domains":["example.com"],"ip_cidrs":["3.0.0.0/9"]},
            "alpha":{"domains":["sub.example.com"],"ip_cidrs":["4.0.0.0/9"]}
        },
        "route":{"rules":[
            {"list":["zeta"],"outbound":"vpn"},
            {"list":["alpha"],"outbound":"direct"}
        ]}
    })");
    const auto a = audit_lists(cfg);
    const auto b = audit_lists(cfg);
    REQUIRE(a.size() == b.size());
    for (std::size_t i = 0; i < a.size(); ++i) {
        CHECK(a[i].list == b[i].list);
        CHECK(a[i].entry == b[i].entry);
    }
    // Oversized ranges sort before shadowed domains.
    CHECK(a.front().kind == ListAdvisory::Kind::OversizedRange);
}

TEST_CASE("list_audit: empty config yields nothing") {
    const auto cfg = cfg_from(R"({
        "outbounds":[{"tag":"vpn","type":"ignore"}],
        "route":{"rules":[]}
    })");
    CHECK(audit_lists(cfg).empty());
}

// --- unused lists ----------------------------------------------------------

TEST_CASE("list_audit: flags the curated list nobody wired up") {
    // The exact confusion this deployment hit: a carefully built google_disk
    // list sitting in the config, read as "Drive is carved out", referenced by
    // no rule and therefore routing nothing.
    const auto cfg = cfg_from(R"({
        "outbounds":[{"tag":"vpn","type":"ignore"}],
        "lists":{
            "vpn_stuff":{"domains":["example.com"]},
            "google_disk":{"domains":["drive.google.com","googledrive.com"]}
        },
        "route":{"rules":[{"list":["vpn_stuff"],"outbound":"vpn"}]}
    })");

    const auto found = audit_lists(cfg);
    REQUIRE(count_of(found, ListAdvisory::Kind::UnusedList) == 1);
    const auto it = std::find_if(found.begin(), found.end(),
                                 [](const ListAdvisory& a) {
                                     return a.kind == ListAdvisory::Kind::UnusedList;
                                 });
    REQUIRE(it != found.end());
    CHECK(it->list == "google_disk");
    CHECK(it->entry_count == 2u);
}

TEST_CASE("list_audit: a list referenced only by a disabled rule counts as unused") {
    const auto cfg = cfg_from(R"({
        "outbounds":[{"tag":"vpn","type":"ignore"}],
        "lists":{"parked":{"domains":["example.com"]}},
        "route":{"rules":[{"list":["parked"],"outbound":"vpn","enabled":false}]}
    })");
    CHECK(count_of(audit_lists(cfg), ListAdvisory::Kind::UnusedList) == 1);
}

TEST_CASE("list_audit: an unused URL-sourced list is reported despite zero inline entries") {
    // It still downloads on every refresh and still routes nothing, so the
    // intent is just as unfinished as an inline list's would be.
    const auto cfg = cfg_from(R"({
        "outbounds":[{"tag":"vpn","type":"ignore"}],
        "lists":{
            "used":{"domains":["example.com"]},
            "remote":{"url":"https://example.org/list.txt"}
        },
        "route":{"rules":[{"list":["used"],"outbound":"vpn"}]}
    })");
    const auto found = audit_lists(cfg);
    REQUIRE(count_of(found, ListAdvisory::Kind::UnusedList) == 1);
    CHECK(found[0].list == "remote");
    CHECK(found[0].entry_count == 0u);
}


