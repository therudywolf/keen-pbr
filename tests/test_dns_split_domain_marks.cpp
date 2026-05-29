#include <doctest/doctest.h>

#include "../src/cache/cache_manager.hpp"
#include "../src/config/config.hpp"
#include "../src/routing/dns_split_marks.hpp"
#include "../src/routing/sni_classifier.hpp"

#include <filesystem>
#include <map>
#include <string>

using namespace keen_pbr3;

namespace {

// A cache dir with no cache files: lists resolve from their inline `domains`
// only, which is exactly what we want to exercise the mark-mapping logic.
CacheManager empty_cache() {
    return CacheManager(std::filesystem::temp_directory_path());
}

std::map<std::string, uint32_t> marks_for(const std::string& json) {
    Config cfg = parse_config(json);
    const auto outbound_marks = allocate_outbound_marks(
        cfg.fwmark.value_or(FwmarkConfig{}),
        cfg.outbounds.value_or(std::vector<Outbound>{}));
    CacheManager cache = empty_cache();
    return build_dns_split_domain_marks(cfg, outbound_marks, {}, cache);
}

}  // namespace

TEST_CASE("dns_split domain marks: the split case — drive to WAN, youtube to VPN") {
    // Two outbounds get sequential fwmarks; drive.google.com and youtube.com
    // each map to their rule's outbound mark even though they share Google edges.
    const std::string json = R"({
        "outbounds":[
            {"tag":"wan","type":"interface","interface":"ppp0"},
            {"tag":"vpn","type":"interface","interface":"nwg2"}
        ],
        "lists":{
            "drive":{"domains":["drive.google.com"]},
            "tube":{"domains":["youtube.com","*.googlevideo.com"]}
        },
        "route":{
            "rules":[
                {"list":["drive"],"outbound":"wan"},
                {"list":["tube"],"outbound":"vpn"}
            ]
        }
    })";

    Config cfg = parse_config(json);
    const auto outbound_marks = allocate_outbound_marks(
        cfg.fwmark.value_or(FwmarkConfig{}),
        cfg.outbounds.value_or(std::vector<Outbound>{}));
    const uint32_t wan_mark = outbound_marks.at("wan");
    const uint32_t vpn_mark = outbound_marks.at("vpn");
    REQUIRE(wan_mark != 0);
    REQUIRE(vpn_mark != 0);
    REQUIRE(wan_mark != vpn_mark);

    CacheManager cache = empty_cache();
    const auto domain_marks = build_dns_split_domain_marks(cfg, outbound_marks, {}, cache);

    CHECK(domain_marks.at("drive.google.com") == wan_mark);
    CHECK(domain_marks.at("youtube.com") == vpn_mark);
    // Wildcard prefix is stripped to a bare domain.
    CHECK(domain_marks.at("googlevideo.com") == vpn_mark);

    // And fed through a classifier it behaves as the split intends.
    SniClassifier classifier(domain_marks);
    CHECK(classifier.classify("docs.drive.google.com") == wan_mark);
    CHECK(classifier.classify("rr3---sn-abc.googlevideo.com") == vpn_mark);
    CHECK(classifier.classify("www.youtube.com") == vpn_mark);
}

TEST_CASE("dns_split domain marks: only marking rules contribute (drop/pass/ignore excluded)") {
    const auto m = marks_for(R"({
        "outbounds":[
            {"tag":"vpn","type":"interface","interface":"nwg2"},
            {"tag":"block","type":"blackhole"},
            {"tag":"direct","type":"ignore"}
        ],
        "lists":{
            "good":{"domains":["youtube.com"]},
            "bad":{"domains":["ads.example.com"]},
            "plain":{"domains":["intranet.local"]}
        },
        "route":{
            "rules":[
                {"list":["good"],"outbound":"vpn"},
                {"list":["bad"],"outbound":"block"},
                {"list":["plain"],"outbound":"direct"}
            ]
        }
    })");

    CHECK(m.count("youtube.com") == 1);       // marking rule -> present
    CHECK(m.count("ads.example.com") == 0);   // blackhole (drop) -> excluded
    CHECK(m.count("intranet.local") == 0);    // ignore (pass) -> excluded
}

TEST_CASE("dns_split domain marks: IP/CIDR list entries are ignored (they route by ipset)") {
    const auto m = marks_for(R"({
        "outbounds":[
            {"tag":"vpn","type":"interface","interface":"nwg2"}
        ],
        "lists":{
            "mixed":{"domains":["youtube.com"],"ip_cidrs":["1.2.3.0/24","8.8.8.8"]}
        },
        "route":{
            "rules":[
                {"list":["mixed"],"outbound":"vpn"}
            ]
        }
    })");

    CHECK(m.count("youtube.com") == 1);
    // No IP/CIDR keys leak into the domain map.
    CHECK(m.count("1.2.3.0/24") == 0);
    CHECK(m.count("8.8.8.8") == 0);
    CHECK(m.size() == 1);
}

TEST_CASE("dns_split domain marks: a later rule overrides an earlier one for the same domain") {
    Config cfg = parse_config(R"({
        "outbounds":[
            {"tag":"wan","type":"interface","interface":"ppp0"},
            {"tag":"vpn","type":"interface","interface":"nwg2"}
        ],
        "lists":{
            "a":{"domains":["dup.example.com"]},
            "b":{"domains":["dup.example.com"]}
        },
        "route":{
            "rules":[
                {"list":["a"],"outbound":"wan"},
                {"list":["b"],"outbound":"vpn"}
            ]
        }
    })");
    const auto outbound_marks = allocate_outbound_marks(
        cfg.fwmark.value_or(FwmarkConfig{}),
        cfg.outbounds.value_or(std::vector<Outbound>{}));
    CacheManager cache = empty_cache();
    const auto m = build_dns_split_domain_marks(cfg, outbound_marks, {}, cache);

    CHECK(m.at("dup.example.com") == outbound_marks.at("vpn"));  // last rule wins
}

TEST_CASE("dns_split domain marks: empty when no lists carry domains") {
    const auto m = marks_for(R"({
        "outbounds":[
            {"tag":"vpn","type":"interface","interface":"nwg2"}
        ],
        "lists":{
            "ips":{"ip_cidrs":["1.2.3.0/24"]}
        },
        "route":{
            "rules":[
                {"list":["ips"],"outbound":"vpn"}
            ]
        }
    })");
    CHECK(m.empty());
}
