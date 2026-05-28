#include <doctest/doctest.h>

#include "../src/metrics/traffic_counters.hpp"

#include <cstdint>
#include <map>
#include <string>
#include <vector>

using namespace keen_pbr3;

namespace {

// Real router output of `iptables -t mangle -L KeenPbrTable -v -x -n`, used as
// the authoritative parser spec and fixture. Two outbounds are marked here:
// 0x50000 (kpbrm_0, one rule per inbound interface) and 0x20000 (kpbrm_1).
const char* kFixture =
    "Chain KeenPbrTable (1 references)\n"
    "    pkts      bytes target     prot opt in     out     source               destination\n"
    "       0        0 RETURN     all  --  *      *       0.0.0.0/0            0.0.0.0/0            ctstate DNAT\n"
    "   10146  1470889 ACCEPT     all  --  *      *       0.0.0.0/0            0.0.0.0/0            mark match ! 0x0\n"
    "   36492  9250344 MARK       all  --  br0    *       0.0.0.0/0            0.0.0.0/0            match-set kpbrm_0 dst MARK xset 0x50000/0xff0000\n"
    "   36492  9250344 RETURN     all  --  br0    *       0.0.0.0/0            0.0.0.0/0            match-set kpbrm_0 dst\n"
    "       0        0 MARK       all  --  ppp0   *       0.0.0.0/0            0.0.0.0/0            match-set kpbrm_0 dst MARK xset 0x50000/0xff0000\n"
    "    4022  1536118 MARK       all  --  nwg1   *       0.0.0.0/0            0.0.0.0/0            match-set kpbrm_0 dst MARK xset 0x50000/0xff0000\n"
    "       0        0 MARK       all  --  nwg2   *       0.0.0.0/0            0.0.0.0/0            match-set kpbrm_0 dst MARK xset 0x50000/0xff0000\n"
    "  120000 80000000 MARK       all  --  br0    *       0.0.0.0/0            0.0.0.0/0            match-set kpbrm_1 dst MARK xset 0x20000/0xff0000\n";

const OutboundTraffic* find(const std::vector<OutboundTraffic>& v, uint32_t mark) {
    for (const auto& e : v) {
        if (e.fwmark == mark) {
            return &e;
        }
    }
    return nullptr;
}

const RuleTraffic* find_rule(const std::vector<RuleTraffic>& v, uint32_t index) {
    for (const auto& e : v) {
        if (e.index == index) {
            return &e;
        }
    }
    return nullptr;
}

}  // namespace

TEST_CASE("traffic_counters: sums per-mark counters across inbound interfaces") {
    // 0x50000 == 327680, 0x20000 == 131072.
    const std::map<uint32_t, std::string> mark_to_tag{
        {0x50000, "forestserver_ru"},
        {0x20000, "vpn"},
    };

    const auto result = parse_outbound_traffic(kFixture, mark_to_tag);
    REQUIRE(result.size() == 2);

    const auto* ru = find(result, 0x50000);
    REQUIRE(ru != nullptr);
    CHECK(ru->tag == "forestserver_ru");
    CHECK(ru->fwmark == 327680u);
    // 36492 + 0 + 4022 + 0 (RETURN line for kpbrm_0 is ignored).
    CHECK(ru->packets == 40514u);
    // 9250344 + 0 + 1536118 + 0. (The task brief's prose byte total of
    // 12322580 disagrees with the fixture lines; the fixture is authoritative
    // and the four 0x50000 MARK rules sum to 10786462.)
    CHECK(ru->bytes == 10786462u);

    const auto* vpn = find(result, 0x20000);
    REQUIRE(vpn != nullptr);
    CHECK(vpn->tag == "vpn");
    CHECK(vpn->fwmark == 131072u);
    CHECK(vpn->packets == 120000u);
    CHECK(vpn->bytes == 80000000u);
}

TEST_CASE("traffic_counters: result is sorted by fwmark ascending") {
    const std::map<uint32_t, std::string> mark_to_tag{
        {0x50000, "forestserver_ru"},
        {0x20000, "vpn"},
    };
    const auto result = parse_outbound_traffic(kFixture, mark_to_tag);
    REQUIRE(result.size() == 2);
    CHECK(result[0].fwmark == 0x20000u);  // 131072 sorts before 327680
    CHECK(result[1].fwmark == 0x50000u);
}

TEST_CASE("traffic_counters: known mark with no traffic reports zeroes") {
    // 0x70000 is in the config but never appears in the listing.
    const std::map<uint32_t, std::string> mark_to_tag{
        {0x50000, "forestserver_ru"},
        {0x70000, "backup"},
    };
    const auto result = parse_outbound_traffic(kFixture, mark_to_tag);
    REQUIRE(result.size() == 2);

    const auto* backup = find(result, 0x70000);
    REQUIRE(backup != nullptr);
    CHECK(backup->tag == "backup");
    CHECK(backup->packets == 0u);
    CHECK(backup->bytes == 0u);
}

TEST_CASE("traffic_counters: marks not in the map are dropped") {
    // Only ask about 0x50000; 0x20000 traffic must not leak into the result.
    const std::map<uint32_t, std::string> mark_to_tag{
        {0x50000, "forestserver_ru"},
    };
    const auto result = parse_outbound_traffic(kFixture, mark_to_tag);
    REQUIRE(result.size() == 1);
    CHECK(result[0].fwmark == 0x50000u);
    CHECK(find(result, 0x20000) == nullptr);
}

TEST_CASE("traffic_counters: empty input yields zeroed entries for known marks") {
    const std::map<uint32_t, std::string> mark_to_tag{
        {0x50000, "forestserver_ru"},
    };
    const auto result = parse_outbound_traffic("", mark_to_tag);
    REQUIRE(result.size() == 1);
    CHECK(result[0].tag == "forestserver_ru");
    CHECK(result[0].packets == 0u);
    CHECK(result[0].bytes == 0u);
}

TEST_CASE("traffic_counters: empty mark map yields empty result") {
    const std::map<uint32_t, std::string> mark_to_tag;
    const auto result = parse_outbound_traffic(kFixture, mark_to_tag);
    CHECK(result.empty());
}

TEST_CASE("traffic_counters: RETURN and ACCEPT lines are not counted") {
    // A chain with only non-MARK targets must produce zero traffic even though
    // the lines carry large packet/byte counters.
    const char* only_return =
        "Chain KeenPbrTable (1 references)\n"
        "    pkts      bytes target     prot opt in     out     source               destination\n"
        "       0        0 RETURN     all  --  *      *       0.0.0.0/0            0.0.0.0/0            ctstate DNAT\n"
        "   10146  1470889 ACCEPT     all  --  *      *       0.0.0.0/0            0.0.0.0/0            mark match ! 0x0\n"
        "   36492  9250344 RETURN     all  --  br0    *       0.0.0.0/0            0.0.0.0/0            match-set kpbrm_0 dst\n";
    const std::map<uint32_t, std::string> mark_to_tag{{0x50000, "ru"}};
    const auto result = parse_outbound_traffic(only_return, mark_to_tag);
    REQUIRE(result.size() == 1);
    CHECK(result[0].packets == 0u);
    CHECK(result[0].bytes == 0u);
}

TEST_CASE("traffic_counters: malformed lines are skipped without crashing") {
    // Garbage tokens, a truncated MARK line, and a non-numeric counter column.
    const char* malformed =
        "this is not a rule at all\n"
        "MARK xset\n"                                            // truncated target
        "   abc   def MARK all -- br0 * MARK xset 0x50000/0xff0000\n"  // bad counters
        "       MARK xset 0x50000/0xff0000\n"                    // missing columns
        "\n"
        "   100   200 MARK all -- br0 * 0 0 match-set kpbrm_0 dst MARK xset 0x50000/0xff0000\n";  // valid
    const std::map<uint32_t, std::string> mark_to_tag{{0x50000, "ru"}};
    const auto result = parse_outbound_traffic(malformed, mark_to_tag);
    REQUIRE(result.size() == 1);
    // Only the final well-formed line counts.
    CHECK(result[0].packets == 100u);
    CHECK(result[0].bytes == 200u);
}

// --- parse_rule_traffic: per-kpbrm_<N> rule totals -------------------------

TEST_CASE("rule_traffic: sums per-rule counters across inbound interfaces") {
    const auto result = parse_rule_traffic(kFixture);
    // Two rule sets appear in the fixture: kpbrm_0 and kpbrm_1.
    REQUIRE(result.size() == 2);

    const auto* rule0 = find_rule(result, 0);
    REQUIRE(rule0 != nullptr);
    CHECK(rule0->index == 0u);
    // Four MARK rules for kpbrm_0 (36492 + 0 + 4022 + 0); the RETURN companion
    // line that also matches kpbrm_0 must NOT be counted.
    CHECK(rule0->packets == 40514u);
    CHECK(rule0->bytes == 10786462u);

    const auto* rule1 = find_rule(result, 1);
    REQUIRE(rule1 != nullptr);
    CHECK(rule1->index == 1u);
    CHECK(rule1->packets == 120000u);
    CHECK(rule1->bytes == 80000000u);
}

TEST_CASE("rule_traffic: result is sorted by index ascending") {
    // A listing whose kpbrm_1 line precedes the kpbrm_0 line must still come
    // back index-sorted.
    const char* reordered =
        "Chain KeenPbrTable (1 references)\n"
        "    pkts      bytes target     prot opt in     out     source               destination\n"
        "  120000 80000000 MARK       all  --  br0    *       0.0.0.0/0            0.0.0.0/0            match-set kpbrm_1 dst MARK xset 0x20000/0xff0000\n"
        "   36492  9250344 MARK       all  --  br0    *       0.0.0.0/0            0.0.0.0/0            match-set kpbrm_0 dst MARK xset 0x50000/0xff0000\n";
    const auto result = parse_rule_traffic(reordered);
    REQUIRE(result.size() == 2);
    CHECK(result[0].index == 0u);
    CHECK(result[1].index == 1u);
}

TEST_CASE("rule_traffic: RETURN and ACCEPT lines are not counted") {
    // kpbrm_0 appears only on a RETURN line: it carries no MARK xset target, so
    // it must produce no rule entry at all.
    const char* only_return =
        "Chain KeenPbrTable (1 references)\n"
        "    pkts      bytes target     prot opt in     out     source               destination\n"
        "   10146  1470889 ACCEPT     all  --  *      *       0.0.0.0/0            0.0.0.0/0            mark match ! 0x0\n"
        "   36492  9250344 RETURN     all  --  br0    *       0.0.0.0/0            0.0.0.0/0            match-set kpbrm_0 dst\n";
    const auto result = parse_rule_traffic(only_return);
    CHECK(result.empty());
}

TEST_CASE("rule_traffic: non-kpbrm match-set clauses are ignored") {
    // A MARK rule that matches a kpbrd_<list> domain set (not a kpbrm_<N> rule
    // set) must not be miscounted as a rule.
    const char* other_set =
        "Chain KeenPbrTable (1 references)\n"
        "    pkts      bytes target     prot opt in     out     source               destination\n"
        "     500     6000 MARK       all  --  br0    *       0.0.0.0/0            0.0.0.0/0            match-set kpbrd_openai dst MARK xset 0x50000/0xff0000\n";
    const auto result = parse_rule_traffic(other_set);
    CHECK(result.empty());
}

TEST_CASE("rule_traffic: empty input yields empty result") {
    CHECK(parse_rule_traffic("").empty());
}

TEST_CASE("rule_traffic: malformed lines are skipped without crashing") {
    const char* malformed =
        "this is not a rule at all\n"
        "MARK xset\n"
        "   abc   def MARK all -- br0 * match-set kpbrm_0 dst MARK xset 0x50000/0xff0000\n"  // bad counters
        "   100   200 MARK all -- br0 * match-set kpbrm_x dst MARK xset 0x50000/0xff0000\n"   // non-numeric index
        "\n"
        "   100   200 MARK all -- br0 * match-set kpbrm_3 dst MARK xset 0x50000/0xff0000\n";  // valid
    const auto result = parse_rule_traffic(malformed);
    REQUIRE(result.size() == 1);
    CHECK(result[0].index == 3u);
    CHECK(result[0].packets == 100u);
    CHECK(result[0].bytes == 200u);
}
