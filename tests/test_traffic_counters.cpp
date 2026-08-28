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

const SetTraffic* find_set(const std::vector<SetTraffic>& v,
                           const std::string& name) {
    for (const auto& e : v) {
        if (e.set_name == name) {
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

// --- parse_set_traffic: per-set totals -------------------------------------

TEST_CASE("set_traffic: sums per-set counters across inbound interfaces") {
    const auto result = parse_set_traffic(kFixture);
    // Two counting sets appear in the fixture: kpbrm_0 and kpbrm_1.
    REQUIRE(result.size() == 2);

    const auto* set0 = find_set(result, "kpbrm_0");
    REQUIRE(set0 != nullptr);
    // Four MARK rules for kpbrm_0 (36492 + 0 + 4022 + 0); the RETURN companion
    // line that also matches kpbrm_0 must NOT be counted.
    CHECK(set0->packets == 40514u);
    CHECK(set0->bytes == 10786462u);

    const auto* set1 = find_set(result, "kpbrm_1");
    REQUIRE(set1 != nullptr);
    CHECK(set1->packets == 120000u);
    CHECK(set1->bytes == 80000000u);
}

TEST_CASE("set_traffic: result is sorted by set name ascending") {
    const char* reordered =
        "Chain KeenPbrTable (1 references)\n"
        "    pkts      bytes target     prot opt in     out     source               destination\n"
        "  120000 80000000 MARK       all  --  br0    *       0.0.0.0/0            0.0.0.0/0            match-set kpbrm_1 dst MARK xset 0x20000/0xff0000\n"
        "   36492  9250344 MARK       all  --  br0    *       0.0.0.0/0            0.0.0.0/0            match-set kpbrm_0 dst MARK xset 0x50000/0xff0000\n";
    const auto result = parse_set_traffic(reordered);
    REQUIRE(result.size() == 2);
    CHECK(result[0].set_name == "kpbrm_0");
    CHECK(result[1].set_name == "kpbrm_1");
}

TEST_CASE("set_traffic: per-list kpbr4/kpbr4d sets are counted") {
    // A rule that didn't consolidate matches its per-list sets directly; both
    // spellings must be counted, each under its own set name.
    const char* per_list =
        "Chain KeenPbrTable (1 references)\n"
        "    pkts      bytes target     prot opt in     out     source               destination\n"
        "     500     6000 MARK       all  --  br0    *       0.0.0.0/0            0.0.0.0/0            match-set kpbr4_wiz dst MARK xset 0x20000/0xff0000\n"
        "     500     6000 RETURN     all  --  br0    *       0.0.0.0/0            0.0.0.0/0            match-set kpbr4_wiz dst\n"
        "     250     3000 MARK       all  --  ppp0   *       0.0.0.0/0            0.0.0.0/0            match-set kpbr4d_wiz dst MARK xset 0x20000/0xff0000\n";
    const auto result = parse_set_traffic(per_list);
    REQUIRE(result.size() == 2);
    const auto* stat = find_set(result, "kpbr4_wiz");
    REQUIRE(stat != nullptr);
    CHECK(stat->packets == 500u);
    const auto* dyn = find_set(result, "kpbr4d_wiz");
    REQUIRE(dyn != nullptr);
    CHECK(dyn->packets == 250u);
}

TEST_CASE("set_traffic: DROP (blackhole) lines are counted") {
    const char* drop_rule =
        "Chain KeenPbrTable (1 references)\n"
        "    pkts      bytes target     prot opt in     out     source               destination\n"
        "     700     8400 DROP       all  --  br0    *       0.0.0.0/0            0.0.0.0/0            match-set kpbr4_block dst\n";
    const auto result = parse_set_traffic(drop_rule);
    REQUIRE(result.size() == 1);
    CHECK(result[0].set_name == "kpbr4_block");
    CHECK(result[0].packets == 700u);
    CHECK(result[0].bytes == 8400u);
}

TEST_CASE("set_traffic: RETURN and ACCEPT lines are not counted") {
    const char* only_return =
        "Chain KeenPbrTable (1 references)\n"
        "    pkts      bytes target     prot opt in     out     source               destination\n"
        "   10146  1470889 ACCEPT     all  --  *      *       0.0.0.0/0            0.0.0.0/0            mark match ! 0x0\n"
        "   36492  9250344 RETURN     all  --  br0    *       0.0.0.0/0            0.0.0.0/0            match-set kpbrm_0 dst\n";
    const auto result = parse_set_traffic(only_return);
    CHECK(result.empty());
}

TEST_CASE("set_traffic: non-kpbr match-set clauses are ignored") {
    // A MARK rule matching a foreign (e.g. NDM) set must not be counted.
    const char* other_set =
        "Chain KeenPbrTable (1 references)\n"
        "    pkts      bytes target     prot opt in     out     source               destination\n"
        "     500     6000 MARK       all  --  br0    *       0.0.0.0/0            0.0.0.0/0            match-set _NDM_SET dst MARK xset 0x50000/0xff0000\n";
    const auto result = parse_set_traffic(other_set);
    CHECK(result.empty());
}

TEST_CASE("set_traffic: empty input yields empty result") {
    CHECK(parse_set_traffic("").empty());
}

TEST_CASE("set_traffic: malformed lines are skipped without crashing") {
    const char* malformed =
        "this is not a rule at all\n"
        "MARK xset\n"
        // Non-numeric counters: skipped.
        "   abc   def MARK all -- br0 * match-set kpbrm_0 dst MARK xset 0x50000/0xff0000\n"
        "\n"
        // The only well-formed line.
        "   100   200 MARK all -- br0 * match-set kpbrm_3 dst MARK xset 0x50000/0xff0000\n";
    const auto result = parse_set_traffic(malformed);
    REQUIRE(result.size() == 1);
    CHECK(result[0].set_name == "kpbrm_3");
    CHECK(result[0].packets == 100u);
    CHECK(result[0].bytes == 200u);
}
