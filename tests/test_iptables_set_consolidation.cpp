#include <doctest/doctest.h>

#include "../src/firewall/iptables_set_consolidation.hpp"

#include <string>
#include <vector>

using namespace keen_pbr3;

namespace {

ConsolidatableRule mark_unit(const std::string& set_name, bool ipv6,
                             uint32_t fwmark) {
  ConsolidatableRule cr;
  cr.ipv6 = ipv6;
  cr.action = ConsolidatableRule::Action::Mark;
  cr.fwmark = fwmark;
  if (!set_name.empty()) {
    cr.criteria.dst_set_name = set_name;
  }
  return cr;
}

ConsolidatableRule drop_unit(const std::string& set_name, bool ipv6) {
  ConsolidatableRule cr;
  cr.ipv6 = ipv6;
  cr.action = ConsolidatableRule::Action::Drop;
  if (!set_name.empty()) {
    cr.criteria.dst_set_name = set_name;
  }
  return cr;
}

} // namespace

// =============================================================================
// Single-member groups: no list:set is synthesized.
// =============================================================================

TEST_CASE("consolidate: a lone per-list set stays a direct rule") {
  const auto out = consolidate_iptables_rules({mark_unit("kpbr4_a", false, 0x100)});
  REQUIRE(out.size() == 1);
  CHECK_FALSE(out[0].is_combined);
  CHECK(out[0].criteria.dst_set_name.value_or("") == "kpbr4_a");
  CHECK(out[0].member_sets.empty());
  CHECK(out[0].fwmark == 0x100u);
}

TEST_CASE("consolidate: two sets with different outbounds are not combined") {
  const auto out = consolidate_iptables_rules({
      mark_unit("kpbr4_a", false, 0x100),
      mark_unit("kpbr4_b", false, 0x200),
  });
  REQUIRE(out.size() == 2);
  CHECK_FALSE(out[0].is_combined);
  CHECK(out[0].criteria.dst_set_name.value_or("") == "kpbr4_a");
  CHECK_FALSE(out[1].is_combined);
  CHECK(out[1].criteria.dst_set_name.value_or("") == "kpbr4_b");
}

// =============================================================================
// Multi-member groups: a list:set is synthesized.
// =============================================================================

TEST_CASE("consolidate: two sets, same outbound, collapse into one list:set") {
  const auto out = consolidate_iptables_rules({
      mark_unit("kpbr4_a", false, 0x100),
      mark_unit("kpbr4_b", false, 0x100),
  });
  REQUIRE(out.size() == 1);
  CHECK(out[0].is_combined);
  CHECK(out[0].criteria.dst_set_name.value_or("") == "kpbrm_0");
  CHECK(out[0].member_sets == std::vector<std::string>({"kpbr4_a", "kpbr4_b"}));
  CHECK(out[0].fwmark == 0x100u);
}

TEST_CASE("consolidate: static and dynamic sets of one list collapse together") {
  // A single list routed to one outbound emits kpbr4_/kpbr4d_ pairs; they share
  // a fwmark and selector so they fold into one rule per family.
  const auto out = consolidate_iptables_rules({
      mark_unit("kpbr4_l", false, 0x100),
      mark_unit("kpbr6_l", true, 0x100),
      mark_unit("kpbr4d_l", false, 0x100),
      mark_unit("kpbr6d_l", true, 0x100),
  });
  REQUIRE(out.size() == 2);
  CHECK(out[0].is_combined);
  CHECK_FALSE(out[0].ipv6);
  CHECK(out[0].criteria.dst_set_name.value_or("") == "kpbrm_0");
  CHECK(out[0].member_sets == std::vector<std::string>({"kpbr4_l", "kpbr4d_l"}));
  CHECK(out[1].is_combined);
  CHECK(out[1].ipv6);
  CHECK(out[1].criteria.dst_set_name.value_or("") == "kpbrm_1");
  CHECK(out[1].member_sets == std::vector<std::string>({"kpbr6_l", "kpbr6d_l"}));
}

TEST_CASE("consolidate: IPv4 and IPv6 never share a list:set") {
  const auto out = consolidate_iptables_rules({
      mark_unit("kpbr4_a", false, 0x100),
      mark_unit("kpbr6_a", true, 0x100),
      mark_unit("kpbr4_b", false, 0x100),
      mark_unit("kpbr6_b", true, 0x100),
  });
  REQUIRE(out.size() == 2);
  CHECK_FALSE(out[0].ipv6);
  CHECK(out[0].member_sets == std::vector<std::string>({"kpbr4_a", "kpbr4_b"}));
  CHECK(out[1].ipv6);
  CHECK(out[1].member_sets == std::vector<std::string>({"kpbr6_a", "kpbr6_b"}));
}

TEST_CASE("consolidate: drop rules consolidate independently of mark rules") {
  const auto out = consolidate_iptables_rules({
      drop_unit("kpbr4_a", false),
      drop_unit("kpbr4_b", false),
  });
  REQUIRE(out.size() == 1);
  CHECK(out[0].is_combined);
  CHECK(out[0].action == ConsolidatableRule::Action::Drop);
  CHECK(out[0].member_sets == std::vector<std::string>({"kpbr4_a", "kpbr4_b"}));
}

TEST_CASE("consolidate: mark and drop with the same set do not merge") {
  const auto out = consolidate_iptables_rules({
      mark_unit("kpbr4_a", false, 0x100),
      drop_unit("kpbr4_a", false),
  });
  REQUIRE(out.size() == 2);
  CHECK_FALSE(out[0].is_combined);
  CHECK(out[0].action == ConsolidatableRule::Action::Mark);
  CHECK_FALSE(out[1].is_combined);
  CHECK(out[1].action == ConsolidatableRule::Action::Drop);
}

// =============================================================================
// De-duplication and ordering.
// =============================================================================

TEST_CASE("consolidate: a set referenced twice appears once in the list:set") {
  const auto out = consolidate_iptables_rules({
      mark_unit("kpbr4_a", false, 0x100),
      mark_unit("kpbr4_b", false, 0x100),
      mark_unit("kpbr4_a", false, 0x100),
  });
  REQUIRE(out.size() == 1);
  CHECK(out[0].is_combined);
  CHECK(out[0].member_sets == std::vector<std::string>({"kpbr4_a", "kpbr4_b"}));
}

TEST_CASE("consolidate: groups keep first-seen order, ordinals skip singletons") {
  // rule0 -> A (becomes multi-member), rule1 -> B (stays singleton),
  // rule2 -> A. Group A is first-seen so it owns kpbrm_0; B keeps kpbr4_b.
  const auto out = consolidate_iptables_rules({
      mark_unit("kpbr4_a0", false, 0x100),
      mark_unit("kpbr4_b0", false, 0x200),
      mark_unit("kpbr4_a1", false, 0x100),
  });
  REQUIRE(out.size() == 2);
  CHECK(out[0].is_combined);
  CHECK(out[0].criteria.dst_set_name.value_or("") == "kpbrm_0");
  CHECK(out[0].member_sets ==
        std::vector<std::string>({"kpbr4_a0", "kpbr4_a1"}));
  CHECK_FALSE(out[1].is_combined);
  CHECK(out[1].criteria.dst_set_name.value_or("") == "kpbr4_b0");
}

TEST_CASE("consolidate: two distinct multi-member groups get sequential ordinals") {
  const auto out = consolidate_iptables_rules({
      mark_unit("kpbr4_a0", false, 0x100),
      mark_unit("kpbr4_b0", false, 0x200),
      mark_unit("kpbr4_a1", false, 0x100),
      mark_unit("kpbr4_b1", false, 0x200),
  });
  REQUIRE(out.size() == 2);
  CHECK(out[0].criteria.dst_set_name.value_or("") == "kpbrm_0");
  CHECK(out[1].criteria.dst_set_name.value_or("") == "kpbrm_1");
}

// =============================================================================
// Direct (no ipset) rules pass through untouched, keeping position.
// =============================================================================

TEST_CASE("consolidate: a direct rule is preserved verbatim and in place") {
  ConsolidatableRule direct;
  direct.ipv6 = false;
  direct.action = ConsolidatableRule::Action::Mark;
  direct.fwmark = 0x10000;
  direct.criteria.dst_addr = {"10.8.0.1"};
  direct.criteria.dst_port = "53";

  const auto out = consolidate_iptables_rules({
      mark_unit("kpbr4_a", false, 0x100),
      mark_unit("kpbr4_b", false, 0x100),
      direct,
  });
  REQUIRE(out.size() == 2);
  CHECK(out[0].is_combined);
  CHECK(out[0].member_sets == std::vector<std::string>({"kpbr4_a", "kpbr4_b"}));
  CHECK_FALSE(out[1].is_combined);
  CHECK_FALSE(out[1].criteria.dst_set_name.has_value());
  CHECK(out[1].criteria.dst_addr == std::vector<std::string>({"10.8.0.1"}));
  CHECK(out[1].fwmark == 0x10000u);
}

// =============================================================================
// Selector-aware grouping: rules with different selectors stay separate.
// =============================================================================

TEST_CASE("consolidate: same outbound but different proto are separate groups") {
  ConsolidatableRule tcp = mark_unit("kpbr4_a", false, 0x100);
  tcp.criteria.proto = L4Proto::Tcp;
  ConsolidatableRule udp = mark_unit("kpbr4_b", false, 0x100);
  udp.criteria.proto = L4Proto::Udp;

  const auto out = consolidate_iptables_rules({tcp, udp});
  REQUIRE(out.size() == 2);
  CHECK_FALSE(out[0].is_combined);
  CHECK(out[0].criteria.proto == L4Proto::Tcp);
  CHECK_FALSE(out[1].is_combined);
  CHECK(out[1].criteria.proto == L4Proto::Udp);
}

TEST_CASE("consolidate: same outbound and proto with two sets collapse") {
  ConsolidatableRule a = mark_unit("kpbr4_a", false, 0x100);
  a.criteria.proto = L4Proto::Tcp;
  a.criteria.dst_port = "443";
  ConsolidatableRule b = mark_unit("kpbr4_b", false, 0x100);
  b.criteria.proto = L4Proto::Tcp;
  b.criteria.dst_port = "443";

  const auto out = consolidate_iptables_rules({a, b});
  REQUIRE(out.size() == 1);
  CHECK(out[0].is_combined);
  CHECK(out[0].criteria.proto == L4Proto::Tcp);
  CHECK(out[0].criteria.dst_port.to_iptables_string() == "443");
  CHECK(out[0].member_sets == std::vector<std::string>({"kpbr4_a", "kpbr4_b"}));
}

TEST_CASE("consolidate: differing src_addr keeps rules in separate groups") {
  ConsolidatableRule a = mark_unit("kpbr4_a", false, 0x100);
  a.criteria.src_addr = {"192.168.1.0/24"};
  ConsolidatableRule b = mark_unit("kpbr4_b", false, 0x100);
  b.criteria.src_addr = {"10.0.0.0/8"};

  const auto out = consolidate_iptables_rules({a, b});
  REQUIRE(out.size() == 2);
  CHECK_FALSE(out[0].is_combined);
  CHECK_FALSE(out[1].is_combined);
}

TEST_CASE("consolidate: a /32 host suffix does not split an address group") {
  ConsolidatableRule a = mark_unit("kpbr4_a", false, 0x100);
  a.criteria.dst_addr = {"203.0.113.5/32"};
  ConsolidatableRule b = mark_unit("kpbr4_b", false, 0x100);
  b.criteria.dst_addr = {"203.0.113.5"};

  const auto out = consolidate_iptables_rules({a, b});
  REQUIRE(out.size() == 1);
  CHECK(out[0].is_combined);
  CHECK(out[0].member_sets == std::vector<std::string>({"kpbr4_a", "kpbr4_b"}));
}

// =============================================================================
// Bulk shape: many lists to one outbound collapse to one rule per family.
// =============================================================================

TEST_CASE("consolidate: 40 lists to one outbound collapse to two rules") {
  std::vector<ConsolidatableRule> input;
  for (int i = 0; i < 40; ++i) {
    input.push_back(mark_unit("kpbr4_l" + std::to_string(i), false, 0x100));
    input.push_back(mark_unit("kpbr6_l" + std::to_string(i), true, 0x100));
  }
  const auto out = consolidate_iptables_rules(input);
  REQUIRE(out.size() == 2);
  CHECK(out[0].is_combined);
  CHECK(out[0].member_sets.size() == 40);
  CHECK(out[1].is_combined);
  CHECK(out[1].member_sets.size() == 40);
}

TEST_CASE("consolidate: empty input yields no rules") {
  const auto out = consolidate_iptables_rules({});
  CHECK(out.empty());
}

TEST_CASE("combined_set_name: deterministic kpbrm_ naming") {
  CHECK(combined_set_name(0) == "kpbrm_0");
  CHECK(combined_set_name(7) == "kpbrm_7");
}
