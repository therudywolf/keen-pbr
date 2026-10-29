#include <doctest/doctest.h>

#include "../src/config/config.hpp"
#include "../src/config/routing_state.hpp"
#include "../src/firewall/ipset_restore_pipe.hpp"
#include "../src/firewall/iptables.hpp"
#include "../src/firewall/iptables_set_consolidation.hpp"
#include "../src/lists/list_entry_visitor.hpp"

#include <sstream>
#include <iomanip>
#include <map>
#include <optional>
#include <string>
#include <set>
#include <tuple>
#include <utility>
#include <array>
#include <algorithm>
#include <sys/socket.h>
#include <vector>

namespace keen_pbr3 {

namespace {

L4Proto parse_test_proto(const std::string& proto) {
  if (proto.empty()) return L4Proto::Any;
  if (proto == "tcp") return L4Proto::Tcp;
  if (proto == "udp") return L4Proto::Udp;
  if (proto == "tcp/udp") return L4Proto::TcpUdp;
  throw std::invalid_argument("unexpected proto in test: " + proto);
}

} // namespace

// Friend class with test access to IptablesFirewall private methods.
class IptablesBuilderTest {
public:
  // Public mirror of PendingRule for use in test functions.
  struct RuleDesc {
    std::string set_name;
    bool ipv6;
    bool direct = false;
    enum Action { Mark, Drop, Pass } action;
    uint32_t fwmark;
    ProtoPortFilter filter;
  };

  static std::string build_ipset_create_line(const std::string &name,
                                             const std::string &family_str,
                                             uint32_t timeout) {
    IptablesFirewall::PendingSet ps;
    ps.name = name;
    ps.family_str = family_str;
    ps.timeout = timeout;
    return IptablesFirewall::build_ipset_create_line(ps);
  }

  static std::string build_list_set_lines(const std::string &name,
                                          const std::vector<std::string> &members) {
    IptablesFirewall::PendingListSet pls;
    pls.name = name;
    pls.members = members;
    return IptablesFirewall::build_list_set_lines(pls);
  }

  static std::optional<std::string> hash_set_mismatch(const std::string &listing,
                                                      const std::string &name,
                                                      const std::string &family,
                                                      uint32_t timeout) {
    IptablesFirewall::PendingSet ps;
    ps.name = name;
    ps.family_str = family;
    ps.timeout = timeout;
    return IptablesFirewall::live_hash_set_mismatch(
        IptablesFirewall::parse_ipset_terse_listing(listing), ps);
  }

  struct DynamicPlan {
    std::set<std::string> keep;
    std::set<std::string> destroy;
  };

  static DynamicPlan plan_dynamic_sets(
      const std::string &listing,
      const std::vector<std::tuple<std::string, std::string, uint32_t>> &pending,
      bool ipv6) {
    std::vector<IptablesFirewall::PendingSet> sets;
    for (const auto &[name, family, timeout] : pending) {
      IptablesFirewall::PendingSet ps;
      ps.name = name;
      ps.family_str = family;
      ps.timeout = timeout;
      sets.push_back(ps);
    }
    const auto plan = IptablesFirewall::plan_dynamic_sets(
        IptablesFirewall::parse_ipset_terse_listing(listing), sets, ipv6);
    return DynamicPlan{plan.keep, plan.destroy};
  }

  struct LiveSet {
    std::string type;
    std::string family;
    std::optional<uint32_t> timeout;
    std::optional<size_t> entries;
  };

  static std::map<std::string, LiveSet> parse_terse(const std::string &listing) {
    std::map<std::string, LiveSet> out;
    for (const auto &[name, info] : IptablesFirewall::parse_ipset_terse_listing(listing)) {
      out[name] = LiveSet{info.type, info.family, info.timeout, info.entries};
    }
    return out;
  }

  static std::string build_ipt_script(bool ipv6,
                                      const std::vector<RuleDesc> &descs,
                                      FirewallGlobalPrefilter prefilter = {},
                                      bool add_prerouting_jump = true) {
    std::vector<IptablesFirewall::PendingRule> rules;
    rules.reserve(descs.size());
    for (const auto &d : descs) {
      IptablesFirewall::PendingRule pr;
      pr.ipv6 = d.ipv6;
      if (d.action == RuleDesc::Mark) {
        pr.action = IptablesFirewall::PendingRule::Mark;
      } else if (d.action == RuleDesc::Drop) {
        pr.action = IptablesFirewall::PendingRule::Drop;
      } else {
        pr.action = IptablesFirewall::PendingRule::Pass;
      }
      pr.fwmark = d.fwmark;
      pr.criteria = d.filter;
      if (!d.set_name.empty()) {
        pr.criteria.dst_set_name = d.set_name;
      }
      rules.push_back(std::move(pr));
    }
    return IptablesFirewall::build_ipt_script(ipv6, rules, prefilter, add_prerouting_jump);
  }

  static std::string build_ipt_script_for_rule(bool ipv6,
                                               RuleDesc::Action action,
                                               uint32_t fwmark,
                                               FirewallRuleCriteria criteria,
                                               bool list_backed,
                                               uint32_t fwmark_mask = 0xFFFFFFFFu,
                                               FirewallGlobalPrefilter prefilter = {}) {
    IptablesFirewall fw;
    fw.set_fwmark_mask(fwmark_mask);
    if (list_backed) {
      criteria.dst_set_name = "pairwise_set";
      fw.created_sets_["pairwise_set"] = ipv6 ? AF_INET6 : AF_INET;
    }

    IptablesFirewall::PendingRule::Action mapped_action =
        IptablesFirewall::PendingRule::Mark;
    if (action == RuleDesc::Drop) {
      mapped_action = IptablesFirewall::PendingRule::Drop;
    } else if (action == RuleDesc::Pass) {
      mapped_action = IptablesFirewall::PendingRule::Pass;
    }

    fw.append_rules_for_family(ipv6, mapped_action, fwmark, criteria);
    return IptablesFirewall::build_ipt_script(ipv6, fw.pending_rules_, prefilter);
  }

  // Mark rules for several list sets on one firewall instance, so their
  // negated address sets and consolidation interact as in a real apply.
  // Returns the iptables script and the ipset lines of the negated sets.
  static std::pair<std::string, std::string> build_marked_list_rules(
      bool ipv6, uint32_t fwmark,
      const std::vector<std::pair<std::string, FirewallRuleCriteria>> &rules) {
    IptablesFirewall fw;
    for (auto [set_name, criteria] : rules) {
      criteria.dst_set_name = set_name;
      fw.created_sets_[set_name] = ipv6 ? AF_INET6 : AF_INET;
      fw.append_rules_for_family(ipv6, IptablesFirewall::PendingRule::Mark, fwmark, criteria);
    }
    std::string set_lines;
    for (const auto &ps : fw.pending_sets_) {
      set_lines += IptablesFirewall::build_ipset_create_line(ps);
      set_lines += fw.pending_elements_[ps.name].str();
    }
    return {IptablesFirewall::build_ipt_script(ipv6, fw.pending_rules_), set_lines};
  }

  static std::string build_proto_port_fragment(const std::string &proto,
                                               const std::string &src_port,
                                               const std::string &dst_port,
                                               bool negate_src = false,
                                               bool negate_dst = false) {
    return IptablesFirewall::build_proto_port_fragment(
        parse_test_proto(proto), PortSpec(src_port), PortSpec(dst_port),
        negate_src, negate_dst);
  }
};

} // namespace keen_pbr3

using namespace keen_pbr3;
using T = IptablesBuilderTest;
using Rule = IptablesBuilderTest::RuleDesc;

namespace {

Config parse_valid_config(const std::string& json) {
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

} // namespace

static Rule mark_rule(const std::string &set_name, bool ipv6, uint32_t fwmark,
                      ProtoPortFilter filter = {}) {
  Rule r;
  r.set_name = set_name;
  r.ipv6 = ipv6;
  r.action = Rule::Mark;
  r.fwmark = fwmark;
  r.filter = filter;
  return r;
}

static Rule drop_rule(const std::string &set_name, bool ipv6,
                      ProtoPortFilter filter = {}) {
  Rule r;
  r.set_name = set_name;
  r.ipv6 = ipv6;
  r.action = Rule::Drop;
  r.fwmark = 0;
  r.filter = filter;
  return r;
}

static Rule pass_rule(const std::string &set_name, bool ipv6,
                      ProtoPortFilter filter = {}) {
  Rule r;
  r.set_name = set_name;
  r.ipv6 = ipv6;
  r.action = Rule::Pass;
  r.fwmark = 0;
  r.filter = filter;
  return r;
}

static FirewallGlobalPrefilter prefilter_with_interfaces(
    std::vector<std::string> interfaces,
    bool skip_established_or_dnat = true) {
  FirewallGlobalPrefilter prefilter;
  prefilter.skip_established_or_dnat = skip_established_or_dnat;
  prefilter.skip_marked_packets = true;
  prefilter.inbound_interfaces = std::move(interfaces);
  return prefilter;
}

// =============================================================================
// IpsetRestoreVisitor::on_entry tests
// =============================================================================

TEST_CASE("IpsetRestoreVisitor: IP entry without timeout") {
  std::ostringstream buf;
  IpsetRestoreVisitor v(buf, "myset");
  v.on_entry(EntryType::Ip, "10.0.0.1");
  CHECK(buf.str() == "add myset 10.0.0.1 -exist\n");
  CHECK(v.count() == 1);
}

TEST_CASE("IpsetRestoreVisitor: CIDR entry") {
  std::ostringstream buf;
  IpsetRestoreVisitor v(buf, "myset");
  v.on_entry(EntryType::Cidr, "192.168.0.0/24");
  CHECK(buf.str() == "add myset 192.168.0.0/24 -exist\n");
  CHECK(v.count() == 1);
}

TEST_CASE("IpsetRestoreVisitor: IPv4 zero prefix expands for hash:net") {
  std::ostringstream buf;
  IpsetRestoreVisitor v(buf, "myset");
  v.on_entry(EntryType::Cidr, "0.0.0.0/0");
  CHECK(buf.str() == "add myset 0.0.0.0/1 -exist\n"
                     "add myset 128.0.0.0/1 -exist\n");
  CHECK(v.count() == 2);
}

TEST_CASE("IpsetRestoreVisitor: IPv6 zero prefix expands for hash:net") {
  std::ostringstream buf;
  IpsetRestoreVisitor v(buf, "myset");
  v.on_entry(EntryType::Cidr, "::/0");
  CHECK(buf.str() == "add myset ::/1 -exist\n"
                     "add myset 8000::/1 -exist\n");
  CHECK(v.count() == 2);
}

TEST_CASE("IpsetRestoreVisitor: a non-zero prefix ending in 0 is kept verbatim") {
  std::ostringstream buf;
  IpsetRestoreVisitor v(buf, "myset");
  v.on_entry(EntryType::Cidr, "10.0.0.0/10");
  v.on_entry(EntryType::Cidr, "2001:db8::/20");
  CHECK(buf.str() == "add myset 10.0.0.0/10 -exist\n"
                     "add myset 2001:db8::/20 -exist\n");
  CHECK(v.count() == 2);
}

TEST_CASE("IpsetRestoreVisitor: Domain entry is ignored") {
  std::ostringstream buf;
  IpsetRestoreVisitor v(buf, "myset");
  v.on_entry(EntryType::Domain, "example.com");
  CHECK(buf.str().empty());
  CHECK(v.count() == 0);
}

TEST_CASE("IpsetRestoreVisitor: count increments only for IP/CIDR") {
  std::ostringstream buf;
  IpsetRestoreVisitor v(buf, "myset");
  v.on_entry(EntryType::Ip, "1.2.3.4");
  v.on_entry(EntryType::Domain, "example.com");
  v.on_entry(EntryType::Cidr, "10.0.0.0/8");
  CHECK(v.count() == 2);
}

// =============================================================================
// build_ipset_create_line tests
// =============================================================================

TEST_CASE("build_ipset_create_line: IPv4 without timeout") {
  auto line = T::build_ipset_create_line("myset", "inet", 0);
  CHECK(line == "create myset hash:net family inet -exist\n");
}

TEST_CASE("build_ipset_create_line: IPv4 with timeout 60") {
  auto line = T::build_ipset_create_line("myset", "inet", 60);
  CHECK(line == "create myset hash:net family inet timeout 60 -exist\n");
}

TEST_CASE("build_ipset_create_line: IPv6 without timeout") {
  auto line = T::build_ipset_create_line("myset", "inet6", 0);
  CHECK(line == "create myset hash:net family inet6 -exist\n");
}

// =============================================================================
// build_ipt_script tests
// =============================================================================

TEST_CASE("build_ipt_script: IPv4 mark rule") {
  auto s = T::build_ipt_script(false, {mark_rule("myset", false, 0x100)});
  CHECK(s.find("*mangle") != std::string::npos);
  CHECK(s.find(":KeenPbrTable") != std::string::npos);
  CHECK(s.find("-A PREROUTING -j KeenPbrTable") != std::string::npos);
  CHECK(s.find("-A KeenPbrTable -m set --match-set myset dst -j MARK "
               "--set-xmark 0x100/0xffffffff") != std::string::npos);
  CHECK(s.find("-A KeenPbrTable -m set --match-set myset dst -j RETURN") !=
        std::string::npos);
  CHECK(s.size() >= 7);
  CHECK(s.substr(s.size() - 7) == "COMMIT\n");
}

TEST_CASE("build_ipt_script: IPv4 drop rule") {
  auto s = T::build_ipt_script(false, {drop_rule("blacklist", false)});
  CHECK(s.find("-A KeenPbrTable -m set --match-set blacklist dst -j DROP") !=
        std::string::npos);
}

TEST_CASE("build_ipt_script: IPv4 pass rule") {
  auto s = T::build_ipt_script(false, {pass_rule("allowlist", false)});
  CHECK(s.find("-A KeenPbrTable -m set --match-set allowlist dst -j RETURN") !=
        std::string::npos);
}

TEST_CASE("build_ipt_script: IPv6 mark rule") {
  auto s = T::build_ipt_script(true, {mark_rule("v6set", true, 0x200)});
  CHECK(s.find("-A KeenPbrTable -m set --match-set v6set dst -j MARK "
               "--set-xmark 0x200/0xffffffff") != std::string::npos);
  CHECK(s.find("-A KeenPbrTable -m set --match-set v6set dst -j RETURN") !=
        std::string::npos);
  CHECK(s.substr(s.size() - 7) == "COMMIT\n");
}

TEST_CASE("build_ipt_script: ipv6=false filters out IPv6 rules") {
  auto s = T::build_ipt_script(false, {mark_rule("v4set", false, 0x100),
                                       mark_rule("v6set", true, 0x200)});
  CHECK(s.find("v4set") != std::string::npos);
  CHECK(s.find("v6set") == std::string::npos);
}

TEST_CASE("build_ipt_script: ipv6=true filters out IPv4 rules") {
  auto s = T::build_ipt_script(true, {mark_rule("v4set", false, 0x100),
                                      mark_rule("v6set", true, 0x200)});
  CHECK(s.find("v6set") != std::string::npos);
  CHECK(s.find("v4set") == std::string::npos);
}

TEST_CASE("build_ipt_script: zero fwmark") {
  auto s = T::build_ipt_script(false, {mark_rule("zeroset", false, 0)});
  CHECK(s.find("--set-xmark 0x0/0xffffffff") != std::string::npos);
}

TEST_CASE("build_ipt_script: multiple rules appear in order") {
  auto s = T::build_ipt_script(
      false, {mark_rule("first", false, 0x1), drop_rule("second", false)});
  auto pos_first = s.find("first");
  auto pos_second = s.find("second");
  CHECK(pos_first != std::string::npos);
  CHECK(pos_second != std::string::npos);
  CHECK(pos_first < pos_second);
}

TEST_CASE("build_ipt_script: empty rules still build KeenPbrTable scaffold") {
  auto s = T::build_ipt_script(false, {});
  CHECK(s.find("*mangle\n") != std::string::npos);
  CHECK(s.find(":KeenPbrTable - [0:0]\n") != std::string::npos);
  CHECK(s.find("-A PREROUTING -j KeenPbrTable\n") != std::string::npos);
  CHECK(s.find("-A KeenPbrTable ") == std::string::npos);
  CHECK(s == "*mangle\n:KeenPbrTable - [0:0]\n-A PREROUTING -j KeenPbrTable\nCOMMIT\n");
}

TEST_CASE("build_ipt_script: global prefilter RETURN lines are emitted before route rules") {
  auto s = T::build_ipt_script(
      false,
      {mark_rule("myset", false, 0x100)},
      prefilter_with_interfaces({"br0"}));

  const std::string dnat =
      "-A KeenPbrTable -m conntrack --ctstate DNAT -j RETURN\n";
  const std::string marked =
      "-A KeenPbrTable -m mark ! --mark 0x0/0xffffffff -j ACCEPT\n";
  const std::string iface =
      "-A KeenPbrTable ! -i br0 -j RETURN\n";
  const std::string mark =
      "[0:0] -A KeenPbrTable -m set --match-set myset dst -j MARK --set-xmark 0x100/0xffffffff\n";

  const auto dnat_pos = s.find(dnat);
  const auto marked_pos = s.find(marked);
  const auto iface_pos = s.find(iface);
  const auto mark_pos = s.find(mark);
  REQUIRE(dnat_pos != std::string::npos);
  REQUIRE(marked_pos != std::string::npos);
  REQUIRE(iface_pos != std::string::npos);
  REQUIRE(mark_pos != std::string::npos);
  CHECK(s.find("--ctstate RELATED,ESTABLISHED") == std::string::npos);
  CHECK(dnat_pos < marked_pos);
  CHECK(marked_pos < iface_pos);
  CHECK(iface_pos < mark_pos);
}

TEST_CASE("build_ipt_script: skip_marked_packets prefilter can be disabled") {
  FirewallGlobalPrefilter prefilter;
  prefilter.skip_established_or_dnat = true;
  prefilter.skip_marked_packets = false;

  auto s = T::build_ipt_script(false, {mark_rule("myset", false, 0x100)}, prefilter);
  CHECK(s.find("-m mark ! --mark 0x0/0xffffffff -j ACCEPT") == std::string::npos);
}

TEST_CASE("build_ipt_script: offload guard puts -j PPE between MARK and RETURN") {
  FirewallGlobalPrefilter prefilter;
  prefilter.offload_guard = true;

  auto s = T::build_ipt_script(false, {mark_rule("myset", false, 0x100)}, prefilter);
  const std::string rules =
      "[0:0] -A KeenPbrTable -m set --match-set myset dst -j MARK --set-xmark 0x100/0xffffffff\n"
      "-A KeenPbrTable -m set --match-set myset dst -j PPE\n"
      "-A KeenPbrTable -m set --match-set myset dst -j RETURN\n";
  CHECK(s.find(rules) != std::string::npos);
}

TEST_CASE("build_ipt_script: offload guard follows each interface's MARK rule") {
  auto prefilter = prefilter_with_interfaces({"br0", "nwg1"});
  prefilter.offload_guard = true;

  auto s = T::build_ipt_script(false, {mark_rule("kpbrm_0", false, 0x70000)}, prefilter);
  for (const std::string iface : {"br0", "nwg1"}) {
    const std::string rules =
        "[0:0] -A KeenPbrTable -m set --match-set kpbrm_0 dst -i " + iface +
        " -j MARK --set-xmark 0x70000/0xffffffff\n"
        "-A KeenPbrTable -m mark --mark 0x70000/0xffffffff -j PPE\n"
        "-A KeenPbrTable -m mark --mark 0x70000/0xffffffff -j RETURN\n";
    CHECK_MESSAGE(s.find(rules) != std::string::npos, iface);
  }
}

TEST_CASE("build_ipt_script: with skip_marked_packets the RETURN companion tests the mark") {
  FirewallGlobalPrefilter prefilter;
  prefilter.skip_marked_packets = true;

  auto s = T::build_ipt_script(false, {mark_rule("myset", false, 0x100)}, prefilter);
  const std::string rules =
      "[0:0] -A KeenPbrTable -m set --match-set myset dst -j MARK --set-xmark 0x100/0xffffffff\n"
      "-A KeenPbrTable -m mark --mark 0x100/0xffffffff -j RETURN\n";
  CHECK(s.find(rules) != std::string::npos);
  CHECK(s.find("--match-set myset dst -j RETURN") == std::string::npos);
}

TEST_CASE("build_ipt_script: the mark test uses the masked fwmark") {
  FirewallRuleCriteria criteria;
  FirewallGlobalPrefilter prefilter;
  prefilter.skip_marked_packets = true;

  auto s = T::build_ipt_script_for_rule(false, Rule::Mark, 0x00010000, criteria,
                                        true, 0x00FF0000, prefilter);
  CHECK(s.find("[0:0] -A KeenPbrTable -m set --match-set pairwise_set dst -j MARK --set-xmark 0x10000/0xff0000\n"
               "-A KeenPbrTable -m mark --mark 0x10000/0xff0000 -j RETURN\n") !=
        std::string::npos);
}

TEST_CASE("build_ipt_script: a zero fwmark keeps the full match in its companions") {
  FirewallGlobalPrefilter prefilter;
  prefilter.skip_marked_packets = true;
  prefilter.offload_guard = true;

  auto s = T::build_ipt_script(false, {mark_rule("zeroset", false, 0)}, prefilter);
  CHECK(s.find("-A KeenPbrTable -m set --match-set zeroset dst -j PPE\n") != std::string::npos);
  CHECK(s.find("-A KeenPbrTable -m set --match-set zeroset dst -j RETURN\n") != std::string::npos);
  CHECK(s.find("-m mark --mark 0x0/") == std::string::npos);
}

TEST_CASE("build_ipt_script: a later rule still runs after an unmatched mark test") {
  FirewallGlobalPrefilter prefilter;
  prefilter.skip_marked_packets = true;

  auto s = T::build_ipt_script(
      false, {mark_rule("first", false, 0x10000), mark_rule("second", false, 0x20000)}, prefilter);
  const auto first_return = s.find("-A KeenPbrTable -m mark --mark 0x10000/0xffffffff -j RETURN\n");
  const auto second_mark = s.find("--match-set second dst -j MARK --set-xmark 0x20000/0xffffffff\n");
  const auto second_return = s.find("-A KeenPbrTable -m mark --mark 0x20000/0xffffffff -j RETURN\n");
  REQUIRE(first_return != std::string::npos);
  REQUIRE(second_mark != std::string::npos);
  REQUIRE(second_return != std::string::npos);
  CHECK(first_return < second_mark);
  CHECK(second_mark < second_return);
}

TEST_CASE("build_ipt_script: offload guard also follows address-only MARK rules") {
  FirewallRuleCriteria criteria;
  criteria.dst_addr = {"203.0.113.0/24"};
  criteria.proto = L4Proto::Tcp;
  criteria.dst_port = PortSpec("443");
  FirewallGlobalPrefilter prefilter;
  prefilter.offload_guard = true;

  auto s = T::build_ipt_script_for_rule(false, Rule::Mark, 0x100, criteria,
                                        false, 0xFFFFFFFFu, prefilter);
  CHECK(s.find("-A KeenPbrTable -d 203.0.113.0/24 -p tcp --dport 443 -j PPE\n") !=
        std::string::npos);
}

TEST_CASE("build_ipt_script: offload guard does not touch DROP and RETURN rules") {
  FirewallGlobalPrefilter prefilter;
  prefilter.offload_guard = true;

  auto s = T::build_ipt_script(
      false, {drop_rule("blocked", false), pass_rule("allowlist", false)}, prefilter);
  CHECK(s.find("-j PPE") == std::string::npos);
}

TEST_CASE("build_ipt_script: no -j PPE without the offload guard") {
  auto s = T::build_ipt_script(false, {mark_rule("myset", false, 0x100)});
  CHECK(s.find("-j PPE") == std::string::npos);
}

TEST_CASE("build_ipt_script: multi-interface prefilter expands route rules with -i matches") {
  auto s = T::build_ipt_script(
      false,
      {pass_rule("allowlist", false)},
      prefilter_with_interfaces({"br0", "wg0"}, false));

  CHECK(s.find("-A KeenPbrTable -m set --match-set allowlist dst -i br0 -j RETURN\n") !=
        std::string::npos);
  CHECK(s.find("-A KeenPbrTable -m set --match-set allowlist dst -i wg0 -j RETURN\n") !=
        std::string::npos);
}

TEST_CASE("build_ipt_script: config-derived prefilter keeps route rule body unchanged") {
  auto cfg = parse_valid_config(R"({
    "outbounds":[
      {"tag":"wan","type":"interface","interface":"eth0","gateway":"192.0.2.1"}
    ],
    "lists":{
      "local":{"ip_cidrs":["192.168.0.0/16"]}
    },
    "route":{
      "inbound_interfaces":["br0"],
      "rules":[
        {"list":["local"],"outbound":"wan"}
      ]
    }
  })");

  const auto prefilter = build_firewall_global_prefilter(cfg);
  auto s = T::build_ipt_script(false, {mark_rule("kpbr4_local", false, 0x100)}, prefilter);

  const std::string iface = "-A KeenPbrTable ! -i br0 -j RETURN\n";
  const std::string mark =
      "[0:0] -A KeenPbrTable -m set --match-set kpbr4_local dst -j MARK --set-xmark 0x100/0xffffffff\n";
  const auto iface_pos = s.find(iface);
  const auto mark_pos = s.find(mark);
  REQUIRE(iface_pos != std::string::npos);
  REQUIRE(mark_pos != std::string::npos);
  CHECK(iface_pos < mark_pos);
}

TEST_CASE("build_ipt_script_for_rule: masked mark rule uses set-xmark and rule counters") {
  FirewallRuleCriteria criteria;
  auto s = T::build_ipt_script_for_rule(false, Rule::Mark, 0x00010000, criteria,
                                        true, 0x00FF0000);
  CHECK(s.find("[0:0] -A KeenPbrTable -m set --match-set pairwise_set dst -j MARK --set-xmark 0x10000/0xff0000\n") !=
        std::string::npos);
}

TEST_CASE("build_ipt_script: config-derived prefilter omits interface guard when inbound list is empty") {
  auto cfg = parse_valid_config(R"({
    "outbounds":[
      {"tag":"wan","type":"interface","interface":"eth0","gateway":"192.0.2.1"}
    ],
    "lists":{
      "local":{"ip_cidrs":["192.168.0.0/16"]}
    },
    "route":{
      "inbound_interfaces":[],
      "rules":[
        {"list":["local"],"outbound":"wan"}
      ]
    }
  })");

  const auto prefilter = build_firewall_global_prefilter(cfg);
  auto s = T::build_ipt_script(false, {mark_rule("kpbr4_local", false, 0x100)}, prefilter);

  CHECK(s.find("! -i ") == std::string::npos);
  CHECK(s.find("-A KeenPbrTable -m set --match-set kpbr4_local dst -j MARK --set-xmark 0x100/0xffffffff\n") !=
        std::string::npos);
}

// =============================================================================
// build_proto_port_fragment tests
// =============================================================================

TEST_CASE("build_proto_port_fragment: empty filter → empty string") {
  CHECK(T::build_proto_port_fragment("", "", "") == "");
}

TEST_CASE("build_proto_port_fragment: tcp + single dest_port") {
  auto frag = T::build_proto_port_fragment("tcp", "", "443");
  CHECK(frag == " -p tcp --dport 443");
}

TEST_CASE("build_proto_port_fragment: udp + port range") {
  auto frag = T::build_proto_port_fragment("udp", "", "8000-9000");
  CHECK(frag == " -p udp --dport 8000:9000");
}

TEST_CASE("build_proto_port_fragment: tcp + port list → multiport") {
  auto frag = T::build_proto_port_fragment("tcp", "", "80,443");
  CHECK(frag == " -p tcp -m multiport --dports 80,443");
}

TEST_CASE("build_proto_port_fragment: src_port + dest_port → sport and dport") {
  auto frag = T::build_proto_port_fragment("tcp", "1024-65535", "80");
  CHECK(frag == " -p tcp --sport 1024:65535 --dport 80");
}

TEST_CASE("build_proto_port_fragment: proto only, no ports") {
  auto frag = T::build_proto_port_fragment("udp", "", "");
  CHECK(frag == " -p udp");
}

// =============================================================================
// build_ipt_script with proto/port filter tests
// =============================================================================

TEST_CASE("build_ipt_script: tcp + single dest_port in rule") {
  ProtoPortFilter f;
  f.proto = L4Proto::Tcp;
  f.dst_port = "443";
  auto s = T::build_ipt_script(false, {mark_rule("myset", false, 0x100, f)});
  CHECK(s.find("-A KeenPbrTable -m set --match-set myset dst -p tcp --dport "
               "443 -j MARK --set-xmark 0x100/0xffffffff") != std::string::npos);
}

TEST_CASE("build_ipt_script: udp + port range in rule") {
  ProtoPortFilter f;
  f.proto = L4Proto::Udp;
  f.dst_port = "8000-9000";
  auto s = T::build_ipt_script(false, {drop_rule("bl", false, f)});
  CHECK(s.find("-A KeenPbrTable -m set --match-set bl dst -p udp --dport "
               "8000:9000 -j DROP") != std::string::npos);
}

TEST_CASE("build_ipt_script: tcp/udp + port list → two rules") {
  ProtoPortFilter f;
  f.proto = L4Proto::TcpUdp;
  f.dst_port = "80,443";
  // create_mark_rule expands tcp/udp, so we simulate by passing two rules
  // already expanded
  ProtoPortFilter ftcp;
  ftcp.proto = L4Proto::Tcp;
  ftcp.dst_port = "80,443";
  ProtoPortFilter fudp;
  fudp.proto = L4Proto::Udp;
  fudp.dst_port = "80,443";
  auto s = T::build_ipt_script(false, {mark_rule("s", false, 0x10, ftcp),
                                       mark_rule("s", false, 0x10, fudp)});
  CHECK(s.find("-p tcp -m multiport --dports 80,443") != std::string::npos);
  CHECK(s.find("-p udp -m multiport --dports 80,443") != std::string::npos);
}

TEST_CASE("build_ipt_script: any proto + src_port expands to tcp and udp rules") {
  ProtoPortFilter f;
  f.proto = L4Proto::Any;
  f.src_port = "11111";
  auto s = T::build_ipt_script(false, {mark_rule("myset", false, 0x100, f)});
  CHECK(s.find("-A KeenPbrTable -m set --match-set myset dst -p tcp --sport "
               "11111 -j MARK --set-xmark 0x100/0xffffffff") != std::string::npos);
  CHECK(s.find("-A KeenPbrTable -m set --match-set myset dst -p udp --sport "
               "11111 -j MARK --set-xmark 0x100/0xffffffff") != std::string::npos);
  CHECK(s.find("-A KeenPbrTable -m set --match-set myset dst --sport 11111")
        == std::string::npos);
}

TEST_CASE(
    "build_ipt_script: no proto, no ports → no extra flags (regression)") {
  auto s = T::build_ipt_script(false, {mark_rule("myset", false, 0x100)});
  CHECK(s.find("-A KeenPbrTable -m set --match-set myset dst -j MARK "
               "--set-xmark 0x100/0xffffffff") != std::string::npos);
  CHECK(s.find("-p ") == std::string::npos);
  CHECK(s.find("--dport") == std::string::npos);
}

// =============================================================================
// build_ipt_script with src_addr / dest_addr tests
// =============================================================================

TEST_CASE("build_ipt_script: single src_addr → -s flag") {
  ProtoPortFilter f;
  f.src_addr = {"192.168.10.0/24"};
  auto s = T::build_ipt_script(false, {mark_rule("myset", false, 0x100, f)});
  CHECK(s.find("-A KeenPbrTable -m set --match-set myset dst -s "
               "192.168.10.0/24 -j MARK --set-xmark 0x100/0xffffffff") !=
        std::string::npos);
}

TEST_CASE("build_ipt_script: single dest_addr → -d flag") {
  ProtoPortFilter f;
  f.dst_addr = {"10.0.0.0/8"};
  auto s = T::build_ipt_script(false, {mark_rule("myset", false, 0x100, f)});
  CHECK(s.find("-A KeenPbrTable -m set --match-set myset dst -d 10.0.0.0/8 -j "
               "MARK --set-xmark 0x100/0xffffffff") != std::string::npos);
}

TEST_CASE("build_ipt_script: src_addr + dest_addr → both flags") {
  ProtoPortFilter f;
  f.src_addr = {"192.168.1.0/24"};
  f.dst_addr = {"8.8.8.0/24"};
  auto s = T::build_ipt_script(false, {mark_rule("myset", false, 0x100, f)});
  CHECK(s.find("-A KeenPbrTable -m set --match-set myset dst -s 192.168.1.0/24 "
               "-d 8.8.8.0/24 -j MARK --set-xmark 0x100/0xffffffff") != std::string::npos);
}

TEST_CASE("build_ipt_script: src_addr + tcp/udp + dest_port → addr and proto "
          "present") {
  ProtoPortFilter f;
  f.src_addr = {"192.168.1.0/24"};
  f.proto = L4Proto::Tcp;
  f.dst_port = "443";
  auto s = T::build_ipt_script(false, {mark_rule("myset", false, 0x100, f)});
  CHECK(s.find("-A KeenPbrTable -m set --match-set myset dst -s 192.168.1.0/24 "
               "-p tcp --dport 443 -j MARK --set-xmark 0x100/0xffffffff") !=
        std::string::npos);
}

TEST_CASE("build_ipt_script: drop rule with src_addr → -s flag on DROP") {
  ProtoPortFilter f;
  f.src_addr = {"10.10.0.0/16"};
  auto s = T::build_ipt_script(false, {drop_rule("bl", false, f)});
  CHECK(s.find("-A KeenPbrTable -m set --match-set bl dst -s 10.10.0.0/16 -j "
               "DROP") != std::string::npos);
}

// =============================================================================
// build_proto_port_fragment negation tests
// =============================================================================

TEST_CASE(
    "build_proto_port_fragment: negated dest_port (single) → ! --dport 443") {
  auto frag = T::build_proto_port_fragment("tcp", "", "443", false, true);
  CHECK(frag == " -p tcp ! --dport 443");
}

TEST_CASE(
    "build_proto_port_fragment: negated port range → ! --dport 8000:9000") {
  auto frag = T::build_proto_port_fragment("udp", "", "8000-9000", false, true);
  CHECK(frag == " -p udp ! --dport 8000:9000");
}

TEST_CASE("build_proto_port_fragment: negated multiport list → -m multiport ! "
          "--dports 80,443") {
  auto frag = T::build_proto_port_fragment("tcp", "", "80,443", false, true);
  CHECK(frag == " -p tcp -m multiport ! --dports 80,443");
}

TEST_CASE("build_proto_port_fragment: negated src_port only → ! --sport 1024") {
  auto frag = T::build_proto_port_fragment("tcp", "1024", "", true, false);
  CHECK(frag == " -p tcp ! --sport 1024");
}

TEST_CASE(
    "build_proto_port_fragment: both ports negated → sport and dport") {
  auto frag =
      T::build_proto_port_fragment("tcp", "1024-65535", "80", true, true);
  CHECK(frag == " -p tcp ! --sport 1024:65535 ! --dport 80");
}

TEST_CASE(
    "build_proto_port_fragment: mixed negation → sport and dport") {
  auto frag = T::build_proto_port_fragment("tcp", "1024", "443", true, false);
  CHECK(frag == " -p tcp ! --sport 1024 --dport 443");
}

// =============================================================================
// build_ipt_script negation tests
// =============================================================================

TEST_CASE("build_ipt_script: negated src_addr → ! -s flag") {
  ProtoPortFilter f;
  f.src_addr = {"192.168.1.0/24"};
  f.negate_src_addr = true;
  auto s = T::build_ipt_script(false, {mark_rule("myset", false, 0x100, f)});
  CHECK(s.find("-A KeenPbrTable -m set --match-set myset dst ! -s "
               "192.168.1.0/24 -j MARK --set-xmark 0x100/0xffffffff") != std::string::npos);
}

TEST_CASE("build_ipt_script: negated dest_addr → ! -d flag") {
  ProtoPortFilter f;
  f.dst_addr = {"10.0.0.0/8"};
  f.negate_dst_addr = true;
  auto s = T::build_ipt_script(false, {mark_rule("myset", false, 0x100, f)});
  CHECK(s.find("-A KeenPbrTable -m set --match-set myset dst ! -d 10.0.0.0/8 "
               "-j MARK --set-xmark 0x100/0xffffffff") != std::string::npos);
}

TEST_CASE("build_ipt_script: negated dest_port in full rule") {
  ProtoPortFilter f;
  f.proto = L4Proto::Tcp;
  f.dst_port = "443";
  f.negate_dst_port = true;
  auto s = T::build_ipt_script(false, {mark_rule("myset", false, 0x100, f)});
  CHECK(s.find("-A KeenPbrTable -m set --match-set myset dst -p tcp ! --dport "
               "443 -j MARK --set-xmark 0x100/0xffffffff") != std::string::npos);
}

TEST_CASE("build_ipt_script: combined negated src_addr + negated dest_port") {
  ProtoPortFilter f;
  f.src_addr = {"192.168.1.0/24"};
  f.negate_src_addr = true;
  f.proto = L4Proto::Tcp;
  f.dst_port = "443";
  f.negate_dst_port = true;
  auto s = T::build_ipt_script(false, {mark_rule("myset", false, 0x100, f)});
  CHECK(
      s.find("-A KeenPbrTable -m set --match-set myset dst ! -s 192.168.1.0/24 "
             "-p tcp ! --dport 443 -j MARK --set-xmark 0x100/0xffffffff") !=
      std::string::npos);
}

TEST_CASE("build_ipt_script: drop rule with negated src_addr") {
  ProtoPortFilter f;
  f.src_addr = {"10.10.0.0/16"};
  f.negate_src_addr = true;
  auto s = T::build_ipt_script(false, {drop_rule("bl", false, f)});
  CHECK(s.find("-A KeenPbrTable -m set --match-set bl dst ! -s 10.10.0.0/16 -j "
               "DROP") != std::string::npos);
}

// =============================================================================
// Multiple CIDR / port negation tests
// (expand_and_push emits one rule per CIDR; each carries the shared negate
// flag)
// =============================================================================

TEST_CASE(
    "build_ipt_script: two negated src_addrs → two rules each with ! -s") {
  // Simulate what expand_and_push produces for negate_src_addr + two CIDRs
  ProtoPortFilter f1;
  f1.src_addr = {"192.168.1.0/24"};
  f1.negate_src_addr = true;
  ProtoPortFilter f2;
  f2.src_addr = {"10.0.0.0/8"};
  f2.negate_src_addr = true;
  auto s = T::build_ipt_script(false, {mark_rule("myset", false, 0x100, f1),
                                       mark_rule("myset", false, 0x100, f2)});
  CHECK(s.find("! -s 192.168.1.0/24") != std::string::npos);
  CHECK(s.find("! -s 10.0.0.0/8") != std::string::npos);
  // Both are mark rules
  CHECK(s.find("! -s 192.168.1.0/24 -j MARK") != std::string::npos);
  CHECK(s.find("! -s 10.0.0.0/8 -j MARK") != std::string::npos);
}

TEST_CASE(
    "build_ipt_script: two negated dst_addrs → two rules each with ! -d") {
  ProtoPortFilter f1;
  f1.dst_addr = {"8.8.8.0/24"};
  f1.negate_dst_addr = true;
  ProtoPortFilter f2;
  f2.dst_addr = {"1.1.1.0/24"};
  f2.negate_dst_addr = true;
  auto s = T::build_ipt_script(
      false, {drop_rule("bl", false, f1), drop_rule("bl", false, f2)});
  CHECK(s.find("! -d 8.8.8.0/24") != std::string::npos);
  CHECK(s.find("! -d 1.1.1.0/24") != std::string::npos);
}

TEST_CASE("build_proto_port_fragment: negated src port list → -m multiport ! "
          "--sports 80,8080") {
  auto frag = T::build_proto_port_fragment("tcp", "80,8080", "", true, false);
  CHECK(frag == " -p tcp -m multiport ! --sports 80,8080");
}

TEST_CASE(
    "build_proto_port_fragment: negated src port range → ! --sport 8000:9000") {
  auto frag = T::build_proto_port_fragment("tcp", "8000-9000", "", true, false);
  CHECK(frag == " -p tcp ! --sport 8000:9000");
}

// =============================================================================
// Mixed negation documentation tests
// (current design: negation is per-list, determined by the first element)
// =============================================================================

TEST_CASE(
    "build_ipt_script: non-negated and negated src_addrs in separate rules") {
  // A non-negated CIDR and a negated CIDR produce independent rules — each can
  // match different traffic, so there is no contradiction.
  ProtoPortFilter fpos;
  fpos.src_addr = {"172.16.0.0/12"};
  ProtoPortFilter fneg;
  fneg.src_addr = {"10.0.0.0/8"};
  fneg.negate_src_addr = true;
  auto s = T::build_ipt_script(false, {mark_rule("myset", false, 0x100, fpos),
                                       mark_rule("myset", false, 0x100, fneg)});
  CHECK(s.find(" -s 172.16.0.0/12") != std::string::npos);
  CHECK(s.find("! -s 10.0.0.0/8") != std::string::npos);
}

// =============================================================================
// Static / dynamic set split tests
// =============================================================================

TEST_CASE("static set naming: kpbr4_ prefix, no timeout") {
  auto line = T::build_ipset_create_line("kpbr4_mylist", "inet", 0);
  CHECK(line == "create kpbr4_mylist hash:net family inet -exist\n");
}

TEST_CASE("dynamic set naming: kpbr4d_ prefix, no timeout when ttl_ms=0") {
  auto line = T::build_ipset_create_line("kpbr4d_mylist", "inet", 0);
  CHECK(line == "create kpbr4d_mylist hash:net family inet -exist\n");
}

TEST_CASE("dynamic set naming: kpbr4d_ prefix, with timeout when ttl_ms set") {
  auto line = T::build_ipset_create_line("kpbr4d_mylist", "inet", 3600);
  CHECK(line == "create kpbr4d_mylist hash:net family inet timeout 3600 -exist\n");
}

TEST_CASE("dynamic set naming: kpbr6d_ IPv6 with timeout") {
  auto line = T::build_ipset_create_line("kpbr6d_mylist", "inet6", 86400);
  CHECK(line == "create kpbr6d_mylist hash:net family inet6 timeout 86400 -exist\n");
}

TEST_CASE("dual-set mark rules: static and dynamic sets fold into one list:set rule") {
  // kpbr4_ and kpbr4d_ share a family/verb/fwmark/selector, so consolidation
  // collapses them into a single list:set-backed mark rule.
  auto s = T::build_ipt_script(false, {mark_rule("kpbr4_mylist", false, 0x100),
                                       mark_rule("kpbr4d_mylist", false, 0x100)});
  CHECK(s.find("--match-set kpbrm_0 dst -j MARK --set-xmark 0x100/0xffffffff") != std::string::npos);
  CHECK(s.find("--match-set kpbrm_0 dst -j RETURN") != std::string::npos);
  // The per-list sets are no longer referenced directly by the chain rules.
  CHECK(s.find("--match-set kpbr4_mylist") == std::string::npos);
  CHECK(s.find("--match-set kpbr4d_mylist") == std::string::npos);
}

TEST_CASE("dual-set drop rules: static and dynamic sets fold into one list:set rule") {
  auto s = T::build_ipt_script(false, {drop_rule("kpbr4_mylist", false),
                                       drop_rule("kpbr4d_mylist", false)});
  CHECK(s.find("--match-set kpbrm_0 dst -j DROP") != std::string::npos);
  CHECK(s.find("--match-set kpbr4_mylist") == std::string::npos);
  CHECK(s.find("--match-set kpbr4d_mylist") == std::string::npos);
}

TEST_CASE("dual-set IPv6 mark rules: kpbr6_ and kpbr6d_ fold into one list:set rule") {
  auto s = T::build_ipt_script(true, {mark_rule("kpbr6_mylist", true, 0x200),
                                      mark_rule("kpbr6d_mylist", true, 0x200)});
  CHECK(s.find("--match-set kpbrm_0 dst -j MARK --set-xmark 0x200/0xffffffff") != std::string::npos);
  CHECK(s.find("--match-set kpbr6_mylist") == std::string::npos);
  CHECK(s.find("--match-set kpbr6d_mylist") == std::string::npos);
}

// =============================================================================
// list:set consolidation tests
// =============================================================================

TEST_CASE("build_list_set_lines: create + flush + members, sized with headroom") {
  auto s = T::build_list_set_lines("kpbrm_0", {"kpbr4_a", "kpbr4_b"});
  // 2 members -> size 2 + 2/2 + 8 = 11.
  CHECK(s == "create kpbrm_0 list:set size 11 -exist\n"
             "flush kpbrm_0\n"
             "add kpbrm_0 kpbr4_a -exist\n"
             "add kpbrm_0 kpbr4_b -exist\n");
}

TEST_CASE("build_ipt_script: single per-list set is left as a direct rule") {
  // One set in its group: no list:set, the per-list set is matched directly.
  auto s = T::build_ipt_script(false, {mark_rule("kpbr4_only", false, 0x100)});
  CHECK(s.find("--match-set kpbr4_only dst -j MARK --set-xmark 0x100/0xffffffff") !=
        std::string::npos);
  CHECK(s.find("kpbrm_") == std::string::npos);
}

TEST_CASE("build_ipt_script: many lists to one outbound collapse to one rule") {
  std::vector<Rule> rules;
  for (int i = 0; i < 5; ++i) {
    rules.push_back(mark_rule("kpbr4_l" + std::to_string(i), false, 0x100));
  }
  auto s = T::build_ipt_script(false, rules);
  // Exactly one MARK rule (plus its RETURN), against the combined set.
  CHECK(s.find("--match-set kpbrm_0 dst -j MARK --set-xmark 0x100/0xffffffff") !=
        std::string::npos);
  for (int i = 0; i < 5; ++i) {
    CHECK(s.find("--match-set kpbr4_l" + std::to_string(i)) == std::string::npos);
  }
}

TEST_CASE("build_ipt_script: lists to different outbounds get separate combined sets") {
  auto s = T::build_ipt_script(false, {mark_rule("kpbr4_a0", false, 0x100),
                                       mark_rule("kpbr4_a1", false, 0x100),
                                       mark_rule("kpbr4_b0", false, 0x200),
                                       mark_rule("kpbr4_b1", false, 0x200)});
  CHECK(s.find("--match-set kpbrm_0 dst -j MARK --set-xmark 0x100/0xffffffff") !=
        std::string::npos);
  CHECK(s.find("--match-set kpbrm_1 dst -j MARK --set-xmark 0x200/0xffffffff") !=
        std::string::npos);
}

TEST_CASE("build_ipt_script: combined rule order follows first-seen group order") {
  auto s = T::build_ipt_script(false, {mark_rule("kpbr4_a0", false, 0x100),
                                       mark_rule("kpbr4_b0", false, 0x200),
                                       mark_rule("kpbr4_a1", false, 0x100),
                                       mark_rule("kpbr4_b1", false, 0x200)});
  const auto pos0 = s.find("--match-set kpbrm_0");
  const auto pos1 = s.find("--match-set kpbrm_1");
  REQUIRE(pos0 != std::string::npos);
  REQUIRE(pos1 != std::string::npos);
  CHECK(pos0 < pos1);
}

// Helper for direct (no-set) mark rules
static Rule direct_mark_rule(bool ipv6, uint32_t fwmark, ProtoPortFilter filter = {}) {
  Rule r;
  r.set_name = "";
  r.ipv6 = ipv6;
  r.direct = true;
  r.action = Rule::Mark;
  r.fwmark = fwmark;
  r.filter = filter;
  return r;
}

// =============================================================================
// create_direct_mark_rule / build_ipt_script with direct=true tests
// =============================================================================

TEST_CASE("build_ipt_script: direct mark rule IPv4 UDP dst port 53") {
  ProtoPortFilter f;
  f.proto = L4Proto::Udp;
  f.dst_port = "53";
  f.dst_addr = {"10.8.0.1"};
  auto s = T::build_ipt_script(false, {direct_mark_rule(false, 0x10000, f)});
  // Must NOT contain --match-set
  CHECK(s.find("--match-set") == std::string::npos);
  // Must contain dst addr and port
  CHECK(s.find("-d 10.8.0.1") != std::string::npos);
  CHECK(s.find("--dport 53") != std::string::npos);
  CHECK(s.find("-j MARK --set-xmark 0x10000/0xffffffff") != std::string::npos);
}

TEST_CASE("build_ipt_script: direct mark rule IPv4 TCP dst port 53") {
  ProtoPortFilter f;
  f.proto = L4Proto::Tcp;
  f.dst_port = "53";
  f.dst_addr = {"10.8.0.1"};
  auto s = T::build_ipt_script(false, {direct_mark_rule(false, 0x10000, f)});
  CHECK(s.find("--match-set") == std::string::npos);
  CHECK(s.find("-d 10.8.0.1") != std::string::npos);
  CHECK(s.find("-p tcp --dport 53") != std::string::npos);
  CHECK(s.find("-j MARK --set-xmark 0x10000/0xffffffff") != std::string::npos);
}

TEST_CASE("build_ipt_script: direct mark rule has no set_name reference") {
  ProtoPortFilter f;
  f.proto = L4Proto::Udp;
  f.dst_addr = {"192.0.2.1"};
  auto s = T::build_ipt_script(false, {direct_mark_rule(false, 0x20000, f)});
  CHECK(s.find("--match-set") == std::string::npos);
  CHECK(s.find("-d 192.0.2.1") != std::string::npos);
}

namespace {

enum class PairwiseRuleMode {
  ListBacked,
  Direct,
};

enum class PairwiseAction {
  Mark,
  Drop,
  Pass,
};

struct ProtoVariant {
  const char *name;
  L4Proto proto;
};

enum class PortShape {
  Empty,
  Single,
  Multi,
  Range,
};

struct PortVariant {
  const char *name;
  PortShape shape;
  const char *spec;
  const char *iptables_spec;
  bool negated;
};

struct AddrVariant {
  const char *name;
  std::vector<std::string> addrs;
  bool negated;
};

struct PairwiseIptablesCase {
  std::string name;
  PairwiseRuleMode mode;
  PairwiseAction action;
  ProtoVariant proto;
  PortVariant src_port;
  PortVariant dst_port;
  AddrVariant src_addr;
  AddrVariant dst_addr;
};

constexpr std::array<ProtoVariant, 4> kProtoVariants{{
    {"any", L4Proto::Any},
    {"tcp", L4Proto::Tcp},
    {"udp", L4Proto::Udp},
    {"tcp_udp", L4Proto::TcpUdp},
}};

constexpr std::array<PortVariant, 7> kPortVariants{{
    {"empty", PortShape::Empty, "", "", false},
    {"single", PortShape::Single, "443", "443", false},
    {"multi", PortShape::Multi, "80,443", "80,443", false},
    {"range", PortShape::Range, "8000-9000", "8000:9000", false},
    {"neg_single", PortShape::Single, "53", "53", true},
    {"neg_multi", PortShape::Multi, "53,123", "53,123", true},
    {"neg_range", PortShape::Range, "10000-10010", "10000:10010", true},
}};

const std::array<AddrVariant, 5> kAddrVariants{{
    {"empty", {}, false},
    {"single", {"192.0.2.0/24"}, false},
    {"multi", {"192.0.2.0/24", "198.51.100.0/24"}, false},
    {"neg_single", {"203.0.113.0/24"}, true},
    {"neg_multi", {"203.0.113.0/24", "198.18.0.0/15"}, true},
}};

constexpr std::array<const char *, 2> kModeNames{{"list", "direct"}};
constexpr std::array<const char *, 3> kActionNames{{"mark", "drop", "pass"}};

using PairwiseIndex = std::array<size_t, 7>;

size_t selector_count(const PairwiseIptablesCase &tc) {
  size_t count = 0;
  count += tc.src_port.shape != PortShape::Empty ? 1 : 0;
  count += tc.dst_port.shape != PortShape::Empty ? 1 : 0;
  count += tc.src_addr.addrs.empty() ? 0 : 1;
  count += tc.dst_addr.addrs.empty() ? 0 : 1;
  return count;
}

bool has_negated_selector(const PairwiseIptablesCase &tc) {
  return tc.src_port.negated || tc.dst_port.negated || tc.src_addr.negated ||
         tc.dst_addr.negated;
}

bool has_positive_selector(const PairwiseIptablesCase &tc) {
  return (tc.src_port.shape != PortShape::Empty && !tc.src_port.negated) ||
         (tc.dst_port.shape != PortShape::Empty && !tc.dst_port.negated) ||
         (!tc.src_addr.addrs.empty() && !tc.src_addr.negated) ||
         (!tc.dst_addr.addrs.empty() && !tc.dst_addr.negated);
}

std::string pairwise_combo_name(const PairwiseIndex &idx) {
  std::ostringstream os;
  os << kModeNames[idx[0]] << "__" << kActionNames[idx[1]] << "__"
     << kProtoVariants[idx[2]].name << "__srcp_" << kPortVariants[idx[3]].name
     << "__dstp_" << kPortVariants[idx[4]].name << "__srca_"
     << kAddrVariants[idx[5]].name << "__dsta_" << kAddrVariants[idx[6]].name;
  return os.str();
}

FirewallRuleCriteria build_pairwise_filter(const PairwiseIptablesCase &tc) {
  FirewallRuleCriteria filter;
  filter.proto = tc.proto.proto;
  filter.src_port = tc.src_port.spec;
  filter.dst_port = tc.dst_port.spec;
  filter.src_addr = tc.src_addr.addrs;
  filter.dst_addr = tc.dst_addr.addrs;
  filter.negate_src_port = tc.src_port.negated;
  filter.negate_dst_port = tc.dst_port.negated;
  filter.negate_src_addr = tc.src_addr.negated;
  filter.negate_dst_addr = tc.dst_addr.negated;
  return filter;
}

std::string format_fwmark(uint32_t fwmark) {
  std::ostringstream os;
  os << "0x" << std::hex << std::nouppercase << fwmark;
  return os.str();
}

std::vector<L4Proto> expand_proto(L4Proto proto,
                                  const PortVariant &src_port,
                                  const PortVariant &dst_port) {
  if (proto == L4Proto::Any &&
      (src_port.shape != PortShape::Empty || dst_port.shape != PortShape::Empty)) {
    return {L4Proto::Tcp, L4Proto::Udp};
  }
  if (proto == L4Proto::TcpUdp) {
    return {L4Proto::Tcp, L4Proto::Udp};
  }
  return {proto};
}

std::string expected_proto_port_fragment(L4Proto proto,
                                         const PortVariant &src_port,
                                         const PortVariant &dst_port) {
  if (proto == L4Proto::Any && src_port.shape == PortShape::Empty &&
      dst_port.shape == PortShape::Empty) {
    return "";
  }

  std::string frag;
  if (proto != L4Proto::Any) {
    frag += " -p ";
    frag += l4_proto_name(proto);
  }

  const bool has_src = src_port.shape != PortShape::Empty;
  const bool has_dst = dst_port.shape != PortShape::Empty;
  const bool src_list = src_port.shape == PortShape::Multi;
  const bool dst_list = dst_port.shape == PortShape::Multi;

  if (has_src || has_dst) {
    if (src_list || dst_list) {
      if (src_list) {
        frag += " -m multiport";
        if (src_port.negated) frag += " !";
        frag += " --sports ";
        frag += src_port.iptables_spec;
      } else if (has_src) {
        if (src_port.negated) frag += " !";
        frag += " --sport ";
        frag += src_port.iptables_spec;
      }
      if (dst_list) {
        frag += " -m multiport";
        if (dst_port.negated) frag += " !";
        frag += " --dports ";
        frag += dst_port.iptables_spec;
      } else if (has_dst) {
        if (dst_port.negated) frag += " !";
        frag += " --dport ";
        frag += dst_port.iptables_spec;
      }
    } else {
      if (has_src) {
        if (src_port.negated) frag += " !";
        frag += " --sport ";
        frag += src_port.iptables_spec;
      }
      if (has_dst) {
        if (dst_port.negated) frag += " !";
        frag += " --dport ";
        frag += dst_port.iptables_spec;
      }
    }
  }

  return frag;
}

std::vector<std::string> expected_rule_lines(const PairwiseIptablesCase &tc,
                                             uint32_t fwmark) {
  std::vector<std::string> lines;
  const std::vector<std::string> src_addrs =
      tc.src_addr.addrs.empty() ? std::vector<std::string>{""}
                                : tc.src_addr.addrs;
  const std::vector<std::string> dst_addrs =
      tc.dst_addr.addrs.empty() ? std::vector<std::string>{""}
                                : tc.dst_addr.addrs;

  for (L4Proto proto : expand_proto(tc.proto.proto, tc.src_port, tc.dst_port)) {
    const std::string proto_port_frag =
        expected_proto_port_fragment(proto, tc.src_port, tc.dst_port);
    for (const auto &src_addr : src_addrs) {
      for (const auto &dst_addr : dst_addrs) {
        std::string prefix = "-A KeenPbrTable";
        if (tc.mode == PairwiseRuleMode::ListBacked) {
          prefix += " -m set --match-set pairwise_set dst";
        }

        if (!src_addr.empty()) {
          prefix += tc.src_addr.negated ? " ! -s " : " -s ";
          prefix += src_addr;
        }
        if (!dst_addr.empty()) {
          prefix += tc.dst_addr.negated ? " ! -d " : " -d ";
          prefix += dst_addr;
        }

        prefix += proto_port_frag;

        if (tc.action == PairwiseAction::Mark) {
          lines.push_back("[0:0] " + prefix + " -j MARK --set-xmark " + format_fwmark(fwmark) +
                          "/0xffffffff" +
                          "\n");
          lines.push_back(prefix + " -j RETURN\n");
        } else if (tc.action == PairwiseAction::Drop) {
          lines.push_back(prefix + " -j DROP\n");
        } else {
          lines.push_back(prefix + " -j RETURN\n");
        }
      }
    }
  }

  return lines;
}

std::vector<std::string> extract_rule_lines(const std::string &script) {
  std::vector<std::string> lines;
  std::istringstream input(script);
  std::string line;
  while (std::getline(input, line)) {
    if (line.rfind("-A KeenPbrTable", 0) == 0) {
      lines.push_back(line + "\n");
    }
  }
  return lines;
}

std::set<std::string> build_uncovered_pairs() {
  const std::array<size_t, 7> axis_sizes{
      kModeNames.size(),      kActionNames.size(), kProtoVariants.size(),
      kPortVariants.size(),   kPortVariants.size(), kAddrVariants.size(),
      kAddrVariants.size(),
  };

  std::set<std::string> uncovered;
  for (size_t a = 0; a < axis_sizes.size(); ++a) {
    for (size_t b = a + 1; b < axis_sizes.size(); ++b) {
      for (size_t va = 0; va < axis_sizes[a]; ++va) {
        for (size_t vb = 0; vb < axis_sizes[b]; ++vb) {
          uncovered.insert(std::to_string(a) + ":" + std::to_string(va) + "|" +
                           std::to_string(b) + ":" + std::to_string(vb));
        }
      }
    }
  }
  return uncovered;
}

std::vector<std::string> coverage_keys(const PairwiseIndex &idx) {
  std::vector<std::string> keys;
  for (size_t a = 0; a < idx.size(); ++a) {
    for (size_t b = a + 1; b < idx.size(); ++b) {
      keys.push_back(std::to_string(a) + ":" + std::to_string(idx[a]) + "|" +
                     std::to_string(b) + ":" + std::to_string(idx[b]));
    }
  }
  return keys;
}

std::vector<PairwiseIndex> generate_pairwise_indices() {
  std::vector<PairwiseIndex> all_combos;
  for (size_t mode = 0; mode < kModeNames.size(); ++mode) {
    for (size_t action = 0; action < kActionNames.size(); ++action) {
      for (size_t proto = 0; proto < kProtoVariants.size(); ++proto) {
        for (size_t src_port = 0; src_port < kPortVariants.size(); ++src_port) {
          for (size_t dst_port = 0; dst_port < kPortVariants.size(); ++dst_port) {
            for (size_t src_addr = 0; src_addr < kAddrVariants.size(); ++src_addr) {
              for (size_t dst_addr = 0; dst_addr < kAddrVariants.size(); ++dst_addr) {
                all_combos.push_back(
                    {mode, action, proto, src_port, dst_port, src_addr, dst_addr});
              }
            }
          }
        }
      }
    }
  }

  std::set<std::string> uncovered = build_uncovered_pairs();
  std::vector<PairwiseIndex> selected;
  std::set<std::string> seen;

  const std::vector<PairwiseIndex> seeds{
      {0, 0, 1, 0, 1, 0, 0},
      {1, 1, 2, 0, 3, 1, 0},
      {0, 2, 3, 5, 1, 3, 2},
      {1, 0, 1, 4, 2, 3, 1},
  };

  auto add_combo = [&](const PairwiseIndex &combo) {
    const std::string key = pairwise_combo_name(combo);
    if (!seen.insert(key).second) {
      return;
    }
    selected.push_back(combo);
    for (const auto &coverage : coverage_keys(combo)) {
      uncovered.erase(coverage);
    }
  };

  for (const auto &seed : seeds) {
    add_combo(seed);
  }

  while (!uncovered.empty()) {
    size_t best_score = 0;
    size_t best_index = 0;
    for (size_t i = 0; i < all_combos.size(); ++i) {
      if (seen.count(pairwise_combo_name(all_combos[i])) != 0) {
        continue;
      }
      size_t score = 0;
      for (const auto &coverage : coverage_keys(all_combos[i])) {
        score += uncovered.count(coverage);
      }
      if (score > best_score) {
        best_score = score;
        best_index = i;
      }
    }
    add_combo(all_combos[best_index]);
  }

  return selected;
}

std::vector<PairwiseIptablesCase> generate_pairwise_cases() {
  std::vector<PairwiseIptablesCase> cases;
  for (const auto &idx : generate_pairwise_indices()) {
    cases.push_back({
        pairwise_combo_name(idx),
        idx[0] == 0 ? PairwiseRuleMode::ListBacked : PairwiseRuleMode::Direct,
        idx[1] == 0 ? PairwiseAction::Mark
                    : (idx[1] == 1 ? PairwiseAction::Drop : PairwiseAction::Pass),
        kProtoVariants[idx[2]],
        kPortVariants[idx[3]],
        kPortVariants[idx[4]],
        kAddrVariants[idx[5]],
        kAddrVariants[idx[6]],
    });
  }
  return cases;
}

bool pairwise_is_complete(const std::vector<PairwiseIndex> &cases) {
  std::set<std::string> uncovered = build_uncovered_pairs();
  for (const auto &combo : cases) {
    for (const auto &coverage : coverage_keys(combo)) {
      uncovered.erase(coverage);
    }
  }
  return uncovered.empty();
}

} // namespace

// =============================================================================
// RulesOnly: live set preflight and in-place chain rebuild
// =============================================================================

namespace {

const char* kTerseListing =
    "Name: kpbr4_static\n"
    "Type: hash:net\n"
    "Revision: 6\n"
    "Header: family inet hashsize 1024 maxelem 65536\n"
    "Size in memory: 1048\n"
    "References: 1\n"
    "Number of entries: 12\n"
    "\n"
    "Name: kpbr4d_domains\n"
    "Type: hash:net\n"
    "Revision: 6\n"
    "Header: family inet hashsize 1024 maxelem 65536 timeout 600 bucketsize 12 initval 0x5a1d\n"
    "Size in memory: 2024\n"
    "References: 1\n"
    "Number of entries: 3\n"
    "\n"
    "Name: kpbr6_static\n"
    "Type: hash:net\n"
    "Revision: 6\n"
    "Header: family inet6 hashsize 1024 maxelem 65536\n"
    "Number of entries: 0\n"
    "\n"
    "Name: kpbrm_0\n"
    "Type: list:set\n"
    "Revision: 3\n"
    "Header: size 11\n"
    "Number of entries: 2\n"
    "\n"
    "Name: _NDM_BFD_TMP\n"
    "Type: hash:ip\n"
    "Header: family inet hashsize 1024 maxelem 65536 timeout 300\n";

} // namespace

TEST_CASE("parse_ipset_terse_listing: names, types, families, timeouts and entries") {
  const auto sets = T::parse_terse(kTerseListing);
  REQUIRE(sets.size() == 5);
  CHECK(sets.at("kpbr4_static").type == "hash:net");
  CHECK(sets.at("kpbr4_static").family == "inet");
  CHECK_FALSE(sets.at("kpbr4_static").timeout.has_value());
  CHECK(sets.at("kpbr4_static").entries == std::optional<size_t>{12});
  CHECK(sets.at("kpbr4d_domains").timeout == std::optional<uint32_t>{600});
  CHECK(sets.at("kpbr6_static").family == "inet6");
  CHECK(sets.at("kpbrm_0").type == "list:set");
  CHECK(sets.at("kpbrm_0").entries == std::optional<size_t>{2});
  CHECK(sets.at("_NDM_BFD_TMP").type == "hash:ip");
}

TEST_CASE("live_hash_set_mismatch: only the expected layout may be reused") {
  CHECK_FALSE(T::hash_set_mismatch(kTerseListing, "kpbr4_static", "inet", 0).has_value());
  CHECK_FALSE(T::hash_set_mismatch(kTerseListing, "kpbr4d_domains", "inet", 600).has_value());
  CHECK_FALSE(T::hash_set_mismatch(kTerseListing, "kpbr6_static", "inet6", 0).has_value());

  CHECK(T::hash_set_mismatch(kTerseListing, "kpbr4_gone", "inet", 0).has_value());
  CHECK(T::hash_set_mismatch(kTerseListing, "kpbr4d_domains", "inet", 300).has_value());
  CHECK(T::hash_set_mismatch(kTerseListing, "kpbr4_static", "inet", 600).has_value());
  CHECK(T::hash_set_mismatch(kTerseListing, "kpbr6_static", "inet", 0).has_value());
  CHECK(T::hash_set_mismatch(kTerseListing, "kpbrm_0", "inet", 0).has_value());
}

TEST_CASE("build_ipt_script: rules-only rebuild keeps an existing PREROUTING jump") {
  const auto with_jump = T::build_ipt_script(false, {mark_rule("kpbr4_a", false, 0x10000)});
  const auto without_jump =
      T::build_ipt_script(false, {mark_rule("kpbr4_a", false, 0x10000)}, {}, false);

  CHECK(with_jump.find("-A PREROUTING -j KeenPbrTable\n") != std::string::npos);
  CHECK(without_jump.find("PREROUTING") == std::string::npos);
  // The chain is still declared, so --noflush flushes and refills it in the
  // same transaction.
  CHECK(without_jump.rfind("*mangle\n:KeenPbrTable - [0:0]\n", 0) == 0);
  CHECK(without_jump.find("--match-set kpbr4_a dst") != std::string::npos);
  CHECK(without_jump.find("COMMIT\n") != std::string::npos);
}

TEST_CASE("plan_dynamic_sets: keep fitting dnsmasq sets, recreate changed ones") {
  const std::string listing = std::string(kTerseListing) +
      "\n"
      "Name: kpbr4d_old_ttl\n"
      "Type: hash:net\n"
      "Header: family inet hashsize 1024 maxelem 65536 timeout 86400\n"
      "\n"
      "Name: kpbr6d_domains\n"
      "Type: hash:net\n"
      "Header: family inet6 hashsize 1024 maxelem 65536 timeout 600\n";

  const auto plan = T::plan_dynamic_sets(listing,
                                         {
                                             {"kpbr4d_domains", "inet", 600},
                                             {"kpbr4d_old_ttl", "inet", 600},
                                             {"kpbr4d_new_list", "inet", 600},
                                             {"kpbr4_static", "inet", 0},
                                             {"kpbr6d_domains", "inet6", 600},
                                         },
                                         true);
  CHECK(plan.keep == std::set<std::string>{"kpbr4d_domains", "kpbr6d_domains"});
  CHECK(plan.destroy == std::set<std::string>{"kpbr4d_old_ttl"});

  // With IPv6 off the v6 dynamic set is not reused.
  const auto v4_only = T::plan_dynamic_sets(listing, {{"kpbr6d_domains", "inet6", 600}}, false);
  CHECK(v4_only.keep.empty());
  CHECK(v4_only.destroy.empty());
}

// =============================================================================
// Negated address lists ("!a,b")
// =============================================================================

namespace {

size_t count_occurrences(const std::string &haystack, const std::string &needle) {
  size_t count = 0;
  for (size_t pos = haystack.find(needle); pos != std::string::npos;
       pos = haystack.find(needle, pos + needle.size())) {
    ++count;
  }
  return count;
}

} // namespace

TEST_CASE("negated_address_set_name: content-addressed, order-insensitive, per family") {
  const auto name = negated_address_set_name(false, {"10.0.0.0/8", "192.168.1.1/32"});
  CHECK(name.rfind("kpbr4n_", 0) == 0);
  CHECK(name.size() == std::string("kpbr4n_").size() + 16);
  CHECK(name.size() <= 31);  // ipset name limit
  CHECK(name == negated_address_set_name(false, {"192.168.1.1", "10.0.0.0/8"}));
  CHECK(name != negated_address_set_name(false, {"10.0.0.0/8"}));
  CHECK(negated_address_set_name(true, {"2001:db8::/32", "fd00::/8"}).rfind("kpbr6n_", 0) == 0);
  CHECK(is_negated_address_set_name(name));
  CHECK_FALSE(is_negated_address_set_name("kpbr4_list"));
  CHECK_FALSE(needs_negated_address_set(true, {"10.0.0.0/8"}));
  CHECK_FALSE(needs_negated_address_set(false, {"10.0.0.0/8", "10.1.0.0/16"}));
  CHECK(needs_negated_address_set(true, {"10.0.0.0/8", "10.1.0.0/16"}));
}

TEST_CASE("build_ipt_script_for_rule: negated dest_addr list is one rule on a set, not N rules") {
  FirewallRuleCriteria criteria;
  criteria.dst_addr = {"10.0.0.0/8", "192.168.0.0/16"};
  criteria.negate_dst_addr = true;
  const auto s = T::build_ipt_script_for_rule(false, Rule::Mark, 0x100, criteria, true);

  const std::string set_name =
      negated_address_set_name(false, {"10.0.0.0/8", "192.168.0.0/16"});
  // N `! -d` rules OR together and match everything: none of them here.
  CHECK(s.find("! -d") == std::string::npos);
  CHECK(count_occurrences(s, "-j MARK") == 1);
  CHECK(s.find("-m set --match-set pairwise_set dst -m set ! --match-set " + set_name +
               " dst -j MARK --set-xmark 0x100/0xffffffff") != std::string::npos);
}

TEST_CASE("build_ipt_script_for_rule: negated src_addr list and single negations") {
  FirewallRuleCriteria multi;
  multi.src_addr = {"192.168.1.0/24", "192.168.2.0/24"};
  multi.negate_src_addr = true;
  const auto s = T::build_ipt_script_for_rule(false, Rule::Drop, 0, multi, false);
  CHECK(s.find("-m set ! --match-set " +
               negated_address_set_name(false, multi.src_addr) + " src -j DROP") !=
        std::string::npos);
  CHECK(s.find("! -s") == std::string::npos);

  // One negated address keeps the plain form.
  FirewallRuleCriteria single;
  single.dst_addr = {"10.0.0.0/8"};
  single.negate_dst_addr = true;
  const auto plain = T::build_ipt_script_for_rule(false, Rule::Mark, 0x100, single, true);
  CHECK(plain.find("! -d 10.0.0.0/8") != std::string::npos);
  CHECK(plain.find("kpbr4n_") == std::string::npos);

  // A positive list still ORs one rule per address.
  FirewallRuleCriteria positive;
  positive.dst_addr = {"10.0.0.0/8", "192.168.0.0/16"};
  const auto ored = T::build_ipt_script_for_rule(false, Rule::Mark, 0x100, positive, true);
  CHECK(ored.find(" -d 10.0.0.0/8") != std::string::npos);
  CHECK(ored.find(" -d 192.168.0.0/16") != std::string::npos);
  CHECK(ored.find("kpbr4n_") == std::string::npos);
}

TEST_CASE("negated address set: declared once with its entries, per family") {
  FirewallRuleCriteria criteria;
  criteria.dst_addr = {"10.0.0.0/8", "0.0.0.0/0", "2001:db8::/32"};
  criteria.negate_dst_addr = true;
  // Two list sets sharing the selector: consolidation folds them into one
  // list:set rule, and the negated set is declared once.
  const auto [script, set_lines] = T::build_marked_list_rules(
      false, 0x100, {{"kpbr4_a", criteria}, {"kpbr4_b", criteria}});

  const std::string set_name = negated_address_set_name(false, {"10.0.0.0/8", "0.0.0.0/0"});
  CHECK(count_occurrences(set_lines, "create " + set_name + " hash:net family inet -exist\n") == 1);
  CHECK(set_lines.find("add " + set_name + " 10.0.0.0/8 -exist\n") != std::string::npos);
  // The /0 entry is split like in any list; the IPv6 address is not in the v4 set.
  CHECK(set_lines.find("add " + set_name + " 0.0.0.0/1 -exist\n") != std::string::npos);
  CHECK(set_lines.find("2001:db8") == std::string::npos);
  CHECK(count_occurrences(script, "-j MARK") == 1);
  CHECK(script.find("--match-set kpbrm_0 dst -m set ! --match-set " + set_name + " dst") !=
        std::string::npos);
}
