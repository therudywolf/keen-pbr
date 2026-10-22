#include <doctest/doctest.h>

#include "../src/cache/cache_manager.hpp"
#include "../src/firewall/firewall_runtime.hpp"
#include "../src/lists/list_entry_visitor.hpp"

#include <map>
#include <memory>
#include <string>
#include <sys/socket.h>
#include <vector>

using namespace keen_pbr3;

namespace {

// Records what apply_runtime_firewall asks the backend for, without touching
// the kernel.
class RecordingFirewall : public Firewall {
public:
    struct Rule {
        uint32_t fwmark{0};
        std::string set_name;
    };

    void create_ipset(const std::string& set_name, int family, uint32_t timeout) override {
        sets.push_back(set_name);
        set_family[set_name] = family;
        set_timeout[set_name] = timeout;
    }

    void create_mark_rule(uint32_t fwmark, const FirewallRuleCriteria& criteria) override {
        rules.push_back(Rule{fwmark, criteria.dst_set_name.value_or("")});
    }

    void create_drop_rule(const FirewallRuleCriteria& criteria) override {
        rules.push_back(Rule{0, criteria.dst_set_name.value_or("")});
    }

    void create_pass_rule(const FirewallRuleCriteria& criteria) override {
        rules.push_back(Rule{0, criteria.dst_set_name.value_or("")});
    }

    std::unique_ptr<ListEntryVisitor> create_batch_loader(const std::string& set_name) override {
        ++loaders[set_name];
        return std::make_unique<FunctionalVisitor>(
            [this, set_name](EntryType, std::string_view entry) {
                entries[set_name].emplace_back(entry);
            });
    }

    void apply(FirewallApplyMode mode) override {
        applied_modes.push_back(mode);
    }

    void cleanup() override {}

    FirewallBackend backend() const override { return FirewallBackend::iptables; }

    std::vector<std::string> sets;
    std::map<std::string, int> set_family;
    std::map<std::string, uint32_t> set_timeout;
    std::vector<Rule> rules;
    std::map<std::string, int> loaders;
    std::map<std::string, std::vector<std::string>> entries;
    std::vector<FirewallApplyMode> applied_modes;
};

Outbound interface_outbound(const std::string& tag, const std::string& iface) {
    Outbound outbound;
    outbound.tag = tag;
    outbound.type = OutboundType::INTERFACE;
    outbound.interface = iface;
    return outbound;
}

RouteRule route_rule(std::vector<std::string> lists, const std::string& outbound) {
    RouteRule rule;
    rule.list = std::move(lists);
    rule.outbound = outbound;
    return rule;
}

// Two rules to two outbounds, both referencing the "shared" list; IPv6 off so
// only the v4 sets show up.
Config shared_list_config() {
    Config config;
    DaemonConfig daemon;
    daemon.ipv6_enabled = false;
    config.daemon = daemon;
    config.outbounds = std::vector<Outbound>{
        interface_outbound("vpn", "nwg3"),
        interface_outbound("isp", "ppp0"),
    };

    ListConfig shared;
    shared.ip_cidrs = std::vector<std::string>{"10.1.0.0/16", "192.0.2.7"};
    shared.domains = std::vector<std::string>{"example.com"};
    shared.ttl_ms = 600000;
    ListConfig only_vpn;
    only_vpn.ip_cidrs = std::vector<std::string>{"198.51.100.0/24"};
    config.lists = std::map<std::string, ListConfig>{
        {"shared", shared},
        {"only_vpn", only_vpn},
    };

    RouteConfig route;
    route.rules = std::vector<RouteRule>{
        route_rule({"shared", "only_vpn"}, "vpn"),
        route_rule({"shared"}, "isp"),
    };
    config.route = route;
    return config;
}

int count_of(const std::vector<std::string>& values, const std::string& value) {
    int count = 0;
    for (const auto& v : values) {
        if (v == value) {
            ++count;
        }
    }
    return count;
}

} // namespace

TEST_CASE("apply_runtime_firewall: a list shared by two rules is streamed into its sets once") {
    const Config config = shared_list_config();
    const auto marks = allocate_outbound_marks(FwmarkConfig{}, *config.outbounds);
    CacheManager cache("/nonexistent/cache");
    RecordingFirewall firewall;

    const auto states = apply_runtime_firewall(
        config, marks, {}, cache, firewall, FirewallApplyMode::Destructive);

    // Declared once, loaded once, entries not duplicated.
    CHECK(count_of(firewall.sets, "kpbr4_shared") == 1);
    CHECK(count_of(firewall.sets, "kpbr4d_shared") == 1);
    CHECK(firewall.loaders["kpbr4_shared"] == 1);
    CHECK(firewall.entries["kpbr4_shared"] ==
          std::vector<std::string>{"10.1.0.0/16", "192.0.2.7"});
    CHECK(firewall.set_timeout["kpbr4d_shared"] == 600);

    // ...but both rules still match it, each with its own mark.
    REQUIRE(states.size() == 2);
    CHECK(states[0].set_names ==
          std::vector<std::string>{"kpbr4_shared", "kpbr4d_shared", "kpbr4_only_vpn"});
    CHECK(states[1].set_names == std::vector<std::string>{"kpbr4_shared", "kpbr4d_shared"});
    int shared_rules = 0;
    for (const auto& rule : firewall.rules) {
        if (rule.set_name == "kpbr4_shared") {
            ++shared_rules;
        }
    }
    CHECK(shared_rules == 2);
    CHECK(firewall.applied_modes == std::vector<FirewallApplyMode>{FirewallApplyMode::Destructive});
}
