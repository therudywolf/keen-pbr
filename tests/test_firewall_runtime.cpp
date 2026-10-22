#include <doctest/doctest.h>

#include "../src/cache/cache_manager.hpp"
#include "../src/firewall/firewall_runtime.hpp"
#include "../src/lists/list_entry_visitor.hpp"
#include "../src/log/logger.hpp"

#include <cstdlib>
#include <filesystem>
#include <fstream>
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
        clear_dynamic_sets_seen.push_back(clear_dynamic_sets_on_apply());
        if (mode == FirewallApplyMode::RulesOnly && refuse_rules_only) {
            throw FirewallRulesOnlyError("set kpbr4_shared is missing");
        }
    }

    void reset_records() {
        sets.clear();
        rules.clear();
        loaders.clear();
        entries.clear();
        applied_modes.clear();
    }

    bool refuse_rules_only{false};
    std::vector<bool> clear_dynamic_sets_seen;

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

TEST_CASE("apply_runtime_firewall: RulesOnly reuses the recorded set layout without streaming") {
    const Config config = shared_list_config();
    const auto marks = allocate_outbound_marks(FwmarkConfig{}, *config.outbounds);
    CacheManager cache("/nonexistent/cache");
    RecordingFirewall firewall;
    FirewallSetCache set_cache;

    const auto full = apply_runtime_firewall(
        config, marks, {}, cache, firewall, FirewallApplyMode::Destructive, &set_cache);
    CHECK(set_cache.valid);
    firewall.reset_records();

    const auto refreshed = apply_runtime_firewall(
        config, marks, {}, cache, firewall, FirewallApplyMode::RulesOnly, &set_cache);

    CHECK(firewall.applied_modes == std::vector<FirewallApplyMode>{FirewallApplyMode::RulesOnly});
    CHECK(firewall.loaders.empty());
    CHECK(firewall.entries.empty());
    // The sets are still declared, so the backend can check them.
    CHECK(count_of(firewall.sets, "kpbr4_shared") == 1);
    CHECK(count_of(firewall.sets, "kpbr4d_shared") == 1);
    REQUIRE(refreshed.size() == full.size());
    for (size_t i = 0; i < full.size(); ++i) {
        CHECK(refreshed[i].set_names == full[i].set_names);
        CHECK(refreshed[i].fwmark == full[i].fwmark);
    }
    CHECK(set_cache.valid);
}

TEST_CASE("apply_runtime_firewall: RulesOnly without a recorded layout reloads the sets") {
    const Config config = shared_list_config();
    const auto marks = allocate_outbound_marks(FwmarkConfig{}, *config.outbounds);
    CacheManager cache("/nonexistent/cache");
    RecordingFirewall firewall;
    FirewallSetCache set_cache;

    (void)apply_runtime_firewall(
        config, marks, {}, cache, firewall, FirewallApplyMode::RulesOnly, &set_cache);

    CHECK(firewall.applied_modes == std::vector<FirewallApplyMode>{FirewallApplyMode::PreserveSets});
    CHECK(firewall.loaders["kpbr4_shared"] == 1);
    // The full apply recorded the layout for the next refresh.
    CHECK(set_cache.valid);
}

TEST_CASE("apply_runtime_firewall: RulesOnly after a list change reloads the sets") {
    Config config = shared_list_config();
    const auto marks = allocate_outbound_marks(FwmarkConfig{}, *config.outbounds);
    CacheManager cache("/nonexistent/cache");
    RecordingFirewall firewall;
    FirewallSetCache set_cache;
    (void)apply_runtime_firewall(
        config, marks, {}, cache, firewall, FirewallApplyMode::Destructive, &set_cache);
    firewall.reset_records();

    config.lists->at("only_vpn").ip_cidrs = std::vector<std::string>{"203.0.113.0/24"};
    (void)apply_runtime_firewall(
        config, marks, {}, cache, firewall, FirewallApplyMode::RulesOnly, &set_cache);

    CHECK(firewall.applied_modes == std::vector<FirewallApplyMode>{FirewallApplyMode::PreserveSets});
    CHECK(firewall.entries["kpbr4_only_vpn"] == std::vector<std::string>{"203.0.113.0/24"});
}

TEST_CASE("apply_runtime_firewall: a backend refusing RulesOnly gets a full PreserveSets apply") {
    const Config config = shared_list_config();
    const auto marks = allocate_outbound_marks(FwmarkConfig{}, *config.outbounds);
    CacheManager cache("/nonexistent/cache");
    RecordingFirewall firewall;
    FirewallSetCache set_cache;
    (void)apply_runtime_firewall(
        config, marks, {}, cache, firewall, FirewallApplyMode::Destructive, &set_cache);
    firewall.reset_records();
    firewall.refuse_rules_only = true;

    const auto states = apply_runtime_firewall(
        config, marks, {}, cache, firewall, FirewallApplyMode::RulesOnly, &set_cache);

    CHECK(firewall.applied_modes == std::vector<FirewallApplyMode>{
                                        FirewallApplyMode::RulesOnly,
                                        FirewallApplyMode::PreserveSets});
    CHECK(firewall.loaders["kpbr4_shared"] == 1);
    CHECK(states.size() == 2);
}

TEST_CASE("firewall_set_fingerprint: follows list contents, file stamps and IPv6") {
    char dir_template[] = "/tmp/forest-pbr-fw-runtime-XXXXXX";
    REQUIRE(mkdtemp(dir_template) != nullptr);
    const std::filesystem::path dir(dir_template);
    const auto list_file = dir / "local.txt";
    {
        std::ofstream out(list_file);
        out << "10.9.0.0/16\n";
    }

    Config config = shared_list_config();
    ListConfig local;
    local.file = list_file.string();
    config.lists->emplace("local", local);
    config.route->rules->push_back(route_rule({"local"}, "vpn"));
    CacheManager cache("/nonexistent/cache");

    const auto base = firewall_set_fingerprint(config, cache, false);
    CHECK(base == firewall_set_fingerprint(config, cache, false));
    CHECK(base != firewall_set_fingerprint(config, cache, true));

    // Editing the local file changes the static set contents.
    {
        std::ofstream out(list_file, std::ios::app);
        out << "10.10.0.0/16\n";
    }
    CHECK(base != firewall_set_fingerprint(config, cache, false));

    // A list no enabled rule references does not matter.
    const auto with_file_change = firewall_set_fingerprint(config, cache, false);
    ListConfig unused;
    unused.ip_cidrs = std::vector<std::string>{"192.0.2.0/24"};
    config.lists->emplace("unused", unused);
    CHECK(with_file_change == firewall_set_fingerprint(config, cache, false));

    std::filesystem::remove_all(dir);
}

TEST_CASE("apply_runtime_firewall: dnsmasq sets are kept by default, cleared on request") {
    Config config = shared_list_config();
    const auto marks = allocate_outbound_marks(FwmarkConfig{}, *config.outbounds);
    CacheManager cache("/nonexistent/cache");
    RecordingFirewall firewall;

    (void)apply_runtime_firewall(config, marks, {}, cache, firewall, FirewallApplyMode::Destructive);
    config.daemon->clear_dynamic_sets_on_apply = true;
    (void)apply_runtime_firewall(config, marks, {}, cache, firewall, FirewallApplyMode::Destructive);

    CHECK(firewall.clear_dynamic_sets_seen == std::vector<bool>{false, true});
}

TEST_CASE("daemon.clear_dynamic_sets_on_apply: optional boolean") {
    CHECK_NOTHROW(parse_config(R"({"daemon":{"clear_dynamic_sets_on_apply":true}})"));
    CHECK_NOTHROW(parse_config(R"({"daemon":{"clear_dynamic_sets_on_apply":null}})"));
    const Config omitted = parse_config(R"({"daemon":{}})");
    CHECK_FALSE(omitted.daemon->clear_dynamic_sets_on_apply.has_value());
    CHECK_THROWS_AS(parse_config(R"({"daemon":{"clear_dynamic_sets_on_apply":"yes"}})"),
                    ConfigValidationError);
}

TEST_CASE("build_firewall_rule_criteria: selectors as the apply installs them") {
    RouteRule rule;
    rule.outbound = "vpn";
    rule.proto = "tcp/udp";
    rule.src_port = "!1024-2048";
    rule.dest_port = "443";
    rule.src_addr = "192.168.1.0/24";
    rule.dest_addr = "!10.0.0.0/8,192.168.0.0/16";

    const auto criteria = build_firewall_rule_criteria(rule);
    CHECK(criteria.proto == L4Proto::TcpUdp);
    CHECK(criteria.negate_src_port);
    CHECK(criteria.src_port.to_iptables_string() == "1024:2048");
    CHECK_FALSE(criteria.negate_dst_port);
    CHECK(criteria.dst_port.to_iptables_string() == "443");
    CHECK(criteria.src_addr == std::vector<std::string>{"192.168.1.0/24"});
    CHECK_FALSE(criteria.negate_src_addr);
    CHECK(criteria.dst_addr == std::vector<std::string>{"10.0.0.0/8", "192.168.0.0/16"});
    CHECK(criteria.negate_dst_addr);

    // The apply records the same criteria in its rule states.
    Config config = shared_list_config();
    config.route->rules->at(0).proto = "tcp";
    config.route->rules->at(0).dest_port = "443";
    const auto marks = allocate_outbound_marks(FwmarkConfig{}, *config.outbounds);
    CacheManager cache("/nonexistent/cache");
    RecordingFirewall firewall;
    const auto states = apply_runtime_firewall(
        config, marks, {}, cache, firewall, FirewallApplyMode::Destructive);
    REQUIRE(states.size() == 2);
    CHECK(states[0].criteria.proto == L4Proto::Tcp);
    CHECK(states[0].criteria.dst_port.to_iptables_string() == "443");
}

TEST_CASE("apply_runtime_firewall: a repeated rules-only fallback is warned about once") {
    const Config config = shared_list_config();
    const auto marks = allocate_outbound_marks(FwmarkConfig{}, *config.outbounds);
    CacheManager cache("/nonexistent/cache");
    RecordingFirewall firewall;
    FirewallSetCache set_cache;
    (void)apply_runtime_firewall(
        config, marks, {}, cache, firewall, FirewallApplyMode::Destructive, &set_cache);

    std::vector<std::string> lines;
    const LogLevel previous_level = Logger::instance().level();
    Logger::instance().set_level(LogLevel::info);
    Logger::instance().set_sink([&lines](const std::string& line) { lines.push_back(line); });
    const auto warnings = [&lines]() {
        int count = 0;
        for (const auto& line : lines) {
            if (line.find("rules-only refresh not possible") != std::string::npos) {
                ++count;
            }
        }
        return count;
    };

    firewall.refuse_rules_only = true;
    (void)apply_runtime_firewall(
        config, marks, {}, cache, firewall, FirewallApplyMode::RulesOnly, &set_cache);
    (void)apply_runtime_firewall(
        config, marks, {}, cache, firewall, FirewallApplyMode::RulesOnly, &set_cache);
    const int after_repeats = warnings();

    // Once RulesOnly works again, a later failure is news again.
    firewall.refuse_rules_only = false;
    (void)apply_runtime_firewall(
        config, marks, {}, cache, firewall, FirewallApplyMode::RulesOnly, &set_cache);
    firewall.refuse_rules_only = true;
    (void)apply_runtime_firewall(
        config, marks, {}, cache, firewall, FirewallApplyMode::RulesOnly, &set_cache);
    const int after_recovery = warnings();

    Logger::instance().clear_sink();
    Logger::instance().set_level(previous_level);
    CHECK(after_repeats == 1);
    CHECK(after_recovery == 2);
}
