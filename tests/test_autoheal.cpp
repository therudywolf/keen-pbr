#include <doctest/doctest.h>

#include "../src/routing/autoheal.hpp"

#include <string>
#include <vector>

using namespace keen_pbr3;

namespace {

// Build a minimal route rule for fixtures.
RouteRule make_rule(const std::string& outbound,
                    std::vector<std::string> lists,
                    bool enabled = true) {
    RouteRule rule;
    rule.outbound = outbound;
    rule.enabled = enabled;
    rule.list = std::move(lists);
    return rule;
}

const std::vector<std::string>& domains_of(const Config& cfg, const std::string& name) {
    static const std::vector<std::string> empty;
    REQUIRE(cfg.lists.has_value());
    const auto it = cfg.lists->find(name);
    REQUIRE(it != cfg.lists->end());
    REQUIRE(it->second.domains.has_value());
    return *it->second.domains;
}

const std::vector<RouteRule>& rules_of(const Config& cfg) {
    static const std::vector<RouteRule> empty;
    REQUIRE(cfg.route.has_value());
    REQUIRE(cfg.route->rules.has_value());
    return *cfg.route->rules;
}

}  // namespace

TEST_CASE("autoheal: creates the list when absent and seeds empty arrays") {
    Config cfg;  // no lists, no route at all
    const Config out = promote_domains(cfg, "auto", "forestserver_ru",
                                       {"a.com", "b.com"});

    REQUIRE(out.lists.has_value());
    const auto it = out.lists->find("auto");
    REQUIRE(it != out.lists->end());
    REQUIRE(it->second.domains.has_value());
    REQUIRE(it->second.ip_cidrs.has_value());  // seeded empty, not null
    CHECK(it->second.ip_cidrs->empty());
    CHECK(*it->second.domains == std::vector<std::string>{"a.com", "b.com"});
}

TEST_CASE("autoheal: inserts the top-priority rule as rules[0]") {
    Config cfg;
    const Config out = promote_domains(cfg, "auto", "forestserver_ru", {"a.com"});

    const auto& rules = rules_of(out);
    REQUIRE(rules.size() == 1);
    CHECK(rules[0].outbound == "forestserver_ru");
    CHECK(route_rule_enabled(rules[0]));
    CHECK(route_rule_lists(rules[0]) == std::vector<std::string>{"auto"});
}

TEST_CASE("autoheal: prepends the top rule ahead of existing rules without clobbering them") {
    Config cfg;
    cfg.route = RouteConfig{};
    cfg.route->rules = std::vector<RouteRule>{
        make_rule("vpn", {"youtube"}),
        make_rule("direct", {"local", "lan"}),
    };

    const Config out = promote_domains(cfg, "auto", "forestserver_ru", {"a.com"});
    const auto& rules = rules_of(out);

    REQUIRE(rules.size() == 3);
    // New top rule first.
    CHECK(rules[0].outbound == "forestserver_ru");
    CHECK(route_rule_lists(rules[0]) == std::vector<std::string>{"auto"});
    // Original rules preserved in order, lists untouched.
    CHECK(rules[1].outbound == "vpn");
    CHECK(route_rule_lists(rules[1]) == std::vector<std::string>{"youtube"});
    CHECK(rules[2].outbound == "direct");
    CHECK(route_rule_lists(rules[2]) == std::vector<std::string>{"local", "lan"});
}

TEST_CASE("autoheal: dedups new domains against existing and within the batch") {
    Config cfg;
    cfg.lists = std::map<std::string, ListConfig>{};
    ListConfig seed;
    seed.domains = std::vector<std::string>{"a.com"};
    (*cfg.lists)["auto"] = seed;

    const Config out = promote_domains(
        cfg, "auto", "forestserver_ru",
        {"a.com", "b.com", "b.com", "", "c.com"});  // dup existing, dup batch, empty

    CHECK(domains_of(out, "auto") ==
          std::vector<std::string>{"a.com", "b.com", "c.com"});
}

TEST_CASE("autoheal: idempotent on repeat — no duplicate rule, no duplicate domains") {
    Config cfg;
    const Config first = promote_domains(cfg, "auto", "forestserver_ru",
                                         {"a.com", "b.com"});
    const Config second = promote_domains(first, "auto", "forestserver_ru",
                                          {"a.com", "b.com"});

    // Domains unchanged.
    CHECK(domains_of(second, "auto") ==
          std::vector<std::string>{"a.com", "b.com"});
    // Still exactly one rule — the existing top rule was reused, not duplicated.
    const auto& rules = rules_of(second);
    REQUIRE(rules.size() == 1);
    CHECK(rules[0].outbound == "forestserver_ru");
    CHECK(route_rule_lists(rules[0]) == std::vector<std::string>{"auto"});
}

TEST_CASE("autoheal: reuses rules[0] when it is already exactly the top rule") {
    Config cfg;
    cfg.route = RouteConfig{};
    cfg.route->rules = std::vector<RouteRule>{
        make_rule("forestserver_ru", {"auto"}),  // already the desired top rule
        make_rule("vpn", {"youtube"}),
    };

    const Config out = promote_domains(cfg, "auto", "forestserver_ru", {"x.com"});
    const auto& rules = rules_of(out);

    // No new rule prepended; still two rules.
    REQUIRE(rules.size() == 2);
    CHECK(rules[0].outbound == "forestserver_ru");
    CHECK(route_rule_lists(rules[0]) == std::vector<std::string>{"auto"});
    CHECK(rules[1].outbound == "vpn");
    // Domains were still appended to the auto list.
    CHECK(domains_of(out, "auto") == std::vector<std::string>{"x.com"});
}

TEST_CASE("autoheal: a non-matching rules[0] forces a fresh top rule") {
    Config cfg;
    cfg.route = RouteConfig{};
    // rules[0] uses the same outbound but a different (multi-element) list, so
    // it is NOT the exact top rule and must not be reused in place.
    cfg.route->rules = std::vector<RouteRule>{
        make_rule("forestserver_ru", {"auto", "extra"}),
    };

    const Config out = promote_domains(cfg, "auto", "forestserver_ru", {});
    const auto& rules = rules_of(out);

    REQUIRE(rules.size() == 2);
    CHECK(route_rule_lists(rules[0]) == std::vector<std::string>{"auto"});
    CHECK(route_rule_lists(rules[1]) == std::vector<std::string>{"auto", "extra"});
}

TEST_CASE("autoheal: a disabled matching rules[0] is not reused") {
    Config cfg;
    cfg.route = RouteConfig{};
    cfg.route->rules = std::vector<RouteRule>{
        make_rule("forestserver_ru", {"auto"}, /*enabled=*/false),
    };

    const Config out = promote_domains(cfg, "auto", "forestserver_ru", {});
    const auto& rules = rules_of(out);

    // A fresh enabled top rule is prepended ahead of the disabled one.
    REQUIRE(rules.size() == 2);
    CHECK(route_rule_enabled(rules[0]));
    CHECK(rules[1].enabled.has_value());
    CHECK(*rules[1].enabled == false);
}
