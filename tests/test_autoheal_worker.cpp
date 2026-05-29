#include <doctest/doctest.h>

#include "../src/cmd/test_routing.hpp"
#include "../src/routing/autoheal.hpp"
#include "../src/routing/autoheal_worker.hpp"

#include <map>
#include <optional>
#include <string>
#include <unordered_set>
#include <vector>

using namespace keen_pbr3;

namespace {

const std::string kVpn = "forestserver_ru";
const std::string kWan = "(default)";

// ---- pure-helper fixtures -------------------------------------------------

AutohealDomainStatus status(const std::string& domain, bool leaking) {
    AutohealDomainStatus s;
    s.domain = domain;
    s.leaking = leaking;
    return s;
}

std::unordered_set<std::string> auto_list(std::initializer_list<std::string> items) {
    return std::unordered_set<std::string>(items);
}

// ---- worker fixtures ------------------------------------------------------

// A TestRoutingResult with a single IPv4 entry routed to `expected_outbound`.
// This is what compute_test_routing yields for a domain that resolves to one
// IPv4 address; the worker treats expected_outbound != autoheal_outbound as a
// leak.
TestRoutingResult routing_to(const std::string& expected_outbound) {
    TestRoutingResult result;
    result.is_domain = true;
    result.resolved_ips = {"203.0.113.7"};
    TestRoutingEntry entry;
    entry.ip = "203.0.113.7";
    entry.expected_outbound = expected_outbound;
    entry.actual_outbound = expected_outbound;
    entry.ok = true;
    result.entries.push_back(std::move(entry));
    return result;
}

// A TestRoutingResult for a domain that did not resolve (no IPv4 entries).
TestRoutingResult routing_unresolved() {
    TestRoutingResult result;
    result.is_domain = true;
    TestRoutingEntry entry;
    entry.ip = "(no IPs resolved)";
    entry.expected_outbound = "(default)";
    entry.actual_outbound = "(unknown)";
    entry.ok = false;
    result.entries.push_back(std::move(entry));
    return result;
}

// Builds a daemon config with the auto-heal knobs set. `watchlist == nullopt`
// leaves autoheal_watchlist unset (absent); an empty vector sets it explicitly
// empty. `seed_auto` pre-populates the auto list's domains.
Config make_config(std::optional<bool> enabled,
                   std::optional<std::vector<std::string>> watchlist,
                   std::vector<std::string> seed_auto = {},
                   std::string list = "auto",
                   std::string outbound = kVpn) {
    Config cfg;
    DaemonConfig daemon;
    daemon.autoheal_enabled = enabled;
    daemon.autoheal_list = list;
    daemon.autoheal_outbound = outbound;
    daemon.autoheal_watchlist = std::move(watchlist);
    cfg.daemon = std::move(daemon);

    if (!seed_auto.empty()) {
        cfg.lists = std::map<std::string, ListConfig>{};
        ListConfig lc;
        lc.domains = std::move(seed_auto);
        (*cfg.lists)[list] = std::move(lc);
    }
    return cfg;
}

// Worker harness: owns the live config and the routing map, captures applies.
struct WorkerHarness {
    Config config;
    std::map<std::string, TestRoutingResult> routing;  // domain -> result
    std::vector<Config> applied;                        // captured promoted configs

    AutohealWorker make_worker() {
        return AutohealWorker(
            [this]() -> const Config& { return config; },
            [this](const std::string& target) -> TestRoutingResult {
                auto it = routing.find(target);
                if (it == routing.end()) {
                    // Unknown target: behave like an unresolved domain (no leak).
                    return routing_unresolved();
                }
                return it->second;
            },
            [this](Config promoted) { applied.push_back(std::move(promoted)); });
    }
};

const std::vector<std::string>& auto_domains(const Config& cfg, const std::string& list) {
    static const std::vector<std::string> empty;
    REQUIRE(cfg.lists.has_value());
    auto it = cfg.lists->find(list);
    REQUIRE(it != cfg.lists->end());
    REQUIRE(it->second.domains.has_value());
    return *it->second.domains;
}

}  // namespace

// ===========================================================================
// Pure decision helper: select_autoheal_promotions
// ===========================================================================

TEST_CASE("autoheal_select: disabled => promotes nothing even with leaks") {
    const std::vector<AutohealDomainStatus> statuses = {
        status("a.com", true), status("b.com", true)};
    const auto out = select_autoheal_promotions(/*enabled=*/false, statuses, auto_list({}));
    CHECK(out.empty());
}

TEST_CASE("autoheal_select: empty watchlist (no statuses) => promotes nothing") {
    const auto out = select_autoheal_promotions(/*enabled=*/true, {}, auto_list({}));
    CHECK(out.empty());
}

TEST_CASE("autoheal_select: leaking domain not in auto list => promoted") {
    const std::vector<AutohealDomainStatus> statuses = {status("a.com", true)};
    const auto out = select_autoheal_promotions(/*enabled=*/true, statuses, auto_list({}));
    CHECK(out == std::vector<std::string>{"a.com"});
}

TEST_CASE("autoheal_select: leaking domain already in auto list => skipped") {
    const std::vector<AutohealDomainStatus> statuses = {status("a.com", true)};
    const auto out =
        select_autoheal_promotions(/*enabled=*/true, statuses, auto_list({"a.com"}));
    CHECK(out.empty());
}

TEST_CASE("autoheal_select: non-leaking domain => skipped") {
    const std::vector<AutohealDomainStatus> statuses = {status("a.com", false)};
    const auto out = select_autoheal_promotions(/*enabled=*/true, statuses, auto_list({}));
    CHECK(out.empty());
}

TEST_CASE("autoheal_select: mixed batch keeps order, dedups, drops non-leaking/known/empty") {
    const std::vector<AutohealDomainStatus> statuses = {
        status("leak1.com", true),
        status("ok.com", false),       // not leaking -> skip
        status("known.com", true),     // already in auto list -> skip
        status("leak2.com", true),
        status("leak1.com", true),     // dup -> collapsed
        status("", true),              // empty -> skip
    };
    const auto out = select_autoheal_promotions(
        /*enabled=*/true, statuses, auto_list({"known.com"}));
    CHECK(out == std::vector<std::string>{"leak1.com", "leak2.com"});
}

// ===========================================================================
// Worker tick(): end-to-end gating + promotion + apply
// ===========================================================================

TEST_CASE("autoheal_worker: disabled => no evaluation, no apply") {
    WorkerHarness h;
    h.config = make_config(/*enabled=*/false, std::vector<std::string>{"leak.com"});
    h.routing["leak.com"] = routing_to(kWan);  // would leak if evaluated

    AutohealWorker worker = h.make_worker();
    CHECK(worker.tick() == 0);
    CHECK(h.applied.empty());
}

TEST_CASE("autoheal_worker: enabled but watchlist absent => no apply") {
    WorkerHarness h;
    h.config = make_config(/*enabled=*/true, /*watchlist=*/std::nullopt);

    AutohealWorker worker = h.make_worker();
    CHECK(worker.tick() == 0);
    CHECK(h.applied.empty());
}

TEST_CASE("autoheal_worker: enabled but watchlist empty => no apply") {
    WorkerHarness h;
    h.config = make_config(/*enabled=*/true, std::vector<std::string>{});

    AutohealWorker worker = h.make_worker();
    CHECK(worker.tick() == 0);
    CHECK(h.applied.empty());
}

TEST_CASE("autoheal_worker: leaking watchlist domain => promoted + applied into auto list") {
    WorkerHarness h;
    h.config = make_config(/*enabled=*/true, std::vector<std::string>{"leak.com"});
    h.routing["leak.com"] = routing_to(kWan);  // expected != VPN -> leaking

    AutohealWorker worker = h.make_worker();
    CHECK(worker.tick() == 1);

    REQUIRE(h.applied.size() == 1);
    // The applied config is the promote_domains result: leak.com is in "auto"
    // and a top-priority VPN rule exists.
    const Config& promoted = h.applied.front();
    CHECK(auto_domains(promoted, "auto") == std::vector<std::string>{"leak.com"});
    REQUIRE(promoted.route.has_value());
    REQUIRE(promoted.route->rules.has_value());
    const auto& rules = *promoted.route->rules;
    REQUIRE(!rules.empty());
    CHECK(rules[0].outbound == kVpn);
    CHECK(route_rule_lists(rules[0]) == std::vector<std::string>{"auto"});
}

TEST_CASE("autoheal_worker: domain already in auto list => skipped, no apply") {
    WorkerHarness h;
    h.config = make_config(/*enabled=*/true, std::vector<std::string>{"known.com"},
                           /*seed_auto=*/{"known.com"});
    h.routing["known.com"] = routing_to(kWan);  // leaking, but already promoted

    AutohealWorker worker = h.make_worker();
    CHECK(worker.tick() == 0);
    CHECK(h.applied.empty());
}

TEST_CASE("autoheal_worker: domain already routed to VPN => not leaking, no apply") {
    WorkerHarness h;
    h.config = make_config(/*enabled=*/true, std::vector<std::string>{"vpn.com"});
    h.routing["vpn.com"] = routing_to(kVpn);  // expected == VPN -> not leaking

    AutohealWorker worker = h.make_worker();
    CHECK(worker.tick() == 0);
    CHECK(h.applied.empty());
}

TEST_CASE("autoheal_worker: unresolved domain => not leaking, no apply") {
    WorkerHarness h;
    h.config = make_config(/*enabled=*/true, std::vector<std::string>{"dead.com"});
    h.routing["dead.com"] = routing_unresolved();  // no IPv4 entry -> not leaking

    AutohealWorker worker = h.make_worker();
    CHECK(worker.tick() == 0);
    CHECK(h.applied.empty());
}

TEST_CASE("autoheal_worker: only leaking subset of watchlist is promoted") {
    WorkerHarness h;
    h.config = make_config(/*enabled=*/true,
                           std::vector<std::string>{"leak.com", "vpn.com", "known.com"},
                           /*seed_auto=*/{"known.com"});
    h.routing["leak.com"] = routing_to(kWan);   // leak -> promote
    h.routing["vpn.com"] = routing_to(kVpn);    // already VPN -> skip
    h.routing["known.com"] = routing_to(kWan);  // leak but already in list -> skip

    AutohealWorker worker = h.make_worker();
    CHECK(worker.tick() == 1);

    REQUIRE(h.applied.size() == 1);
    const Config& promoted = h.applied.front();
    // known.com was pre-seeded; leak.com appended; vpn.com never added.
    CHECK(auto_domains(promoted, "auto") ==
          std::vector<std::string>{"known.com", "leak.com"});
}

TEST_CASE("autoheal_worker: a custom outbound is honored when deciding leaks") {
    WorkerHarness h;
    // autoheal_outbound is a non-default tag; a domain routed to it is NOT a leak.
    h.config = make_config(/*enabled=*/true, std::vector<std::string>{"x.com"}, {},
                           /*list=*/"auto", /*outbound=*/"my_vpn");
    h.routing["x.com"] = routing_to("my_vpn");

    AutohealWorker worker = h.make_worker();
    CHECK(worker.tick() == 0);
    CHECK(h.applied.empty());
}
