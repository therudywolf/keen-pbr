#include <doctest/doctest.h>

#include "../src/lists/list_warmer.hpp"
#include "../src/util/blocking_executor.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

using namespace keen_pbr3;

namespace {

// Captures every (set, ips, timeout) batch the warmer hands to the ipset adder.
// The warmer now batches all IPs for a given (domain, family) into one call,
// so one entry per call, not per IP.
struct IpsetCall {
    std::string set_name;
    std::vector<std::string> ips;
    uint32_t timeout_seconds{0};
};

// Helper: poll a counter until it reaches the expected value, or time out.
// The warmer submits work via BlockingExecutor::try_post (fire-and-forget),
// so the test needs to wait for tasks to actually run before asserting.
void wait_for_count(const std::atomic<int>& counter,
                    int expected,
                    std::chrono::milliseconds timeout = std::chrono::seconds{2}) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (counter.load() < expected && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
}

// Builds a deterministic A-resolver that returns the provided map values
// (or empty when the domain is missing).
ListWarmer::AResolver mock_a_resolver(
    std::shared_ptr<std::mutex> mtx,
    std::shared_ptr<std::map<std::string, int>> counts,
    std::map<std::string, std::vector<std::string>> answers) {
    return [mtx, counts, answers = std::move(answers)](
               const std::string& /*server*/,
               const std::string& domain,
               std::chrono::milliseconds /*timeout*/) {
        {
            std::lock_guard<std::mutex> lock(*mtx);
            (*counts)[domain]++;
        }
        auto it = answers.find(domain);
        if (it == answers.end()) return std::vector<std::string>{};
        return it->second;
    };
}

ListWarmer::AaaaResolver mock_aaaa_resolver(
    std::shared_ptr<std::mutex> mtx,
    std::shared_ptr<std::map<std::string, int>> counts,
    std::map<std::string, std::vector<std::string>> answers) {
    return [mtx, counts, answers = std::move(answers)](
               const std::string& /*server*/,
               const std::string& domain,
               std::chrono::milliseconds /*timeout*/) {
        {
            std::lock_guard<std::mutex> lock(*mtx);
            (*counts)[domain]++;
        }
        auto it = answers.find(domain);
        if (it == answers.end()) return std::vector<std::string>{};
        return it->second;
    };
}

ListWarmer::IpsetAdder mock_ipset_adder(
    std::shared_ptr<std::mutex> mtx,
    std::shared_ptr<std::vector<IpsetCall>> calls) {
    return [mtx, calls](const std::string& set_name,
                        const std::vector<std::string>& ips,
                        uint32_t timeout_seconds) {
        std::lock_guard<std::mutex> lock(*mtx);
        calls->push_back({set_name, ips, timeout_seconds});
        return true;
    };
}

// Decorate an existing AResolver so that each invocation also bumps a counter.
// The counter doubles as a "tasks finished" signal that wait_for_count() polls,
// so the test doesn't need to sleep for a fixed duration.
ListWarmer::AResolver with_done_signal(ListWarmer::AResolver inner,
                                       std::shared_ptr<std::atomic<int>> done_counter) {
    return [inner = std::move(inner), done_counter](
               const std::string& server,
               const std::string& domain,
               std::chrono::milliseconds timeout) {
        auto result = inner(server, domain, timeout);
        done_counter->fetch_add(1);
        return result;
    };
}

// Assemble a minimal Config with the given list definitions.
Config make_config_with_lists(std::map<std::string, ListConfig> lists,
                              std::optional<bool> ipv6_enabled = std::nullopt) {
    Config cfg;
    cfg.lists = std::move(lists);
    if (ipv6_enabled.has_value()) {
        DaemonConfig daemon_cfg;
        daemon_cfg.ipv6_enabled = ipv6_enabled;
        cfg.daemon = std::move(daemon_cfg);
    }
    return cfg;
}

} // namespace

TEST_CASE("list_warmer queues one task per domain across all domain-bearing lists") {
    auto mtx = std::make_shared<std::mutex>();
    auto a_counts = std::make_shared<std::map<std::string, int>>();
    auto aaaa_counts = std::make_shared<std::map<std::string, int>>();
    auto ipset_calls = std::make_shared<std::vector<IpsetCall>>();
    auto a_done = std::make_shared<std::atomic<int>>(0);

    ListConfig list_a;
    list_a.domains = std::vector<std::string>{"example.com", "foo.example.com"};
    list_a.ttl_ms = 86400000; // 24h -> 86400s timeout
    ListConfig list_b;
    list_b.domains = std::vector<std::string>{"another.test"};
    list_b.ttl_ms = 60000;

    Config cfg = make_config_with_lists({
        {"rkn", list_a},
        {"misc", list_b},
    });

    BlockingExecutor executor(2, 16);

    ListWarmer warmer(
        ListWarmer::Settings{},
        [&cfg]() -> const Config& { return cfg; },
        &executor,
        with_done_signal(
            mock_a_resolver(mtx, a_counts,
                            {{"example.com",     {"1.2.3.4"}},
                             {"foo.example.com", {"1.2.3.5", "1.2.3.6"}},
                             {"another.test",    {"9.9.9.9"}}}),
            a_done),
        mock_aaaa_resolver(mtx, aaaa_counts, {}),
        mock_ipset_adder(mtx, ipset_calls));

    const int queued = warmer.warm_once();
    wait_for_count(*a_done, 3);
    executor.shutdown();

    CHECK(queued == 3);
    CHECK(a_done->load() == 3);
    {
        std::lock_guard<std::mutex> lock(*mtx);
        CHECK((*a_counts)["example.com"] == 1);
        CHECK((*a_counts)["foo.example.com"] == 1);
        CHECK((*a_counts)["another.test"] == 1);
    }
}

TEST_CASE("list_warmer skips lists that have no domains field") {
    auto mtx = std::make_shared<std::mutex>();
    auto a_counts = std::make_shared<std::map<std::string, int>>();
    auto aaaa_counts = std::make_shared<std::map<std::string, int>>();
    auto ipset_calls = std::make_shared<std::vector<IpsetCall>>();
    auto a_done = std::make_shared<std::atomic<int>>(0);

    ListConfig static_only;
    static_only.ip_cidrs = std::vector<std::string>{"10.0.0.0/8"};

    ListConfig file_only;
    file_only.file = std::string{"/etc/keen-pbr/lists/static.txt"};

    ListConfig empty_domains;
    empty_domains.domains = std::vector<std::string>{};

    ListConfig with_domains;
    with_domains.domains = std::vector<std::string>{"keep.me"};

    Config cfg = make_config_with_lists({
        {"static",    static_only},
        {"from_file", file_only},
        {"empty",     empty_domains},
        {"warmable",  with_domains},
    });

    BlockingExecutor executor(2, 16);
    ListWarmer warmer(
        ListWarmer::Settings{},
        [&cfg]() -> const Config& { return cfg; },
        &executor,
        with_done_signal(
            mock_a_resolver(mtx, a_counts, {{"keep.me", {"7.7.7.7"}}}),
            a_done),
        mock_aaaa_resolver(mtx, aaaa_counts, {}),
        mock_ipset_adder(mtx, ipset_calls));

    const int queued = warmer.warm_once();
    wait_for_count(*a_done, 1);
    executor.shutdown();

    CHECK(queued == 1);
    {
        std::lock_guard<std::mutex> lock(*mtx);
        CHECK(a_counts->size() == 1);
        CHECK((*a_counts)["keep.me"] == 1);
    }
}

TEST_CASE("list_warmer adds every resolved IP to the v4 ipset") {
    auto mtx = std::make_shared<std::mutex>();
    auto a_counts = std::make_shared<std::map<std::string, int>>();
    auto aaaa_counts = std::make_shared<std::map<std::string, int>>();
    auto ipset_calls = std::make_shared<std::vector<IpsetCall>>();
    auto a_done = std::make_shared<std::atomic<int>>(0);

    ListConfig list_cfg;
    list_cfg.domains = std::vector<std::string>{"multi.example.com"};
    list_cfg.ttl_ms = 0; // no timeout

    Config cfg = make_config_with_lists({{"multi", list_cfg}},
                                        /*ipv6_enabled=*/false);

    BlockingExecutor executor(2, 16);
    ListWarmer warmer(
        ListWarmer::Settings{},
        [&cfg]() -> const Config& { return cfg; },
        &executor,
        with_done_signal(
            mock_a_resolver(mtx, a_counts,
                            {{"multi.example.com", {"1.1.1.1", "2.2.2.2", "3.3.3.3"}}}),
            a_done),
        mock_aaaa_resolver(mtx, aaaa_counts, {}),
        mock_ipset_adder(mtx, ipset_calls));

    (void)warmer.warm_once();
    wait_for_count(*a_done, 1);
    executor.shutdown();

    std::lock_guard<std::mutex> lock(*mtx);
    // One batched call carries all three IPs into kpbr4d_multi.
    REQUIRE(ipset_calls->size() == 1);
    CHECK((*ipset_calls)[0].set_name == "kpbr4d_multi");
    CHECK((*ipset_calls)[0].timeout_seconds == 0u);
    std::vector<std::string> ips = (*ipset_calls)[0].ips;
    std::sort(ips.begin(), ips.end());
    CHECK(ips == std::vector<std::string>{"1.1.1.1", "2.2.2.2", "3.3.3.3"});
}

TEST_CASE("list_warmer skips ipv6 ipset add when AAAA returns nothing") {
    auto mtx = std::make_shared<std::mutex>();
    auto a_counts = std::make_shared<std::map<std::string, int>>();
    auto aaaa_counts = std::make_shared<std::map<std::string, int>>();
    auto ipset_calls = std::make_shared<std::vector<IpsetCall>>();
    auto a_done = std::make_shared<std::atomic<int>>(0);

    ListConfig list_cfg;
    list_cfg.domains = std::vector<std::string>{"ipv4only.example.com"};

    // ipv6 enabled (default), so the warmer WILL issue a AAAA query — but no
    // AAAA records exist for the domain, so the only ipset add should be the
    // single v4 entry. We assert that explicitly.
    Config cfg = make_config_with_lists({{"only4", list_cfg}});

    BlockingExecutor executor(2, 16);
    ListWarmer warmer(
        ListWarmer::Settings{},
        [&cfg]() -> const Config& { return cfg; },
        &executor,
        with_done_signal(
            mock_a_resolver(mtx, a_counts, {{"ipv4only.example.com", {"4.4.4.4"}}}),
            a_done),
        mock_aaaa_resolver(mtx, aaaa_counts, {}), // returns {} for every query
        mock_ipset_adder(mtx, ipset_calls));

    (void)warmer.warm_once();
    wait_for_count(*a_done, 1);
    executor.shutdown();

    std::lock_guard<std::mutex> lock(*mtx);
    REQUIRE(ipset_calls->size() == 1);
    CHECK((*ipset_calls)[0].set_name == "kpbr4d_only4");
    REQUIRE((*ipset_calls)[0].ips.size() == 1);
    CHECK((*ipset_calls)[0].ips[0] == "4.4.4.4");
    // No v6 add for an empty AAAA answer.
    for (const auto& call : *ipset_calls) {
        CHECK(call.set_name.find("kpbr6d_") == std::string::npos);
    }
}

TEST_CASE("list_warmer does not query AAAA when ipv6 is disabled in config") {
    auto mtx = std::make_shared<std::mutex>();
    auto a_counts = std::make_shared<std::map<std::string, int>>();
    auto aaaa_counts = std::make_shared<std::map<std::string, int>>();
    auto ipset_calls = std::make_shared<std::vector<IpsetCall>>();
    auto a_done = std::make_shared<std::atomic<int>>(0);

    ListConfig list_cfg;
    list_cfg.domains = std::vector<std::string>{"v4only.example.com"};

    Config cfg = make_config_with_lists({{"only4", list_cfg}},
                                        /*ipv6_enabled=*/false);

    BlockingExecutor executor(2, 16);
    ListWarmer warmer(
        ListWarmer::Settings{},
        [&cfg]() -> const Config& { return cfg; },
        &executor,
        with_done_signal(
            mock_a_resolver(mtx, a_counts, {{"v4only.example.com", {"5.5.5.5"}}}),
            a_done),
        mock_aaaa_resolver(mtx, aaaa_counts, {}),
        mock_ipset_adder(mtx, ipset_calls));

    (void)warmer.warm_once();
    wait_for_count(*a_done, 1);
    executor.shutdown();

    std::lock_guard<std::mutex> lock(*mtx);
    // With ipv6_enabled=false, the warmer must NOT issue any AAAA query.
    CHECK(aaaa_counts->empty());
    REQUIRE(ipset_calls->size() == 1);
    CHECK((*ipset_calls)[0].set_name == "kpbr4d_only4");
    REQUIRE((*ipset_calls)[0].ips.size() == 1);
    CHECK((*ipset_calls)[0].ips[0] == "5.5.5.5");
}

TEST_CASE("list_warmer propagates ttl_ms to the ipset add timeout") {
    auto mtx = std::make_shared<std::mutex>();
    auto a_counts = std::make_shared<std::map<std::string, int>>();
    auto aaaa_counts = std::make_shared<std::map<std::string, int>>();
    auto ipset_calls = std::make_shared<std::vector<IpsetCall>>();
    auto a_done = std::make_shared<std::atomic<int>>(0);

    ListConfig list_cfg;
    list_cfg.domains = std::vector<std::string>{"ttl.example.com"};
    list_cfg.ttl_ms = 86400000; // 24h -> 86400 seconds

    Config cfg = make_config_with_lists({{"with_ttl", list_cfg}},
                                        /*ipv6_enabled=*/false);

    BlockingExecutor executor(2, 16);
    ListWarmer warmer(
        ListWarmer::Settings{},
        [&cfg]() -> const Config& { return cfg; },
        &executor,
        with_done_signal(
            mock_a_resolver(mtx, a_counts, {{"ttl.example.com", {"6.6.6.6"}}}),
            a_done),
        mock_aaaa_resolver(mtx, aaaa_counts, {}),
        mock_ipset_adder(mtx, ipset_calls));

    (void)warmer.warm_once();
    wait_for_count(*a_done, 1);
    executor.shutdown();

    std::lock_guard<std::mutex> lock(*mtx);
    REQUIRE(ipset_calls->size() == 1);
    CHECK((*ipset_calls)[0].timeout_seconds == 86400u);
}

TEST_CASE("list_warmer strips dnsmasq wildcard prefix before querying") {
    auto mtx = std::make_shared<std::mutex>();
    auto a_counts = std::make_shared<std::map<std::string, int>>();
    auto aaaa_counts = std::make_shared<std::map<std::string, int>>();
    auto ipset_calls = std::make_shared<std::vector<IpsetCall>>();
    auto a_done = std::make_shared<std::atomic<int>>(0);

    ListConfig list_cfg;
    list_cfg.domains = std::vector<std::string>{"*.wildcard.example"};

    Config cfg = make_config_with_lists({{"wild", list_cfg}},
                                        /*ipv6_enabled=*/false);

    BlockingExecutor executor(2, 16);
    ListWarmer warmer(
        ListWarmer::Settings{},
        [&cfg]() -> const Config& { return cfg; },
        &executor,
        with_done_signal(
            mock_a_resolver(mtx, a_counts,
                            {{"wildcard.example", {"8.8.8.8"}}}),
            a_done),
        mock_aaaa_resolver(mtx, aaaa_counts, {}),
        mock_ipset_adder(mtx, ipset_calls));

    (void)warmer.warm_once();
    wait_for_count(*a_done, 1);
    executor.shutdown();

    std::lock_guard<std::mutex> lock(*mtx);
    // The recursive resolver was queried for the stripped hostname, not the
    // dnsmasq wildcard form.
    CHECK((*a_counts)["wildcard.example"] == 1);
    REQUIRE(ipset_calls->size() == 1);
    REQUIRE((*ipset_calls)[0].ips.size() == 1);
    CHECK((*ipset_calls)[0].ips[0] == "8.8.8.8");
}
