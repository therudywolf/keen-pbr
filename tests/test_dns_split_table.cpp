#include <doctest/doctest.h>

#include "../src/routing/dns_split_table.hpp"

#include <chrono>

using namespace keen_pbr3;
using Clock = DnsSplitTable::Clock;

namespace {
constexpr uint32_t kIpA = 0xC0000201;  // 192.0.2.1
constexpr uint32_t kIpB = 0xC0000202;  // 192.0.2.2
constexpr uint32_t kVpn = 0x50000;
constexpr uint32_t kWan = 0x20000;
}  // namespace

TEST_CASE("dns_split_table: upsert then lookup returns the mark") {
    DnsSplitTable t(std::chrono::seconds{600});
    const auto t0 = Clock::now();
    t.upsert(kIpA, kVpn, t0);
    CHECK(t.lookup(kIpA, t0) == kVpn);
    CHECK(t.size() == 1);
}

TEST_CASE("dns_split_table: a miss returns nullopt (fail-open to IP routing)") {
    DnsSplitTable t;
    CHECK(t.lookup(kIpB) == std::nullopt);
}

TEST_CASE("dns_split_table: last writer for an IP wins") {
    // Two domains resolve to the same CDN IP but route differently; the most
    // recent resolution is the connection the client is about to open.
    DnsSplitTable t;
    const auto t0 = Clock::now();
    t.upsert(kIpA, kWan, t0);
    t.upsert(kIpA, kVpn, t0 + std::chrono::seconds{1});
    CHECK(t.lookup(kIpA, t0 + std::chrono::seconds{2}) == kVpn);
    CHECK(t.size() == 1);
}

TEST_CASE("dns_split_table: an entry past its TTL is treated as absent") {
    DnsSplitTable t(std::chrono::seconds{600});
    const auto t0 = Clock::now();
    t.upsert(kIpA, kVpn, t0);

    CHECK(t.lookup(kIpA, t0 + std::chrono::seconds{599}) == kVpn);  // still fresh
    CHECK(t.lookup(kIpA, t0 + std::chrono::seconds{601}) == std::nullopt);  // expired
    // Expired lookup drops the entry lazily.
    CHECK(t.size() == 0);
}

TEST_CASE("dns_split_table: upsert refreshes the TTL window") {
    DnsSplitTable t(std::chrono::seconds{600});
    const auto t0 = Clock::now();
    t.upsert(kIpA, kVpn, t0);
    // Re-resolved just before expiry -> window restarts from the new stamp.
    t.upsert(kIpA, kVpn, t0 + std::chrono::seconds{590});
    CHECK(t.lookup(kIpA, t0 + std::chrono::seconds{601}) == kVpn);
    CHECK(t.lookup(kIpA, t0 + std::chrono::seconds{1191}) == std::nullopt);
}

TEST_CASE("dns_split_table: expire() removes only stale entries and counts them") {
    DnsSplitTable t(std::chrono::seconds{600});
    const auto t0 = Clock::now();
    t.upsert(kIpA, kVpn, t0);
    t.upsert(kIpB, kWan, t0 + std::chrono::seconds{300});

    const std::size_t removed = t.expire(t0 + std::chrono::seconds{601});
    CHECK(removed == 1);          // only kIpA aged out
    CHECK(t.size() == 1);
    CHECK(t.lookup(kIpB, t0 + std::chrono::seconds{601}) == kWan);
}

TEST_CASE("dns_split_table: clear empties the table") {
    DnsSplitTable t;
    t.upsert(kIpA, kVpn);
    t.upsert(kIpB, kWan);
    t.clear();
    CHECK(t.size() == 0);
    CHECK(t.lookup(kIpA) == std::nullopt);
}
