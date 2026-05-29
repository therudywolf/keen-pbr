#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <optional>
#include <unordered_map>

namespace keen_pbr3 {

// Shared correlation table for DNS-correlation split routing.
//
// The DnsSplitObserver upserts (resolved IPv4 -> outbound fwmark) entries as it
// tails dnsmasq's reply log; the NFQUEUE SYN handler looks up a connection's
// destination IPv4 here to decide which fwmark (if any) to stamp on the new
// flow. Because a single CDN IP can be the answer for several domains that route
// differently, the LAST writer for an IP wins — we mark by the domain the client
// most recently resolved to that address, which is the connection it is about to
// open.
//
// Entries carry a wall-clock-ish timestamp and expire after a TTL so a stale
// answer for a since-reused IP cannot keep mis-marking new connections forever.
// Lookups treat expired entries as absent and let the flow fall through to the
// existing IP-based (ipset) routing — fail-open.
//
// Thread-safe: the observer worker writes from a Scheduler/executor thread while
// the NFQUEUE handler reads from the daemon event-loop thread. All access is
// guarded by one mutex; the table is tiny (bounded by active resolved IPs) and
// lookups are O(1), so contention on a weak router is negligible.
class DnsSplitTable {
public:
    using Clock = std::chrono::steady_clock;

    // ttl: how long an entry stays valid after its last upsert. Defaults to
    // 600s, matching the list-warmer cadence and dnsmasq's max-cache-ttl window.
    explicit DnsSplitTable(std::chrono::seconds ttl = std::chrono::seconds{600});

    // Insert or refresh the mark for a destination IPv4 (host byte order is
    // irrelevant — the key is just an opaque 32-bit token; callers must use the
    // same representation for upsert and lookup). Stamps the entry's timestamp
    // with `now` so its TTL restarts.
    void upsert(uint32_t ipv4, uint32_t mark, Clock::time_point now = Clock::now());

    // Return the mark for `ipv4` if a non-expired entry exists, else nullopt.
    // Expired entries are ignored (and lazily dropped) so a dead correlation
    // never pins a connection to the wrong outbound.
    std::optional<uint32_t> lookup(uint32_t ipv4, Clock::time_point now = Clock::now());

    // Drop every entry older than the TTL. Called periodically by the observer
    // so the table cannot grow unbounded between lookups for cold IPs.
    // Returns the number of entries removed.
    std::size_t expire(Clock::time_point now = Clock::now());

    // Remove all entries (used on teardown / config reload).
    void clear();

    std::size_t size() const;

private:
    struct Entry {
        uint32_t mark;
        Clock::time_point stamped_at;
    };

    mutable std::mutex mu_;
    std::unordered_map<uint32_t, Entry> map_;
    std::chrono::seconds ttl_;
};

}  // namespace keen_pbr3
