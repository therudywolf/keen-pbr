#include <doctest/doctest.h>

#include "../src/lists/ipset.hpp"
#include "../src/routing/conntrack_flush.hpp"
#include "../src/util/blocking_executor.hpp"

#include <atomic>
#include <chrono>
#include <memory>
#include <string>
#include <sys/socket.h>  // AF_INET / AF_INET6
#include <thread>
#include <utility>
#include <vector>

using namespace keen_pbr3;

namespace {

// Helper: poll a counter until it reaches the expected value, or time out.
// Same pattern as test_list_warmer — the flusher uses BlockingExecutor::try_post
// (fire-and-forget), so we poll a deletion counter rather than sleep blindly.
void wait_for_count(const std::atomic<int>& counter,
                    int expected,
                    std::chrono::milliseconds timeout = std::chrono::seconds{2}) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (counter.load() < expected && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
}

// Build a synthetic conntrack entry. The blob is opaque to the flusher logic
// (only the dst-IP membership test drives the delete), but we still populate
// it so a future regression in the "must pass blob through to deleter" path
// would be caught.
ConntrackFlusher::ConntrackEntry make_entry(uint8_t family,
                                            std::string dst,
                                            uint8_t blob_marker = 0x42) {
    ConntrackFlusher::ConntrackEntry entry;
    entry.family = family;
    entry.original_dst_ip = std::move(dst);
    // Just a marker so deleter recording can verify it's the same blob the
    // walker handed out — the byte value itself is arbitrary.
    entry.original_tuple_blob = {blob_marker};
    return entry;
}

// Helper: build a fake snapshot containing the given members.
std::unique_ptr<IpSet> make_snapshot(const std::vector<std::string>& members) {
    auto set = std::make_unique<IpSet>();
    for (const auto& m : members) {
        if (m.find('/') != std::string::npos) {
            set->add_cidr(m);
        } else {
            set->add_address(m);
        }
    }
    return set;
}

} // namespace

TEST_CASE("conntrack_flush deletes only entries whose dst is in the kpbr snapshot") {
    BlockingExecutor executor(2, 16);

    // Snapshot: pretend kpbr4d_youtube + kpbr4_static together contain these.
    const std::vector<std::string> snapshot_members = {
        "172.217.0.0/16",     // CIDR — Google range
        "1.2.3.4",            // exact match
    };

    // Walker emits a mix of matching and non-matching entries.
    std::vector<ConntrackFlusher::ConntrackEntry> live_entries = {
        make_entry(AF_INET, "172.217.10.50", 0x01),  // matches YouTube CIDR
        make_entry(AF_INET, "8.8.8.8",       0x02),  // NOT in snapshot
        make_entry(AF_INET, "1.2.3.4",       0x03),  // exact match
        make_entry(AF_INET, "192.168.1.1",   0x04),  // LAN, NOT in snapshot
    };

    auto deleted_entries = std::make_shared<std::vector<ConntrackFlusher::ConntrackEntry>>();
    auto deleted_count = std::make_shared<std::atomic<int>>(0);

    ConntrackFlusher flusher(
        &executor,
        // Walker
        [live_entries](const auto& on_entry) {
            for (const auto& e : live_entries) {
                if (!on_entry(e)) return;
            }
        },
        // Deleter
        [deleted_entries, deleted_count](const ConntrackFlusher::ConntrackEntry& e) {
            deleted_entries->push_back(e);
            deleted_count->fetch_add(1);
            return true;
        },
        // Snapshot provider (move into the lambda once; production has only
        // one flush in-flight via the executor queue gate)
        // Rebuild the snapshot from a copyable members vector on each call:
        // a move-captured unique_ptr would make the lambda move-only, which
        // std::function (KpbrIpsetSnapshotProvider) cannot store.
        [snapshot_members](const std::vector<std::string>&) -> std::unique_ptr<IpSet> {
            return make_snapshot(snapshot_members);
        });

    const int queued = flusher.flush_async();
    CHECK(queued == 1);
    wait_for_count(*deleted_count, 2);
    executor.shutdown();

    REQUIRE(deleted_entries->size() == 2);
    CHECK((*deleted_entries)[0].original_dst_ip == "172.217.10.50");
    CHECK((*deleted_entries)[1].original_dst_ip == "1.2.3.4");
    // Blob must round-trip from walker to deleter unmodified — that's how the
    // production deleter knows which kernel-side tuple to remove.
    REQUIRE((*deleted_entries)[0].original_tuple_blob.size() == 1);
    CHECK((*deleted_entries)[0].original_tuple_blob[0] == 0x01);
    CHECK((*deleted_entries)[1].original_tuple_blob[0] == 0x03);
}

TEST_CASE("conntrack_flush handles IPv6 dst addresses against v6 CIDR members") {
    BlockingExecutor executor(2, 16);

    const std::vector<std::string> snapshot_members = {
        "2001:db8::/32",
    };

    std::vector<ConntrackFlusher::ConntrackEntry> live_entries = {
        make_entry(AF_INET6, "2001:db8:1::1"),  // in /32
        make_entry(AF_INET6, "2606:4700::1"),   // Cloudflare, NOT in snapshot
        make_entry(AF_INET,  "10.0.0.1"),       // v4 shouldn't touch v6 trie
    };

    auto deleted_count = std::make_shared<std::atomic<int>>(0);
    auto deleted_entries = std::make_shared<std::vector<std::string>>();

    ConntrackFlusher flusher(
        &executor,
        [live_entries](const auto& on_entry) {
            for (const auto& e : live_entries) {
                if (!on_entry(e)) return;
            }
        },
        [deleted_count, deleted_entries](const ConntrackFlusher::ConntrackEntry& e) {
            deleted_entries->push_back(e.original_dst_ip);
            deleted_count->fetch_add(1);
            return true;
        },
        // Rebuild the snapshot from a copyable members vector on each call:
        // a move-captured unique_ptr would make the lambda move-only, which
        // std::function (KpbrIpsetSnapshotProvider) cannot store.
        [snapshot_members](const std::vector<std::string>&) -> std::unique_ptr<IpSet> {
            return make_snapshot(snapshot_members);
        });

    flusher.flush_async();
    wait_for_count(*deleted_count, 1);
    executor.shutdown();

    REQUIRE(deleted_entries->size() == 1);
    CHECK((*deleted_entries)[0] == "2001:db8:1::1");
}

TEST_CASE("conntrack_flush refuses to delete when snapshot provider returns null") {
    BlockingExecutor executor(2, 16);

    bool walker_called = false;
    auto deleted_count = std::make_shared<std::atomic<int>>(0);

    ConntrackFlusher flusher(
        &executor,
        [&walker_called](const auto& on_entry) {
            walker_called = true;
            // Even if walker were called, we'd never satisfy on_entry's
            // membership test, but we shouldn't even get here — flush_sync
            // must short-circuit before invoking the walker when the
            // snapshot is unavailable. This guarantees we never accidentally
            // flush every conntrack entry on the box just because `ipset` is
            // missing.
            (void)on_entry;
        },
        [deleted_count](const ConntrackFlusher::ConntrackEntry&) {
            deleted_count->fetch_add(1);
            return true;
        },
        [](const std::vector<std::string>&) -> std::unique_ptr<IpSet> { return nullptr; });

    const int rc = flusher.flush_sync();
    CHECK(rc == -1);            // hard failure
    CHECK_FALSE(walker_called); // walker never invoked
    CHECK(deleted_count->load() == 0);
    executor.shutdown();
}

TEST_CASE("conntrack_flush skips entries with empty dst IP without crashing") {
    BlockingExecutor executor(2, 16);

    const std::vector<std::string> snapshot_members = {"1.2.3.4"};

    // First entry has an empty dst (would happen if the netlink parser
    // couldn't decode the tuple); we must skip it rather than passing the
    // empty string into IpSet::contains (which would throw and we'd want
    // to swallow that too).
    std::vector<ConntrackFlusher::ConntrackEntry> live_entries = {
        make_entry(AF_INET, ""),
        make_entry(AF_INET, "1.2.3.4"),
    };

    auto deleted_count = std::make_shared<std::atomic<int>>(0);
    ConntrackFlusher flusher(
        &executor,
        [live_entries](const auto& on_entry) {
            for (const auto& e : live_entries) {
                if (!on_entry(e)) return;
            }
        },
        [deleted_count](const ConntrackFlusher::ConntrackEntry&) {
            deleted_count->fetch_add(1);
            return true;
        },
        // Rebuild the snapshot from a copyable members vector on each call:
        // a move-captured unique_ptr would make the lambda move-only, which
        // std::function (KpbrIpsetSnapshotProvider) cannot store.
        [snapshot_members](const std::vector<std::string>&) -> std::unique_ptr<IpSet> {
            return make_snapshot(snapshot_members);
        });

    flusher.flush_async();
    wait_for_count(*deleted_count, 1);
    executor.shutdown();

    // Only the real entry got deleted; the empty-dst one was skipped.
    CHECK(deleted_count->load() == 1);
}

TEST_CASE("conntrack_flush continues even when deleter throws on one entry") {
    BlockingExecutor executor(2, 16);

    const std::vector<std::string> snapshot_members = {"1.2.3.4", "5.6.7.8"};

    std::vector<ConntrackFlusher::ConntrackEntry> live_entries = {
        make_entry(AF_INET, "1.2.3.4"),
        make_entry(AF_INET, "5.6.7.8"),
    };

    auto deleted_count = std::make_shared<std::atomic<int>>(0);
    auto throw_count = std::make_shared<std::atomic<int>>(0);

    ConntrackFlusher flusher(
        &executor,
        [live_entries](const auto& on_entry) {
            for (const auto& e : live_entries) {
                if (!on_entry(e)) return;
            }
        },
        [deleted_count, throw_count](const ConntrackFlusher::ConntrackEntry& e) -> bool {
            if (e.original_dst_ip == "1.2.3.4") {
                throw_count->fetch_add(1);
                throw std::runtime_error("simulated netlink delete failure");
            }
            deleted_count->fetch_add(1);
            return true;
        },
        // Rebuild the snapshot from a copyable members vector on each call:
        // a move-captured unique_ptr would make the lambda move-only, which
        // std::function (KpbrIpsetSnapshotProvider) cannot store.
        [snapshot_members](const std::vector<std::string>&) -> std::unique_ptr<IpSet> {
            return make_snapshot(snapshot_members);
        });

    flusher.flush_async();
    wait_for_count(*deleted_count, 1);
    executor.shutdown();

    CHECK(throw_count->load() == 1);
    CHECK(deleted_count->load() == 1); // 5.6.7.8 still got deleted
}

TEST_CASE("conntrack_flush returns 0 when no entries are in the snapshot") {
    BlockingExecutor executor(2, 16);

    const std::vector<std::string> snapshot_members = {"10.0.0.0/24"};

    // Nothing here is in 10.0.0.0/24.
    std::vector<ConntrackFlusher::ConntrackEntry> live_entries = {
        make_entry(AF_INET, "8.8.8.8"),
        make_entry(AF_INET, "1.1.1.1"),
        make_entry(AF_INET, "172.217.10.10"),
    };

    auto deleted_count = std::make_shared<std::atomic<int>>(0);
    ConntrackFlusher flusher(
        &executor,
        [live_entries](const auto& on_entry) {
            for (const auto& e : live_entries) {
                if (!on_entry(e)) return;
            }
        },
        [deleted_count](const ConntrackFlusher::ConntrackEntry&) {
            deleted_count->fetch_add(1);
            return true;
        },
        // Rebuild the snapshot from a copyable members vector on each call:
        // a move-captured unique_ptr would make the lambda move-only, which
        // std::function (KpbrIpsetSnapshotProvider) cannot store.
        [snapshot_members](const std::vector<std::string>&) -> std::unique_ptr<IpSet> {
            return make_snapshot(snapshot_members);
        });

    const int rc = flusher.flush_sync();
    CHECK(rc == 0);
    CHECK(deleted_count->load() == 0);
    executor.shutdown();
}

TEST_CASE("conntrack_flush does not invalidate non-PBR flows (e.g. LAN-LAN, public DNS)") {
    // Acceptance criterion from the plan: "Filter aggressively. Don't touch
    // anything else (that would terminate user sessions to Yandex etc.
    // unnecessarily)." This test pins the policy: only entries whose dst is
    // in a kpbr* member set get touched; everything else — LAN-LAN,
    // public DNS, the user's banking session, the router's WAN handshake —
    // must remain intact across a SIGUSR1.
    BlockingExecutor executor(2, 16);

    // Modest PBR-managed footprint.
    const std::vector<std::string> snapshot_members = {
        "172.217.0.0/16",
    };

    std::vector<ConntrackFlusher::ConntrackEntry> live_entries = {
        make_entry(AF_INET, "172.217.10.50", 0xAA),  // YouTube, should die
        make_entry(AF_INET, "192.168.1.10",  0xBB),  // LAN client
        make_entry(AF_INET, "10.0.0.5",      0xCC),  // Other LAN
        make_entry(AF_INET, "8.8.8.8",       0xDD),  // Public DNS
        make_entry(AF_INET, "5.255.255.55",  0xEE),  // Yandex (not PBR'd)
    };

    auto deleted_blobs = std::make_shared<std::vector<uint8_t>>();
    auto deleted_count = std::make_shared<std::atomic<int>>(0);

    ConntrackFlusher flusher(
        &executor,
        [live_entries](const auto& on_entry) {
            for (const auto& e : live_entries) {
                if (!on_entry(e)) return;
            }
        },
        [deleted_blobs, deleted_count](const ConntrackFlusher::ConntrackEntry& e) {
            REQUIRE(!e.original_tuple_blob.empty());
            deleted_blobs->push_back(e.original_tuple_blob.front());
            deleted_count->fetch_add(1);
            return true;
        },
        // Rebuild the snapshot from a copyable members vector on each call:
        // a move-captured unique_ptr would make the lambda move-only, which
        // std::function (KpbrIpsetSnapshotProvider) cannot store.
        [snapshot_members](const std::vector<std::string>&) -> std::unique_ptr<IpSet> {
            return make_snapshot(snapshot_members);
        });

    flusher.flush_async();
    wait_for_count(*deleted_count, 1);
    executor.shutdown();

    REQUIRE(deleted_blobs->size() == 1);
    // The ONLY blob we should have deleted is the YouTube one (0xAA).
    CHECK((*deleted_blobs)[0] == 0xAA);
}
