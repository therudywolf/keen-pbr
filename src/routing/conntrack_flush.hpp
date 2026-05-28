#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace keen_pbr3 {

class BlockingExecutor;
class IpSet;

// Why this exists
// ===============
// Conntrack caches a routing decision per flow. Once an entry is established
// for a given (src,dst,proto,ports) tuple, kernel netfilter — especially with
// Keenetic's [FASTNAT] shortcut — skips mangle and reuses the cached fwmark,
// so the flow keeps its prior PBR routing decision until it naturally times
// out (hours for TCP ESTABLISHED). When the operator changes a list, applies
// a different config, or the warmer adds fresh IPs to a kpbr* set, the new
// routing is invisible to existing flows: phone YouTube keeps going via WAN
// even after the config swap.
//
// ConntrackFlusher walks the live conntrack table and deletes every entry
// whose original-tuple destination IP is currently a member of one of our
// owned kpbr[46](d)?_* ipsets, forcing the flow to be re-evaluated from
// scratch on its next packet. It does NOT touch any other connection (we
// don't want to drop the user's SSH session to a non-PBR target).
//
// The flush runs on a BlockingExecutor task so it cannot stall the daemon
// event loop. It uses raw netlink (NETLINK_NETFILTER + NFNL_SUBSYS_CTNETLINK)
// directly — no libnl-nf-3, no conntrack-tools shell-out — keeping the
// dependency footprint at exactly the libnl-3 that's already linked.
//
// On kernels without NF_CONNTRACK_NETLINK (rare on Keenetic but possible on
// stripped third-party builds), the netlink socket fails to bind and the
// flush logs a warning and exits cleanly. The daemon keeps running.
class ConntrackFlusher {
public:
    // Snapshot of one conntrack entry, captured by the netlink walker and
    // tested against the kpbr ipset membership snapshot. Only the bits the
    // flush logic needs are extracted; everything else stays opaque on the
    // wire. The deleter callback receives the original entry tuple bytes so
    // it can issue the matching IPCTNL_MSG_CT_DELETE.
    struct ConntrackEntry {
        uint8_t family{0};                       // AF_INET / AF_INET6
        std::string original_dst_ip;             // dotted/colon form, e.g. "1.2.3.4"
        // Opaque payload identifying this entry to the kernel: the original
        // CTA_TUPLE_ORIG attribute bytes (NLA-encoded) plus the protocol
        // number. The deleter sends an IPCTNL_MSG_CT_DELETE carrying these
        // verbatim, which uniquely identifies the entry to be removed.
        std::vector<uint8_t> original_tuple_blob;
    };

    // Yields every live conntrack entry by invoking the callback once per
    // entry. Returning false from the callback stops the walk early. Real
    // implementation talks netlink; tests substitute an in-memory list.
    using ConntrackWalker = std::function<void(
        const std::function<bool(const ConntrackEntry&)>& on_entry)>;

    // Deletes one conntrack entry. Real implementation sends IPCTNL_MSG_CT_DELETE
    // over the netlink socket; tests record the deletion. Returns true if the
    // kernel acknowledged the delete (or the entry was already gone).
    using ConntrackDeleter = std::function<bool(const ConntrackEntry&)>;

    // Returns a snapshot of every IP/CIDR currently in any of our kpbr* sets,
    // packed into an IpSet for O(W) lookup. Real implementation shells out to
    // `ipset list -n` and `ipset save <set>`; tests inject a prebuilt IpSet.
    // Returns an empty unique_ptr on failure (e.g. ipset binary missing); the
    // flush then becomes a no-op (we never delete on a stale or absent snapshot).
    using KpbrIpsetSnapshotProvider = std::function<std::unique_ptr<IpSet>()>;

    explicit ConntrackFlusher(BlockingExecutor* executor);

    // Test-only / dependency-injection constructor. Lets tests substitute the
    // netlink walker, the deleter, and the kpbr-membership snapshot without
    // touching the kernel.
    ConntrackFlusher(BlockingExecutor* executor,
                     ConntrackWalker walker,
                     ConntrackDeleter deleter,
                     KpbrIpsetSnapshotProvider snapshot_provider);

    // Submit one flush pass. Returns the number of work items queued (0 or 1,
    // since the walk is one task — keeps the executor queue from being flooded
    // by repeated SIGUSR1 storms). Non-blocking; work runs on the executor.
    int flush_async();

    // Run one flush pass synchronously. Returns the number of conntrack
    // entries deleted, or -1 on hard failure (e.g. netlink unavailable).
    // Exposed for unit tests; production callers should use flush_async().
    int flush_sync();

private:
    BlockingExecutor* executor_;
    ConntrackWalker walker_;
    ConntrackDeleter deleter_;
    KpbrIpsetSnapshotProvider snapshot_provider_;
};

// Default kpbr ipset membership snapshot provider — shells out to ipset.
// Returns nullptr if `ipset list -n` fails (e.g. ipset binary missing or
// kernel module unloaded). Exposed in the header so the daemon can override
// it in tests without rebuilding the production flusher.
std::unique_ptr<IpSet> default_kpbr_ipset_snapshot();

// Default netlink-backed conntrack walker. Opens a NETLINK_NETFILTER socket,
// issues an IPCTNL_MSG_CT_GET dump, parses each entry, and invokes the
// callback. Logs a warning and returns silently if the socket cannot be
// opened (kernel without NF_CONNTRACK_NETLINK).
void default_conntrack_walker(
    const std::function<bool(const ConntrackFlusher::ConntrackEntry&)>& on_entry);

// Default netlink-backed conntrack deleter. Sends an IPCTNL_MSG_CT_DELETE
// carrying the entry's original tuple. Returns true if the kernel acked or
// the entry was already gone (ENOENT — race with natural expiry, harmless).
bool default_conntrack_delete(const ConntrackFlusher::ConntrackEntry& entry);

} // namespace keen_pbr3
