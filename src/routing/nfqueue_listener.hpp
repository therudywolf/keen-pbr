#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>

namespace keen_pbr3 {

// Netfilter I/O shell. Binds an NFQUEUE, and for each enqueued packet asks a
// caller-supplied decider for a verdict mark, then re-injects the packet
// carrying that fwmark (via nfq_set_verdict2) or unchanged. Exposes a pollable
// fd so the daemon's epoll loop drives it, mirroring DnsProbeServer — no
// internal thread.
//
// The decision is a callback so the same I/O shell serves more than one routing
// strategy:
//   * DNS-correlation split routing passes a decider that parses the packet's
//     destination IPv4 and looks it up in the DnsSplitTable (the daemon uses
//     this path).
//   * SNI-based routing passes a decider built from a domain->mark map that
//     parses the TLS ClientHello (kept for the existing tests / future use).
//
// Fully functional only when the build found libnetfilter_queue
// (KEEN_PBR_HAVE_NFQUEUE). Otherwise open() is a logged no-op returning false,
// so the daemon still links and runs and the feature simply stays unavailable.
class NfqueueListener {
public:
    // Decide a verdict for one enqueued packet, given the raw bytes starting at
    // the IP header. Returns the fwmark to stamp (nfq_set_verdict2 NF_ACCEPT
    // mark) or nullopt to accept the packet unchanged. Must be cheap and must
    // never throw — it runs inside the netfilter callback. Fail-open: on any
    // doubt, return nullopt so traffic is never blocked.
    using MarkDecider =
        std::function<std::optional<uint32_t>(const uint8_t* ip_packet, std::size_t len)>;

    // Generic constructor: bind `queue_num` and consult `decider` per packet.
    NfqueueListener(uint16_t queue_num, MarkDecider decider);

    // Convenience constructor that builds an SNI-based decider from a
    // domain->mark map (parses each first segment's TLS ClientHello). Kept so
    // the original SNI path stays exercised; the daemon uses the generic ctor.
    NfqueueListener(uint16_t queue_num, std::map<std::string, uint32_t> domain_marks);

    ~NfqueueListener();

    NfqueueListener(const NfqueueListener&) = delete;
    NfqueueListener& operator=(const NfqueueListener&) = delete;

    // Whether this build was compiled with NFQUEUE support at all.
    static bool supported();

    // Bind the queue. Returns false if unsupported or binding failed; callers
    // then proceed without this routing (connections route by IP as before).
    bool open();

    // The pollable netfilter fd, or -1 when not open. Register it with EPOLLIN.
    int fd() const;

    // Drain ready packets and issue verdicts. Call when fd() reports readable.
    void handle_readable();

    // Release the queue. Idempotent; also invoked by the destructor.
    void close();

private:
    uint16_t queue_num_;
    MarkDecider decider_;

    struct Impl;  // hides libnetfilter_queue handles from this header
    std::unique_ptr<Impl> impl_;
};

}  // namespace keen_pbr3
