#pragma once

#include <cstdint>
#include <map>
#include <memory>
#include <string>

#include "sni_router.hpp"

namespace keen_pbr3 {

// Netfilter I/O shell around SniRouter. Binds an NFQUEUE, reads the first
// segment of each enqueued tcp/443 connection, asks SniRouter for a verdict,
// and re-injects the packet carrying the chosen fwmark (via nfq_set_verdict2)
// or unchanged. Exposes a pollable fd so the daemon's epoll loop drives it,
// mirroring DnsProbeServer — no internal thread.
//
// Fully functional only when the build found libnetfilter_queue
// (KEEN_PBR_HAVE_NFQUEUE). Otherwise open() is a logged no-op returning false,
// so the daemon still links and runs and SNI routing simply stays unavailable.
class NfqueueListener {
public:
    NfqueueListener(uint16_t queue_num, std::map<std::string, uint32_t> domain_marks);
    ~NfqueueListener();

    NfqueueListener(const NfqueueListener&) = delete;
    NfqueueListener& operator=(const NfqueueListener&) = delete;

    // Whether this build was compiled with NFQUEUE support at all.
    static bool supported();

    // Bind the queue. Returns false if unsupported or binding failed; callers
    // then proceed without SNI routing (connections route by IP as before).
    bool open();

    // The pollable netfilter fd, or -1 when not open. Register it with EPOLLIN.
    int fd() const;

    // Drain ready packets and issue verdicts. Call when fd() reports readable.
    void handle_readable();

    // Release the queue. Idempotent; also invoked by the destructor.
    void close();

private:
    uint16_t queue_num_;
    SniRouter router_;

    struct Impl;  // hides libnetfilter_queue handles from this header
    std::unique_ptr<Impl> impl_;
};

}  // namespace keen_pbr3
