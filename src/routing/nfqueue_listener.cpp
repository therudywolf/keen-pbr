#include "nfqueue_listener.hpp"

#include <memory>
#include <utility>

#include "../log/logger.hpp"
#include "sni_router.hpp"
#include "tcp_payload.hpp"

#ifdef KEEN_PBR_HAVE_NFQUEUE
#include <arpa/inet.h>
#include <linux/netfilter.h>  // NF_ACCEPT
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <vector>

#include <libnetfilter_queue/libnetfilter_queue.h>
#endif

namespace keen_pbr3 {

#ifdef KEEN_PBR_HAVE_NFQUEUE
namespace {

// Copy enough of each packet to capture the TLS ClientHello. A single MTU-sized
// first segment is far smaller, but asking for the whole packet costs nothing
// here and avoids ever clipping a large ClientHello.
constexpr unsigned int kCopyLen = 0xFFFF;
constexpr unsigned int kQueueMaxLen = 1024;
constexpr std::size_t kRecvBufferBytes = 0x10000;  // 64 KiB

int packet_callback(struct nfq_q_handle* qh, struct nfgenmsg* /*nfmsg*/,
                    struct nfq_data* nfa, void* data) {
    const auto* decider = static_cast<const NfqueueListener::MarkDecider*>(data);

    struct nfqnl_msg_packet_hdr* ph = nfq_get_msg_packet_hdr(nfa);
    if (ph == nullptr) {
        return 0;  // nothing to act on; no verdict id available
    }
    const uint32_t id = ntohl(ph->packet_id);

    unsigned char* payload = nullptr;
    const int plen = nfq_get_payload(nfa, &payload);
    if (plen <= 0 || payload == nullptr || decider == nullptr || !*decider) {
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);
    }

    std::optional<uint32_t> mark =
        (*decider)(payload, static_cast<std::size_t>(plen));
    if (mark.has_value()) {
        return nfq_set_verdict2(qh, id, NF_ACCEPT, *mark, 0, nullptr);
    }
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);
}

}  // namespace
#endif  // KEEN_PBR_HAVE_NFQUEUE

namespace {

// Build a decider that parses each packet's first TCP segment for a TLS SNI and
// maps the hostname to a fwmark via SniRouter. Used by the convenience ctor so
// the original SNI-based path stays compiled and exercised.
NfqueueListener::MarkDecider make_sni_decider(std::map<std::string, uint32_t> domain_marks) {
    auto router = std::make_shared<SniRouter>(std::move(domain_marks));
    return [router](const uint8_t* ip_packet,
                    std::size_t len) -> std::optional<uint32_t> {
        const L4Slice l4 = locate_tcp_payload(ip_packet, len);
        if (!l4) {
            return std::nullopt;
        }
        const SniDecision decision = router->decide(l4.data, l4.len);
        if (decision.action == SniAction::SetMark) {
            return decision.mark;
        }
        return std::nullopt;
    };
}

}  // namespace

struct NfqueueListener::Impl {
#ifdef KEEN_PBR_HAVE_NFQUEUE
    struct nfq_handle* h = nullptr;
    struct nfq_q_handle* qh = nullptr;
    int fd = -1;
    std::vector<uint8_t> buf;
#endif
};

NfqueueListener::NfqueueListener(uint16_t queue_num, MarkDecider decider)
    : queue_num_(queue_num), decider_(std::move(decider)) {}

NfqueueListener::NfqueueListener(uint16_t queue_num,
                                 std::map<std::string, uint32_t> domain_marks)
    : queue_num_(queue_num), decider_(make_sni_decider(std::move(domain_marks))) {}

NfqueueListener::~NfqueueListener() {
    close();
}

bool NfqueueListener::supported() {
#ifdef KEEN_PBR_HAVE_NFQUEUE
    return true;
#else
    return false;
#endif
}

bool NfqueueListener::open() {
#ifdef KEEN_PBR_HAVE_NFQUEUE
    if (impl_ && impl_->h != nullptr) {
        return true;  // already open
    }
    impl_ = std::make_unique<Impl>();
    impl_->buf.resize(kRecvBufferBytes);

    impl_->h = nfq_open();
    if (impl_->h == nullptr) {
        Logger::instance().error("nfqueue: nfq_open failed: {}", std::strerror(errno));
        close();
        return false;
    }
    // Legacy pf (un)bind: a no-op on modern kernels but harmless to issue.
    nfq_unbind_pf(impl_->h, AF_INET);
    if (nfq_bind_pf(impl_->h, AF_INET) < 0) {
        Logger::instance().error("nfqueue: nfq_bind_pf(AF_INET) failed");
        close();
        return false;
    }

    impl_->qh = nfq_create_queue(impl_->h, queue_num_, &packet_callback, &decider_);
    if (impl_->qh == nullptr) {
        Logger::instance().error("nfqueue: nfq_create_queue({}) failed: {}", queue_num_,
                                 std::strerror(errno));
        close();
        return false;
    }
    if (nfq_set_mode(impl_->qh, NFQNL_COPY_PACKET, kCopyLen) < 0) {
        Logger::instance().error("nfqueue: nfq_set_mode failed");
        close();
        return false;
    }
    nfq_set_queue_maxlen(impl_->qh, kQueueMaxLen);
    // Fail-open: if the queue fills, let packets through (they route by IP)
    // rather than dropping them. This routing must never break connectivity.
    nfq_set_queue_flags(impl_->qh, NFQA_CFG_F_FAIL_OPEN, NFQA_CFG_F_FAIL_OPEN);

    impl_->fd = nfq_fd(impl_->h);
    Logger::instance().info("nfqueue: listener bound to queue {}", queue_num_);
    return true;
#else
    Logger::instance().warn(
        "nfqueue: NFQUEUE routing requested but this build lacks libnetfilter_queue support");
    return false;
#endif
}

int NfqueueListener::fd() const {
#ifdef KEEN_PBR_HAVE_NFQUEUE
    return impl_ ? impl_->fd : -1;
#else
    return -1;
#endif
}

void NfqueueListener::handle_readable() {
#ifdef KEEN_PBR_HAVE_NFQUEUE
    if (!impl_ || impl_->fd < 0) {
        return;
    }
    for (;;) {
        const ssize_t n =
            recv(impl_->fd, impl_->buf.data(), impl_->buf.size(), MSG_DONTWAIT);
        if (n > 0) {
            nfq_handle_packet(impl_->h, reinterpret_cast<char*>(impl_->buf.data()),
                              static_cast<int>(n));
            continue;
        }
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;  // queue drained
            }
            if (errno == ENOBUFS) {
                // Kernel queue overran; those packets were fail-open accepted.
                Logger::instance().warn("nfqueue: recv ENOBUFS (queue overrun)");
                break;
            }
            Logger::instance().error("nfqueue: recv failed: {}", std::strerror(errno));
            break;
        }
        break;  // n == 0
    }
#endif
}

void NfqueueListener::close() {
#ifdef KEEN_PBR_HAVE_NFQUEUE
    if (!impl_) {
        return;
    }
    if (impl_->qh != nullptr) {
        nfq_destroy_queue(impl_->qh);
        impl_->qh = nullptr;
    }
    if (impl_->h != nullptr) {
        nfq_close(impl_->h);
        impl_->h = nullptr;
    }
    impl_->fd = -1;
#endif
}

}  // namespace keen_pbr3
