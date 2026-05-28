#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>

#include "sni_classifier.hpp"

namespace keen_pbr3 {

// What the NFQUEUE handler should do with a packet after inspecting its TLS SNI.
enum class SniAction {
    SetMark,       // SNI matched a configured domain -> set `mark`, then accept
    Accept,        // accept unchanged: not TLS, no SNI, or SNI matched no rule
    NeedMoreData,  // ClientHello continues past this segment. We only get one
                   // inspection shot (first-segment iptables match), so callers
                   // treat this like Accept; it is surfaced separately so the
                   // rare truncated-hello case is visible in logs/metrics.
};

struct SniDecision {
    SniAction action = SniAction::Accept;
    uint32_t mark = 0;     // meaningful only when action == SetMark
    std::string hostname;  // parsed SNI, for logging; empty when none found
};

// Decision core for SNI-based routing: given the first TCP payload bytes of a
// tcp/443 connection, decide which fwmark (if any) the connection should carry
// based on its TLS SNI. This is what lets two domains on one shared CDN IP take
// different outbounds (drive.google.com -> WAN while www.youtube.com -> VPN),
// which IP-based ipset routing fundamentally cannot do.
//
// Intentionally free of any kernel/NFQUEUE dependency so the decision logic is
// fully unit-testable against crafted ClientHello bytes; the netfilter I/O shell
// (NfqueueListener) calls into this.
class SniRouter {
public:
    explicit SniRouter(std::map<std::string, uint32_t> domain_marks);

    // Inspect the first TCP payload bytes of a tcp/443 connection.
    SniDecision decide(const uint8_t* tcp_payload, std::size_t len) const;

    std::size_t domain_count() const { return classifier_.size(); }

private:
    SniClassifier classifier_;
};

}  // namespace keen_pbr3
