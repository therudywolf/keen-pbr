#pragma once

#include <cstddef>
#include <cstdint>

namespace keen_pbr3 {

// A view into someone else's buffer: the TCP payload bytes of a packet.
struct L4Slice {
    const uint8_t* data = nullptr;
    std::size_t len = 0;
    // True when a TCP payload was located (len may still be 0 for a bare ACK).
    explicit operator bool() const { return data != nullptr; }
};

// Locate the TCP payload inside a raw IP packet as NFQUEUE delivers it (the
// buffer starts at the IP header). Returns a slice pointing into `ip_packet`,
// or an empty slice (data == nullptr) when the packet is not TCP, is truncated,
// or uses an L3 version / IPv6 extension-header chain this does not decode.
//
// Pure, fully bounds-checked byte math with no kernel/netfilter dependency, so
// the demux that feeds SniRouter::decide() is unit-testable on its own.
L4Slice locate_tcp_payload(const uint8_t* ip_packet, std::size_t len);

}  // namespace keen_pbr3
