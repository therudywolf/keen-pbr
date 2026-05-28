#include "tcp_payload.hpp"

namespace keen_pbr3 {

namespace {
constexpr uint8_t kProtoTcp = 6;
constexpr std::size_t kIpv4MinHeader = 20;
constexpr std::size_t kIpv6Header = 40;
constexpr std::size_t kTcpMinHeader = 20;
}  // namespace

L4Slice locate_tcp_payload(const uint8_t* pkt, std::size_t len) {
    if (pkt == nullptr || len < 1) {
        return {};
    }

    const uint8_t version = static_cast<uint8_t>(pkt[0] >> 4);
    std::size_t l3_len = 0;
    uint8_t proto = 0;

    if (version == 4) {
        if (len < kIpv4MinHeader) {
            return {};
        }
        l3_len = static_cast<std::size_t>(pkt[0] & 0x0f) * 4u;  // IHL, in 32-bit words
        if (l3_len < kIpv4MinHeader || len < l3_len) {
            return {};
        }
        proto = pkt[9];
    } else if (version == 6) {
        if (len < kIpv6Header) {
            return {};
        }
        proto = pkt[6];  // next header; extension-header chains are not decoded
        l3_len = kIpv6Header;
    } else {
        return {};
    }

    if (proto != kProtoTcp) {
        return {};
    }
    if (len < l3_len + kTcpMinHeader) {
        return {};
    }

    // TCP data offset: high nibble of the 13th TCP byte, in 32-bit words.
    const std::size_t tcp_hdr_len = static_cast<std::size_t>(pkt[l3_len + 12] >> 4) * 4u;
    if (tcp_hdr_len < kTcpMinHeader) {
        return {};
    }
    const std::size_t l4_off = l3_len + tcp_hdr_len;
    if (len < l4_off) {
        return {};
    }
    return L4Slice{pkt + l4_off, len - l4_off};
}

}  // namespace keen_pbr3
