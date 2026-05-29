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

std::optional<uint32_t> extract_ipv4_dst(const uint8_t* pkt, std::size_t len) {
    if (pkt == nullptr || len < kIpv4MinHeader) {
        return std::nullopt;
    }
    if (static_cast<uint8_t>(pkt[0] >> 4) != 4) {
        return std::nullopt;  // not IPv4 (IPv6 has no fixed dst at this offset)
    }
    // IPv4 destination address occupies bytes 16..19. Assemble big-endian into a
    // host-order integer (192.0.2.1 -> 0xC0000201), matching parse_ipv4_to_key().
    return (static_cast<uint32_t>(pkt[16]) << 24) |
           (static_cast<uint32_t>(pkt[17]) << 16) |
           (static_cast<uint32_t>(pkt[18]) << 8) |
           (static_cast<uint32_t>(pkt[19]));
}

std::optional<uint32_t> parse_ipv4_to_key(const char* s, std::size_t len) {
    if (s == nullptr || len == 0) {
        return std::nullopt;
    }
    uint32_t result = 0;
    int octets = 0;
    std::size_t i = 0;
    while (i < len) {
        std::size_t digits = 0;
        uint32_t value = 0;
        while (i < len && s[i] >= '0' && s[i] <= '9') {
            value = value * 10u + static_cast<uint32_t>(s[i] - '0');
            ++digits;
            ++i;
            if (digits > 3) {
                return std::nullopt;
            }
        }
        if (digits == 0 || value > 255) {
            return std::nullopt;
        }
        result = (result << 8) | value;
        ++octets;
        if (octets > 4) {
            return std::nullopt;
        }
        if (i < len) {
            if (s[i] != '.') {
                return std::nullopt;
            }
            ++i;
            if (i >= len) {
                return std::nullopt;  // trailing dot
            }
        }
    }
    if (octets != 4) {
        return std::nullopt;
    }
    return result;
}

}  // namespace keen_pbr3
