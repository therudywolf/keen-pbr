#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>

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

// Extract the destination IPv4 address from a raw IPv4 packet as NFQUEUE
// delivers it (the buffer starts at the IP header). Returns the address as a
// host-order integer assembled big-endian from the four header bytes — i.e.
// 192.0.2.1 yields 0xC0000201, independent of the host's own endianness. This
// is the same representation parse_ipv4_to_key() produces from a dotted-quad
// string, so the DNS-split correlation table can be keyed identically whether an
// IP arrives from a packet (here) or a dnsmasq log line (the observer).
//
// Returns nullopt when the packet is not IPv4 or is too short to contain the
// destination-address field. Pure, bounds-checked byte math with no kernel
// dependency, so the DNS-split SYN-mark demux is unit-testable on its own.
std::optional<uint32_t> extract_ipv4_dst(const uint8_t* ip_packet, std::size_t len);

// Parse a dotted-quad IPv4 string into the SAME host-order, big-endian-assembled
// key extract_ipv4_dst() returns (192.0.2.1 -> 0xC0000201). Returns nullopt if
// the string is not a strict dotted-quad. Used by the DNS-split observer so the
// key it stores for a resolved IP matches the key the NFQUEUE handler derives
// from a packet's destination address.
std::optional<uint32_t> parse_ipv4_to_key(const char* s, std::size_t len);

}  // namespace keen_pbr3
