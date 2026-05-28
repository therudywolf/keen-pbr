#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace keen_pbr3 {

// Why this exists
// ===============
// IP-based policy routing can't distinguish two domains that share a CDN's IP
// pool (e.g. drive.google.com vs www.youtube.com, both on Google's edges, or
// every Cloudflare-fronted service). The only place the client states which
// host it wants is the SNI (Server Name Indication) field of the TLS
// ClientHello — sent in plaintext for TLS 1.2 and TLS 1.3 (absent only when
// Encrypted Client Hello is in use, still rare). Parsing it lets us route by
// hostname instead of by IP.
//
// This parser is deliberately pure and dependency-free so it can be unit-tested
// against captured ClientHello bytes with no network or kernel involvement.

enum class SniParseStatus {
    Found,         // hostname is populated with the SNI value
    NeedMoreData,  // the ClientHello legitimately extends past this buffer
    NoSni,         // valid ClientHello but no usable server_name (or ECH)
    NotTls,        // not a TLS handshake / ClientHello at all
};

struct SniParseResult {
    SniParseStatus status;
    std::string hostname;  // valid only when status == Found
};

// Parse the SNI host_name out of a TLS ClientHello at the start of `data`.
// `data`/`len` is the raw TCP payload of the first segment of a connection.
// Never reads out of bounds; on any malformed/truncated structure it returns
// NeedMoreData (if plausibly just truncated) or NotTls/NoSni (if definitively
// not extractable). The returned hostname is lowercased and stripped of a
// trailing dot.
SniParseResult parse_tls_sni(const uint8_t* data, std::size_t len);

}  // namespace keen_pbr3
