#include <doctest/doctest.h>

#include "../src/routing/tcp_payload.hpp"

#include <algorithm>
#include <cstdint>
#include <vector>

using namespace keen_pbr3;

namespace {

// Build an IPv4+TCP packet. ihl_words/tcp_doff_words let tests exercise IP
// options and TCP options; proto lets a test claim a non-TCP protocol.
std::vector<uint8_t> ipv4_tcp(const std::vector<uint8_t>& payload,
                              uint8_t ihl_words = 5,
                              uint8_t tcp_doff_words = 5,
                              uint8_t proto = 6) {
    const std::size_t l3 = static_cast<std::size_t>(ihl_words) * 4u;
    const std::size_t l4hdr = static_cast<std::size_t>(tcp_doff_words) * 4u;
    std::vector<uint8_t> p(l3 + l4hdr + payload.size(), 0);
    p[0] = static_cast<uint8_t>((4u << 4) | ihl_words);
    p[9] = proto;
    p[l3 + 12] = static_cast<uint8_t>(tcp_doff_words << 4);
    std::copy(payload.begin(), payload.end(), p.begin() + l3 + l4hdr);
    return p;
}

}  // namespace

TEST_CASE("locate_tcp_payload: ipv4 minimal headers yields the payload") {
    const auto p = ipv4_tcp({0xDE, 0xAD, 0xBE, 0xEF});
    const auto s = locate_tcp_payload(p.data(), p.size());
    REQUIRE(static_cast<bool>(s));
    REQUIRE(s.len == 4);
    CHECK(s.data[0] == 0xDE);
    CHECK(s.data[3] == 0xEF);
}

TEST_CASE("locate_tcp_payload: ipv4 options + tcp options offsets are honored") {
    const auto p = ipv4_tcp({1, 2, 3}, /*ihl*/ 6, /*tcp_doff*/ 7);
    const auto s = locate_tcp_payload(p.data(), p.size());
    REQUIRE(static_cast<bool>(s));
    CHECK(s.len == 3);
    CHECK(s.data[0] == 1);
    CHECK(s.data[2] == 3);
}

TEST_CASE("locate_tcp_payload: non-TCP protocol returns empty") {
    const auto p = ipv4_tcp({1, 2, 3}, 5, 5, /*proto=UDP*/ 17);
    CHECK_FALSE(static_cast<bool>(locate_tcp_payload(p.data(), p.size())));
}

TEST_CASE("locate_tcp_payload: bare ACK (zero payload) is located with len 0") {
    const auto p = ipv4_tcp({});
    const auto s = locate_tcp_payload(p.data(), p.size());
    REQUIRE(static_cast<bool>(s));  // TCP found...
    CHECK(s.len == 0);              // ...but no payload bytes
}

TEST_CASE("locate_tcp_payload: truncated before end of TCP header returns empty") {
    auto p = ipv4_tcp({}, 5, 5);
    p.resize(25);  // ipv4(20) + only 5 of 20 TCP header bytes
    CHECK_FALSE(static_cast<bool>(locate_tcp_payload(p.data(), p.size())));
}

TEST_CASE("locate_tcp_payload: IHL below the 20-byte minimum is rejected") {
    auto p = ipv4_tcp({1, 2, 3});
    p[0] = static_cast<uint8_t>((4u << 4) | 4u);  // IHL = 4 words = 16 bytes < 20
    CHECK_FALSE(static_cast<bool>(locate_tcp_payload(p.data(), p.size())));
}

TEST_CASE("locate_tcp_payload: tcp data offset below minimum is rejected") {
    auto p = ipv4_tcp({1, 2, 3});
    p[20 + 12] = static_cast<uint8_t>(4u << 4);  // TCP doff = 4 words = 16 < 20
    CHECK_FALSE(static_cast<bool>(locate_tcp_payload(p.data(), p.size())));
}

TEST_CASE("locate_tcp_payload: ipv6 with TCP as next header") {
    std::vector<uint8_t> p(40 + 20 + 2, 0);
    p[0] = static_cast<uint8_t>(6u << 4);
    p[6] = 6;                 // next header = TCP
    p[40 + 12] = (5u << 4);   // TCP data offset 5 words
    p[60] = 0xAB;
    p[61] = 0xCD;
    const auto s = locate_tcp_payload(p.data(), p.size());
    REQUIRE(static_cast<bool>(s));
    REQUIRE(s.len == 2);
    CHECK(s.data[0] == 0xAB);
    CHECK(s.data[1] == 0xCD);
}

TEST_CASE("locate_tcp_payload: unknown version, null, and empty are rejected") {
    CHECK_FALSE(static_cast<bool>(locate_tcp_payload(nullptr, 0)));
    std::vector<uint8_t> p(20, 0);
    p[0] = static_cast<uint8_t>(5u << 4);  // bogus IP version 5
    CHECK_FALSE(static_cast<bool>(locate_tcp_payload(p.data(), p.size())));
}
