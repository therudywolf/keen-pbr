#include <doctest/doctest.h>

#include "../src/dns/dns_txt_client.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

using namespace keen_pbr3;

namespace {

std::vector<uint8_t> encode_qname(const std::string& domain) {
    std::vector<uint8_t> encoded;
    size_t start = 0;
    while (start < domain.size()) {
        const size_t dot = domain.find('.', start);
        const size_t end = (dot == std::string::npos) ? domain.size() : dot;
        const size_t len = end - start;
        encoded.push_back(static_cast<uint8_t>(len));
        encoded.insert(encoded.end(), domain.begin() + static_cast<std::ptrdiff_t>(start),
                       domain.begin() + static_cast<std::ptrdiff_t>(end));
        if (dot == std::string::npos) {
            break;
        }
        start = dot + 1;
    }
    encoded.push_back(0x00);
    return encoded;
}

void push_u16(std::vector<uint8_t>& out, uint16_t value) {
    out.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>(value & 0xFF));
}

void push_u32(std::vector<uint8_t>& out, uint32_t value) {
    out.push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
    out.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>(value & 0xFF));
}

std::vector<uint8_t> build_txt_response(uint16_t id,
                                        const std::string& domain,
                                        const std::vector<std::string>& txt_answers) {
    std::vector<uint8_t> packet;
    packet.reserve(512);

    push_u16(packet, id);
    push_u16(packet, 0x8180);
    push_u16(packet, 0x0001);
    push_u16(packet, static_cast<uint16_t>(txt_answers.size()));
    push_u16(packet, 0x0000);
    push_u16(packet, 0x0000);

    const auto qname = encode_qname(domain);
    packet.insert(packet.end(), qname.begin(), qname.end());
    push_u16(packet, 0x0010);
    push_u16(packet, 0x0001);

    for (const auto& txt : txt_answers) {
        push_u16(packet, 0xC00C);
        push_u16(packet, 0x0010);
        push_u16(packet, 0x0001);
        push_u32(packet, 0);
        push_u16(packet, static_cast<uint16_t>(txt.size() + 1));
        packet.push_back(static_cast<uint8_t>(txt.size()));
        packet.insert(packet.end(), txt.begin(), txt.end());
    }

    return packet;
}

class SingleResponseDnsServer {
public:
    explicit SingleResponseDnsServer(std::vector<std::string> txt_answers)
        : txt_answers_(std::move(txt_answers)) {
        socket_fd_ = socket(AF_INET, SOCK_DGRAM, 0);
        if (socket_fd_ < 0) {
            throw std::runtime_error("socket() failed");
        }

        sockaddr_in addr {};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(0);
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (bind(socket_fd_, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) != 0) {
            close(socket_fd_);
            throw std::runtime_error("bind() failed");
        }

        socklen_t len = sizeof(addr);
        if (getsockname(socket_fd_, reinterpret_cast<sockaddr*>(&addr), &len) != 0) {
            close(socket_fd_);
            throw std::runtime_error("getsockname() failed");
        }
        port_ = ntohs(addr.sin_port);

        server_thread_ = std::thread([this]() { serve_once(); });
    }

    ~SingleResponseDnsServer() {
        if (socket_fd_ >= 0) {
            close(socket_fd_);
            socket_fd_ = -1;
        }
        if (server_thread_.joinable()) {
            server_thread_.join();
        }
    }

    std::string address() const {
        return "127.0.0.1:" + std::to_string(port_);
    }

private:
    void serve_once() {
        std::array<uint8_t, 512> buffer {};
        sockaddr_in client_addr {};
        socklen_t client_len = sizeof(client_addr);
        const ssize_t received = recvfrom(socket_fd_,
                                          buffer.data(),
                                          buffer.size(),
                                          0,
                                          reinterpret_cast<sockaddr*>(&client_addr),
                                          &client_len);
        if (received < 2) {
            return;
        }

        const uint16_t id = static_cast<uint16_t>((buffer[0] << 8) | buffer[1]);
        auto response = build_txt_response(id, "config-hash.keen.pbr", txt_answers_);
        (void)sendto(socket_fd_,
                     response.data(),
                     response.size(),
                     0,
                     reinterpret_cast<const sockaddr*>(&client_addr),
                     client_len);
    }

    int socket_fd_{-1};
    uint16_t port_{0};
    std::vector<std::string> txt_answers_;
    std::thread server_thread_;
};

// Answers one query with whatever `respond` builds from the received query.
class ScriptedDnsServer {
public:
    using Responder = std::function<std::vector<uint8_t>(const std::vector<uint8_t>& query)>;

    explicit ScriptedDnsServer(Responder respond) : respond_(std::move(respond)) {
        socket_fd_ = socket(AF_INET, SOCK_DGRAM, 0);
        if (socket_fd_ < 0) {
            throw std::runtime_error("socket() failed");
        }
        sockaddr_in addr {};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(0);
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (bind(socket_fd_, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) != 0) {
            close(socket_fd_);
            throw std::runtime_error("bind() failed");
        }
        socklen_t len = sizeof(addr);
        if (getsockname(socket_fd_, reinterpret_cast<sockaddr*>(&addr), &len) != 0) {
            close(socket_fd_);
            throw std::runtime_error("getsockname() failed");
        }
        port_ = ntohs(addr.sin_port);
        server_thread_ = std::thread([this]() { serve_once(); });
    }

    ~ScriptedDnsServer() {
        if (socket_fd_ >= 0) {
            shutdown(socket_fd_, SHUT_RDWR);
            close(socket_fd_);
            socket_fd_ = -1;
        }
        if (server_thread_.joinable()) {
            server_thread_.join();
        }
    }

    std::string address() const {
        return "127.0.0.1:" + std::to_string(port_);
    }

private:
    void serve_once() {
        std::array<uint8_t, 512> buffer {};
        sockaddr_in client_addr {};
        socklen_t client_len = sizeof(client_addr);
        const ssize_t received = recvfrom(socket_fd_, buffer.data(), buffer.size(), 0,
                                          reinterpret_cast<sockaddr*>(&client_addr), &client_len);
        if (received < 12) {
            return;
        }
        const std::vector<uint8_t> query(buffer.begin(), buffer.begin() + received);
        const auto response = respond_(query);
        (void)sendto(socket_fd_, response.data(), response.size(), 0,
                     reinterpret_cast<const sockaddr*>(&client_addr), client_len);
    }

    Responder respond_;
    int socket_fd_{-1};
    uint16_t port_{0};
    std::thread server_thread_;
};

// Header + echoed question of a query, with the given flags and answer count.
std::vector<uint8_t> response_head(const std::vector<uint8_t>& query,
                                   uint16_t flags,
                                   uint16_t answer_count) {
    std::vector<uint8_t> packet(query.begin(), query.begin() + 2);
    push_u16(packet, flags);
    push_u16(packet, 0x0001);
    push_u16(packet, answer_count);
    push_u16(packet, 0x0000);
    push_u16(packet, 0x0000);
    // The question runs from offset 12 to the end of the query (no EDNS).
    packet.insert(packet.end(), query.begin() + 12, query.end());
    return packet;
}

void push_a_answer(std::vector<uint8_t>& packet, const std::array<uint8_t, 4>& address) {
    push_u16(packet, 0xC00C);
    push_u16(packet, 0x0001);
    push_u16(packet, 0x0001);
    push_u32(packet, 60);
    push_u16(packet, 4);
    packet.insert(packet.end(), address.begin(), address.end());
}

} // namespace

TEST_CASE("DNS truncation flag parsing supports unaligned packet buffers") {
    constexpr std::size_t dns_header_size = 12;
    std::array<unsigned char, dns_header_size + 1> storage {};
    unsigned char* packet = storage.data() + 1;
    packet[2] = 0x02;
    CHECK(keen_pbr3::detail::dns_response_is_truncated(packet, dns_header_size));
    packet[2] = 0;
    CHECK_FALSE(keen_pbr3::detail::dns_response_is_truncated(packet, dns_header_size));
    CHECK_FALSE(keen_pbr3::detail::dns_response_is_truncated(packet, dns_header_size - 1));
}

TEST_CASE("DNS response validation checks transaction, flags and question") {
    constexpr std::uint16_t id = 0x1234;
    constexpr int kTxt = 16;
    constexpr int kA = 1;
    auto response = build_txt_response(
        id, "config-hash.keen.pbr", {"0123456789abcdef0123456789abcdef"});
    CHECK(keen_pbr3::detail::dns_response_matches_query(
        response.data(), response.size(), id, "config-hash.keen.pbr", kTxt));
    CHECK(keen_pbr3::detail::dns_response_matches_query(
        response.data(), response.size(), id, "CONFIG-HASH.keen.pbr.", kTxt));
    CHECK_FALSE(keen_pbr3::detail::dns_response_matches_query(
        response.data(), response.size(), 0xabcd, "config-hash.keen.pbr", kTxt));
    CHECK_FALSE(keen_pbr3::detail::dns_response_matches_query(
        response.data(), response.size(), id, "other.example", kTxt));
    CHECK_FALSE(keen_pbr3::detail::dns_response_matches_query(
        response.data(), response.size(), id, "config-hash.keen.pbr", kA));

    auto query_echo = response;
    query_echo[2] &= 0x7F; // QR cleared: a query, not a response
    CHECK_FALSE(keen_pbr3::detail::dns_response_matches_query(
        query_echo.data(), query_echo.size(), id, "config-hash.keen.pbr", kTxt));

    auto notify = response;
    notify[2] |= 0x20; // opcode 4 (NOTIFY)
    CHECK_FALSE(keen_pbr3::detail::dns_response_matches_query(
        notify.data(), notify.size(), id, "config-hash.keen.pbr", kTxt));

    // NXDOMAIN still answers our question; the answer parsers turn it into
    // "no usable records" instead of a transport failure.
    auto nxdomain = build_txt_response(id, "config-hash.keen.pbr", {});
    nxdomain[3] = static_cast<uint8_t>((nxdomain[3] & 0xF0) | 0x03);
    CHECK(keen_pbr3::detail::dns_response_matches_query(
        nxdomain.data(), nxdomain.size(), id, "config-hash.keen.pbr", kTxt));

    CHECK_FALSE(keen_pbr3::detail::dns_response_matches_query(
        response.data(), 11, id, "config-hash.keen.pbr", kTxt));
}

TEST_CASE("query_resolver_config_hash_txt rejects a response with a foreign transaction ID") {
    ScriptedDnsServer server([](const std::vector<uint8_t>& query) {
        const uint16_t id = static_cast<uint16_t>((query[0] << 8) | query[1]);
        return build_txt_response(static_cast<uint16_t>(id ^ 0x5555), "config-hash.keen.pbr",
                                  {"1744060800|aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"});
    });

    const auto result = query_resolver_config_hash_txt(
        server.address(), "config-hash.keen.pbr", std::chrono::milliseconds(1000));

    CHECK(result.status == ResolverConfigHashProbeStatus::QUERY_FAILED);
    CHECK(result.error.find("did not match") != std::string::npos);
}

TEST_CASE("query_resolver_config_hash_txt keeps NXDOMAIN as no usable TXT") {
    ScriptedDnsServer server([](const std::vector<uint8_t>& query) {
        return response_head(query, 0x8183, 0);
    });

    const auto result = query_resolver_config_hash_txt(
        server.address(), "config-hash.keen.pbr", std::chrono::milliseconds(1000));

    CHECK(result.status == ResolverConfigHashProbeStatus::NO_USABLE_TXT);
}

TEST_CASE("query_resolver_config_hash_txt reports a truncated response") {
    ScriptedDnsServer server([](const std::vector<uint8_t>& query) {
        return response_head(query, 0x8380, 0);
    });

    const auto result = query_resolver_config_hash_txt(
        server.address(), "config-hash.keen.pbr", std::chrono::milliseconds(1000));

    CHECK(result.status == ResolverConfigHashProbeStatus::QUERY_FAILED);
    CHECK(result.error.find("truncated") != std::string::npos);
}

TEST_CASE("query_dns_a_records returns answers to its own question") {
    ScriptedDnsServer server([](const std::vector<uint8_t>& query) {
        auto packet = response_head(query, 0x8180, 1);
        push_a_answer(packet, {192, 0, 2, 7});
        return packet;
    });

    std::string error;
    const auto addresses = query_dns_a_records(
        server.address(), "warm.example", std::chrono::milliseconds(1000), &error);

    REQUIRE(addresses.size() == 1);
    CHECK(addresses[0] == "192.0.2.7");
}

TEST_CASE("query_dns_a_records ignores answers for another question") {
    ScriptedDnsServer server([](const std::vector<uint8_t>& query) {
        // A spoofed reply: right ID, but for a different name.
        std::vector<uint8_t> packet(query.begin(), query.begin() + 2);
        push_u16(packet, 0x8180);
        push_u16(packet, 0x0001);
        push_u16(packet, 0x0001);
        push_u16(packet, 0x0000);
        push_u16(packet, 0x0000);
        const auto qname = encode_qname("attacker.example");
        packet.insert(packet.end(), qname.begin(), qname.end());
        push_u16(packet, 0x0001);
        push_u16(packet, 0x0001);
        push_a_answer(packet, {203, 0, 113, 66});
        return packet;
    });

    std::string error;
    const auto addresses = query_dns_a_records(
        server.address(), "warm.example", std::chrono::milliseconds(1000), &error);

    CHECK(addresses.empty());
    CHECK(error.find("did not match") != std::string::npos);
}

TEST_CASE("parse_resolver_config_hash_txt parses ts/hash payload") {
    const auto parsed = parse_resolver_config_hash_txt("1744060800|0123456789abcdef0123456789abcdef");
    REQUIRE(parsed.ts.has_value());
    CHECK(*parsed.ts == 1744060800);
    CHECK(parsed.hash == "0123456789abcdef0123456789abcdef");
}

TEST_CASE("parse_resolver_config_hash_txt parses quoted ts/hash payload") {
    const auto parsed = parse_resolver_config_hash_txt("\"1744060800|0123456789abcdef0123456789abcdef\"");
    REQUIRE(parsed.ts.has_value());
    CHECK(*parsed.ts == 1744060800);
    CHECK(parsed.hash == "0123456789abcdef0123456789abcdef");
}

TEST_CASE("parse_resolver_config_hash_txt parses md5-prefixed hash payload") {
    const auto parsed = parse_resolver_config_hash_txt("md5=0123456789ABCDEF0123456789ABCDEF");
    CHECK_FALSE(parsed.ts.has_value());
    CHECK(parsed.hash == "0123456789abcdef0123456789abcdef");
}

TEST_CASE("query_resolver_config_hash_txt selects TXT answer with latest timestamp") {
    SingleResponseDnsServer server({
        "1744060800|aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "1744060802|bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    });

    const auto result = query_resolver_config_hash_txt(
        server.address(),
        "config-hash.keen.pbr",
        std::chrono::milliseconds(1000));

    CHECK(result.status == ResolverConfigHashProbeStatus::SUCCESS);
    REQUIRE(result.raw_txt.has_value());
    CHECK(*result.raw_txt == "1744060802|bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    CHECK(result.parsed_value.ts == std::optional<std::int64_t>{1744060802});
    CHECK(result.parsed_value.hash == "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
}

TEST_CASE("query_resolver_config_hash_txt reports missing TXT as no usable TXT") {
    SingleResponseDnsServer server({});

    const auto result = query_resolver_config_hash_txt(
        server.address(),
        "config-hash.keen.pbr",
        std::chrono::milliseconds(1000));

    CHECK(result.status == ResolverConfigHashProbeStatus::NO_USABLE_TXT);
    CHECK_FALSE(result.raw_txt.has_value());
}

TEST_CASE("query_resolver_config_hash_txt reports invalid payload") {
    SingleResponseDnsServer server({"not-a-md5"});

    const auto result = query_resolver_config_hash_txt(
        server.address(),
        "config-hash.keen.pbr",
        std::chrono::milliseconds(1000));

    CHECK(result.status == ResolverConfigHashProbeStatus::INVALID_TXT);
    REQUIRE(result.raw_txt.has_value());
    CHECK(*result.raw_txt == "not-a-md5");
}

TEST_CASE("query_resolver_config_hash_txt reports query failure for invalid resolver address") {
    const auto result = query_resolver_config_hash_txt(
        "not-an-address",
        "config-hash.keen.pbr",
        std::chrono::milliseconds(1000));

    CHECK(result.status == ResolverConfigHashProbeStatus::QUERY_FAILED);
    CHECK_FALSE(result.error.empty());
}
