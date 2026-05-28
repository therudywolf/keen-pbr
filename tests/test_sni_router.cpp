#include <doctest/doctest.h>

#include "../src/routing/sni_router.hpp"

#include "tls_clienthello_builder.hpp"

#include <cstdint>
#include <string>
#include <vector>

using namespace keen_pbr3;
using keen_pbr3_test::build_client_hello;

namespace {
constexpr uint32_t kVpn = 0x50000;        // forestserver_ru (nwg2)
constexpr uint32_t kRostelecom = 0x20000; // rostelecom (ppp0 / WAN)

SniRouter make_router() {
    return SniRouter({
        {"youtube.com", kVpn},
        {"googlevideo.com", kVpn},
        {"drive.google.com", kRostelecom},
    });
}

SniDecision decide_hello(const SniRouter& r, const std::string& sni,
                         bool include_sni = true) {
    const auto bytes = build_client_hello(sni, include_sni);
    return r.decide(bytes.data(), bytes.size());
}
}  // namespace

TEST_CASE("sni_router: the split — youtube to VPN, drive to rostelecom on a shared CDN") {
    // The whole reason SNI routing exists: youtube and drive share Google edges,
    // so IP routing can't separate them. By name they go different ways.
    auto r = make_router();

    const auto yt = decide_hello(r, "rr3---sn-abc.googlevideo.com");
    CHECK(yt.action == SniAction::SetMark);
    CHECK(yt.mark == kVpn);

    const auto drive = decide_hello(r, "drive.google.com");
    CHECK(drive.action == SniAction::SetMark);
    CHECK(drive.mark == kRostelecom);
}

TEST_CASE("sni_router: parsed hostname is surfaced (lowercased) for logging") {
    auto r = make_router();
    const auto d = decide_hello(r, "WWW.YouTube.com");
    CHECK(d.action == SniAction::SetMark);
    CHECK(d.mark == kVpn);
    CHECK(d.hostname == "www.youtube.com");
}

TEST_CASE("sni_router: a TLS host with no matching rule is accepted, left to IP routing") {
    auto r = make_router();
    const auto d = decide_hello(r, "example.org");
    CHECK(d.action == SniAction::Accept);
    CHECK(d.mark == 0);
}

TEST_CASE("sni_router: ClientHello without a server_name extension is accepted") {
    auto r = make_router();
    const auto d = decide_hello(r, "", /*include_sni=*/false);
    CHECK(d.action == SniAction::Accept);
}

TEST_CASE("sni_router: non-TLS payload is accepted, never marked") {
    auto r = make_router();
    const std::vector<uint8_t> appdata = {0x17, 0x03, 0x03, 0x00, 0x05, 1, 2, 3, 4, 5};
    const auto d = r.decide(appdata.data(), appdata.size());
    CHECK(d.action == SniAction::Accept);
}

TEST_CASE("sni_router: truncated ClientHello yields NeedMoreData (not a wrong mark)") {
    auto r = make_router();
    const std::vector<uint8_t> partial = {0x16, 0x03};  // 2 of 5 record-header bytes
    const auto d = r.decide(partial.data(), partial.size());
    CHECK(d.action == SniAction::NeedMoreData);
}

TEST_CASE("sni_router: an empty rule table marks nothing") {
    SniRouter r({});
    CHECK(r.domain_count() == 0);
    const auto d = decide_hello(r, "youtube.com");
    CHECK(d.action == SniAction::Accept);
}

TEST_CASE("sni_router: most-specific domain wins over a broader one") {
    SniRouter r({
        {"google.com", kVpn},
        {"drive.google.com", kRostelecom},
    });
    CHECK(decide_hello(r, "mail.google.com").mark == kVpn);
    const auto drive = decide_hello(r, "drive.google.com");
    CHECK(drive.action == SniAction::SetMark);
    CHECK(drive.mark == kRostelecom);
}
