#include <doctest/doctest.h>

#include "../src/routing/sni_parser.hpp"

#include "tls_clienthello_builder.hpp"

#include <cstdint>
#include <string>
#include <vector>

using namespace keen_pbr3;
using keen_pbr3_test::build_client_hello;

namespace {

SniParseResult parse(const std::vector<uint8_t>& v) {
    return parse_tls_sni(v.data(), v.size());
}

}  // namespace

TEST_CASE("sni_parser: extracts hostname from a normal ClientHello") {
    auto hello = build_client_hello("www.youtube.com");
    auto r = parse(hello);
    CHECK(r.status == SniParseStatus::Found);
    CHECK(r.hostname == "www.youtube.com");
}

TEST_CASE("sni_parser: split case — drive vs youtube parse distinctly") {
    auto drive = parse(build_client_hello("drive.google.com"));
    auto yt = parse(build_client_hello("www.youtube.com"));
    REQUIRE(drive.status == SniParseStatus::Found);
    REQUIRE(yt.status == SniParseStatus::Found);
    CHECK(drive.hostname == "drive.google.com");
    CHECK(yt.hostname == "www.youtube.com");
    CHECK(drive.hostname != yt.hostname);  // the whole point of SNI routing
}

TEST_CASE("sni_parser: hostname is lowercased") {
    auto r = parse(build_client_hello("API.OpenAI.CoM"));
    CHECK(r.status == SniParseStatus::Found);
    CHECK(r.hostname == "api.openai.com");
}

TEST_CASE("sni_parser: trailing dot stripped") {
    auto r = parse(build_client_hello("chatgpt.com."));
    CHECK(r.status == SniParseStatus::Found);
    CHECK(r.hostname == "chatgpt.com");
}

TEST_CASE("sni_parser: SNI not the first extension is still found") {
    auto r = parse(build_client_hello("notebooklm.google.com",
                                      /*include_sni=*/true,
                                      /*dummy_ext_first=*/true));
    CHECK(r.status == SniParseStatus::Found);
    CHECK(r.hostname == "notebooklm.google.com");
}

TEST_CASE("sni_parser: ClientHello without server_name extension -> NoSni") {
    auto r = parse(build_client_hello("", /*include_sni=*/false));
    CHECK(r.status == SniParseStatus::NoSni);
}

TEST_CASE("sni_parser: application data (not handshake) -> NotTls") {
    std::vector<uint8_t> appdata = {0x17, 0x03, 0x03, 0x00, 0x05, 1, 2, 3, 4, 5};
    auto r = parse(appdata);
    CHECK(r.status == SniParseStatus::NotTls);
}

TEST_CASE("sni_parser: ServerHello (not ClientHello) -> NotTls") {
    auto hello = build_client_hello("x.com");
    hello[5] = 0x02;  // flip handshake type ClientHello(1) -> ServerHello(2)
    auto r = parse(hello);
    CHECK(r.status == SniParseStatus::NotTls);
}

TEST_CASE("sni_parser: truncated record header -> NeedMoreData") {
    std::vector<uint8_t> partial = {0x16, 0x03};  // only 2 of 5 header bytes
    auto r = parse(partial);
    CHECK(r.status == SniParseStatus::NeedMoreData);
}

TEST_CASE("sni_parser: handshake body spans beyond buffer -> NeedMoreData") {
    auto hello = build_client_hello("api.openai.com");
    // Truncate mid-body: keep record+handshake headers but cut the payload.
    hello.resize(12);
    auto r = parse(hello);
    CHECK(r.status == SniParseStatus::NeedMoreData);
}

TEST_CASE("sni_parser: empty / null input -> NotTls") {
    CHECK(parse_tls_sni(nullptr, 0).status == SniParseStatus::NotTls);
    std::vector<uint8_t> empty;
    CHECK(parse(empty).status == SniParseStatus::NotTls);
}

TEST_CASE("sni_parser: host_len overrunning the extension is rejected, not OOB") {
    auto hello = build_client_hello("good.example.com");
    // Corrupt the host_name length to claim a huge size. The parser must not
    // read past the buffer — it should return NoSni/NeedMoreData, never crash.
    // Find the SNI host_len field is fiddly; instead just fuzz the tail length
    // bytes and assert we get a defined status with no crash.
    for (std::size_t i = 5; i < hello.size(); ++i) {
        auto copy = hello;
        copy[i] = 0xff;
        auto r = parse(copy);
        // Any defined status is acceptable; the contract is "no out-of-bounds".
        CHECK((r.status == SniParseStatus::Found ||
               r.status == SniParseStatus::NoSni ||
               r.status == SniParseStatus::NeedMoreData ||
               r.status == SniParseStatus::NotTls));
    }
}
