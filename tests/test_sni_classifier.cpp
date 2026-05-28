#include <doctest/doctest.h>

#include "../src/routing/sni_classifier.hpp"

#include <map>
#include <string>

using namespace keen_pbr3;

namespace {
constexpr uint32_t kVpn = 0x50000;        // forestserver_ru
constexpr uint32_t kRostelecom = 0x20000; // rostelecom (WAN-ish)
}

TEST_CASE("sni_classifier: the split case — drive vs youtube on shared CDN") {
    // youtube -> VPN, google_disk (drive) -> rostelecom. Same Google edges,
    // different outbound — this is exactly what IP routing can't do.
    SniClassifier c({
        {"youtube.com", kVpn},
        {"googlevideo.com", kVpn},
        {"drive.google.com", kRostelecom},
    });
    CHECK(c.classify("www.youtube.com") == kVpn);
    CHECK(c.classify("rr3---sn-abc.googlevideo.com") == kVpn);
    CHECK(c.classify("drive.google.com") == kRostelecom);
    CHECK(c.classify("docs.drive.google.com") == kRostelecom);
}

TEST_CASE("sni_classifier: most-specific domain wins") {
    SniClassifier c({
        {"google.com", kVpn},            // broad
        {"drive.google.com", kRostelecom}, // specific override
    });
    CHECK(c.classify("mail.google.com") == kVpn);        // only broad matches
    CHECK(c.classify("drive.google.com") == kRostelecom); // specific wins
    CHECK(c.classify("x.drive.google.com") == kRostelecom);
}

TEST_CASE("sni_classifier: wildcard prefix is stripped") {
    SniClassifier c({{"*.openai.com", kVpn}});
    CHECK(c.classify("api.openai.com") == kVpn);
    CHECK(c.classify("openai.com") == kVpn);
}

TEST_CASE("sni_classifier: case-insensitive + trailing dot") {
    SniClassifier c({{"chatgpt.com", kVpn}});
    CHECK(c.classify("API.ChatGPT.CoM") == kVpn);
    CHECK(c.classify("chatgpt.com.") == kVpn);
}

TEST_CASE("sni_classifier: no match returns nullopt (leave to IP routing)") {
    SniClassifier c({{"youtube.com", kVpn}});
    CHECK(c.classify("yandex.ru") == std::nullopt);
    CHECK(c.classify("example.org") == std::nullopt);
    CHECK(c.classify("notyoutube.com") == std::nullopt);  // not a sub-label
    CHECK(c.classify("") == std::nullopt);
}

TEST_CASE("sni_classifier: a label that merely contains a domain string doesn't match") {
    SniClassifier c({{"openai.com", kVpn}});
    // "myopenai.com" must NOT match openai.com (different registrable label).
    CHECK(c.classify("myopenai.com") == std::nullopt);
    // but a real sub-label does
    CHECK(c.classify("auth.openai.com") == kVpn);
}

TEST_CASE("sni_classifier: empty table classifies nothing") {
    SniClassifier c({});
    CHECK(c.classify("anything.com") == std::nullopt);
    CHECK(c.size() == 0);
}
