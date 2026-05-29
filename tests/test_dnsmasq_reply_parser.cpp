#include <doctest/doctest.h>

#include "../src/dns/dnsmasq_reply_parser.hpp"

using namespace keen_pbr3;

namespace {
// A realistic dnsmasq `log-queries=extra` reply line: timestamp, pid, a request
// serial + client ip/port, then the `reply <domain> is <value>` payload.
std::string line(const std::string& tail) {
    return "Jan  1 00:00:00 dnsmasq[1234]: 7 192.168.1.5/53281 " + tail;
}
}  // namespace

TEST_CASE("parse_dnsmasq_reply_line: a plain A-record reply yields domain + ipv4") {
    const auto r = parse_dnsmasq_reply_line(line("reply drive.google.com is 142.250.1.2"));
    REQUIRE(r.has_value());
    CHECK(r->domain == "drive.google.com");
    CHECK(r->ipv4 == "142.250.1.2");
}

TEST_CASE("parse_dnsmasq_reply_line: works without the syslog/client prefix too") {
    // log-facility=<file> output can be bare; anchor on the keyword, not a column.
    const auto r = parse_dnsmasq_reply_line("reply youtube.com is 10.0.0.1");
    REQUIRE(r.has_value());
    CHECK(r->domain == "youtube.com");
    CHECK(r->ipv4 == "10.0.0.1");
}

TEST_CASE("parse_dnsmasq_reply_line: domain is lowercased and trailing dot stripped") {
    const auto r = parse_dnsmasq_reply_line(line("reply WWW.YouTube.CoM. is 8.8.8.8"));
    REQUIRE(r.has_value());
    CHECK(r->domain == "www.youtube.com");
    CHECK(r->ipv4 == "8.8.8.8");
}

TEST_CASE("parse_dnsmasq_reply_line: trailing CR/LF is tolerated") {
    const auto r = parse_dnsmasq_reply_line(line("reply example.com is 1.2.3.4\r\n"));
    REQUIRE(r.has_value());
    CHECK(r->ipv4 == "1.2.3.4");
}

TEST_CASE("parse_dnsmasq_reply_line: negative answers are not A records") {
    CHECK_FALSE(parse_dnsmasq_reply_line(line("reply example.com is <NODATA>")).has_value());
    CHECK_FALSE(parse_dnsmasq_reply_line(line("reply example.com is <NXDOMAIN>")).has_value());
    CHECK_FALSE(parse_dnsmasq_reply_line(line("reply example.com is <CNAME>")).has_value());
}

TEST_CASE("parse_dnsmasq_reply_line: AAAA / IPv6 answers are ignored") {
    CHECK_FALSE(parse_dnsmasq_reply_line(
                    line("reply ipv6.google.com is 2607:f8b0:4005:80a::200e"))
                    .has_value());
    // Compressed form too.
    CHECK_FALSE(parse_dnsmasq_reply_line(line("reply example.com is ::1")).has_value());
}

TEST_CASE("parse_dnsmasq_reply_line: non-reply lines are ignored") {
    CHECK_FALSE(parse_dnsmasq_reply_line(line("query[A] drive.google.com from 192.168.1.5"))
                    .has_value());
    CHECK_FALSE(parse_dnsmasq_reply_line(line("forwarded drive.google.com to 1.1.1.1"))
                    .has_value());
    CHECK_FALSE(parse_dnsmasq_reply_line(
                    line("cached drive.google.com is 142.250.1.2"))
                    .has_value());  // 'cached', not 'reply'
    CHECK_FALSE(parse_dnsmasq_reply_line("using nameserver 1.1.1.1#53").has_value());
    CHECK_FALSE(parse_dnsmasq_reply_line("").has_value());
}

TEST_CASE("parse_dnsmasq_reply_line: a domain merely containing 'reply' is not matched") {
    // Without the surrounding spaces the keyword anchor must not fire.
    CHECK_FALSE(parse_dnsmasq_reply_line("noreplyhere example.com is 1.2.3.4").has_value());
}

TEST_CASE("parse_dnsmasq_reply_line: malformed / truncated lines yield nullopt") {
    CHECK_FALSE(parse_dnsmasq_reply_line(line("reply")).has_value());
    CHECK_FALSE(parse_dnsmasq_reply_line(line("reply example.com")).has_value());
    CHECK_FALSE(parse_dnsmasq_reply_line(line("reply example.com is")).has_value());
    CHECK_FALSE(parse_dnsmasq_reply_line(line("reply example.com was 1.2.3.4")).has_value());
}

TEST_CASE("parse_dnsmasq_reply_line: invalid dotted-quads are rejected") {
    CHECK_FALSE(parse_dnsmasq_reply_line(line("reply example.com is 1.2.3")).has_value());
    CHECK_FALSE(parse_dnsmasq_reply_line(line("reply example.com is 1.2.3.4.5")).has_value());
    CHECK_FALSE(parse_dnsmasq_reply_line(line("reply example.com is 256.1.1.1")).has_value());
    CHECK_FALSE(parse_dnsmasq_reply_line(line("reply example.com is 1.2.3.4x")).has_value());
    CHECK_FALSE(parse_dnsmasq_reply_line(line("reply example.com is 1.2..4")).has_value());
    CHECK_FALSE(parse_dnsmasq_reply_line(line("reply example.com is .1.2.3.4")).has_value());
}

TEST_CASE("parse_dnsmasq_reply_line: boundary octet values 0 and 255 are accepted") {
    const auto r = parse_dnsmasq_reply_line(line("reply h.test is 0.255.10.255"));
    REQUIRE(r.has_value());
    CHECK(r->ipv4 == "0.255.10.255");
}
