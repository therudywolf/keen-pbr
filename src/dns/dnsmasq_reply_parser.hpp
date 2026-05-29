#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace keen_pbr3 {

// One parsed dnsmasq "reply <domain> is <ipv4>" log line.
struct DnsmasqReply {
    std::string domain;  // lowercased, no trailing dot
    std::string ipv4;    // dotted-quad IPv4 literal, exactly as dnsmasq logged it
};

// Parse a single line of dnsmasq's `log-queries=extra` output and, when it is an
// A-record reply, return the (domain, ipv4) it carries.
//
// dnsmasq emits A-record answers as, e.g.:
//   Jan  1 00:00:00 dnsmasq[123]: 12 192.168.1.5/53281 reply drive.google.com is 142.250.1.2
// The pieces this cares about are the trailing `reply <domain> is <value>`; the
// timestamp / pid / client prefix dnsmasq prepends is ignored, so the parser
// works whether the line came from syslog or a bare log-facility file.
//
// Returns std::nullopt for:
//   - lines that are not `reply ... is ...` answers (queries, forwards, cached,
//     config, "using nameserver", etc.),
//   - negative answers `reply <domain> is <NODATA>` / `<NXDOMAIN>` and any other
//     bracketed sentinel such as `<CNAME>`,
//   - AAAA / IPv6 answers (the value is not a dotted-quad IPv4),
//   - malformed or truncated lines.
//
// Pure, allocation-light, and unit-tested in isolation — no I/O, no kernel,
// no dnsmasq dependency.
std::optional<DnsmasqReply> parse_dnsmasq_reply_line(std::string_view line);

}  // namespace keen_pbr3
