#include "dnsmasq_reply_parser.hpp"

#include <cctype>

namespace keen_pbr3 {

namespace {

// Strict dotted-quad IPv4 validator: exactly four 0-255 decimal octets joined by
// dots, no leading/trailing junk, no embedded spaces. Deliberately rejects
// anything containing ':' (IPv6) and any bracketed sentinel like "<NXDOMAIN>".
bool is_ipv4_literal(std::string_view s) {
    if (s.empty()) {
        return false;
    }
    int octets = 0;
    std::size_t i = 0;
    const std::size_t n = s.size();
    while (i < n) {
        // Each octet: 1-3 digits, value 0-255.
        std::size_t digits = 0;
        int value = 0;
        while (i < n && std::isdigit(static_cast<unsigned char>(s[i]))) {
            value = value * 10 + (s[i] - '0');
            ++digits;
            ++i;
            if (digits > 3) {
                return false;
            }
        }
        if (digits == 0 || value > 255) {
            return false;
        }
        ++octets;
        if (octets > 4) {
            return false;
        }
        if (i < n) {
            if (s[i] != '.') {
                return false;  // unexpected character (':' for v6, etc.)
            }
            ++i;
            if (i >= n) {
                return false;  // trailing dot
            }
        }
    }
    return octets == 4;
}

// Advance past runs of ASCII spaces/tabs.
std::size_t skip_spaces(std::string_view s, std::size_t i) {
    while (i < s.size() && (s[i] == ' ' || s[i] == '\t')) {
        ++i;
    }
    return i;
}

// Read one whitespace-delimited token starting at `i`, returning it and
// advancing `i` past it. The token is the run of non-space characters.
std::string_view read_token(std::string_view s, std::size_t& i) {
    const std::size_t start = i;
    while (i < s.size() && s[i] != ' ' && s[i] != '\t') {
        ++i;
    }
    return s.substr(start, i - start);
}

std::string lower_no_trailing_dot(std::string_view domain) {
    std::string out;
    out.reserve(domain.size());
    for (char c : domain) {
        out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    }
    if (!out.empty() && out.back() == '.') {
        out.pop_back();
    }
    return out;
}

}  // namespace

std::optional<DnsmasqReply> parse_dnsmasq_reply_line(std::string_view line) {
    // Strip a trailing newline / carriage return so a token at end-of-line is
    // not contaminated when callers pass a raw read() chunk line.
    while (!line.empty() && (line.back() == '\n' || line.back() == '\r')) {
        line.remove_suffix(1);
    }

    // Find the "reply" keyword as a whole word. dnsmasq prefixes each line with
    // a variable timestamp/pid/client header (when logging via syslog), so we
    // anchor on the keyword rather than a fixed column; but a bare log-facility
    // file line can also START with "reply". Accept the keyword either at the
    // start of the line or preceded by whitespace, and require a following
    // space, so a domain that merely contains "reply" never false-matches.
    constexpr std::string_view kReply = "reply";
    std::size_t i = std::string_view::npos;
    for (std::size_t pos = line.find(kReply); pos != std::string_view::npos;
         pos = line.find(kReply, pos + 1)) {
        const bool left_ok = (pos == 0) || line[pos - 1] == ' ' || line[pos - 1] == '\t';
        const std::size_t after = pos + kReply.size();
        const bool right_ok = after < line.size() &&
                              (line[after] == ' ' || line[after] == '\t');
        if (left_ok && right_ok) {
            i = after;
            break;
        }
    }
    if (i == std::string_view::npos) {
        return std::nullopt;
    }

    i = skip_spaces(line, i);
    const std::string_view domain_tok = read_token(line, i);
    if (domain_tok.empty()) {
        return std::nullopt;
    }

    i = skip_spaces(line, i);
    const std::string_view is_tok = read_token(line, i);
    if (is_tok != "is") {
        return std::nullopt;
    }

    i = skip_spaces(line, i);
    const std::string_view value_tok = read_token(line, i);
    if (value_tok.empty()) {
        return std::nullopt;
    }

    // Reject negative/sentinel answers (<NXDOMAIN>, <NODATA>, <CNAME>, ...) and
    // IPv6 (rejected by the strict v4 validator). Only a dotted-quad survives.
    if (!is_ipv4_literal(value_tok)) {
        return std::nullopt;
    }

    DnsmasqReply reply;
    reply.domain = lower_no_trailing_dot(domain_tok);
    if (reply.domain.empty()) {
        return std::nullopt;
    }
    reply.ipv4.assign(value_tok.begin(), value_tok.end());
    return reply;
}

}  // namespace keen_pbr3
