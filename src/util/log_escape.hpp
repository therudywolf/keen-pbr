#pragma once

#include <algorithm>
#include <cstddef>
#include <string>
#include <string_view>

namespace keen_pbr3 {

// Makes a traffic-derived string (e.g. a DNS query name) safe to log:
// printable ASCII is kept, a backslash becomes "\\", any other byte "\xNN",
// so a crafted name cannot forge or split log lines. Input longer than 255
// bytes is cut and marked with "...".
inline std::string log_escape(std::string_view s) {
    static constexpr char kHex[] = "0123456789abcdef";
    constexpr std::size_t kMaxBytes = 255;
    std::string out;
    out.reserve(std::min(s.size(), kMaxBytes) + 3);
    for (std::size_t i = 0; i < s.size() && i < kMaxBytes; ++i) {
        const auto byte = static_cast<unsigned char>(s[i]);
        if (byte == '\\') {
            out += "\\\\";
        } else if (byte >= 0x20 && byte <= 0x7E) {
            out += static_cast<char>(byte);
        } else {
            out += "\\x";
            out += kHex[byte >> 4];
            out += kHex[byte & 0xF];
        }
    }
    if (s.size() > kMaxBytes) out += "...";
    return out;
}

} // namespace keen_pbr3
