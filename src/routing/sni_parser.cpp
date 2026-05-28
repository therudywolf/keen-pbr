#include "sni_parser.hpp"

#include <algorithm>
#include <cctype>

namespace keen_pbr3 {

namespace {

// A bounds-checked forward cursor over the input buffer. Every read validates
// that enough bytes remain; on underrun the caller decides whether that means
// "truncated, need more" or "malformed".
class Cursor {
public:
    Cursor(const uint8_t* data, std::size_t len) : data_(data), len_(len) {}

    std::size_t remaining() const { return len_ - pos_; }
    bool has(std::size_t n) const { return remaining() >= n; }

    uint8_t u8() { return data_[pos_++]; }

    uint16_t u16() {
        uint16_t v = static_cast<uint16_t>((data_[pos_] << 8) | data_[pos_ + 1]);
        pos_ += 2;
        return v;
    }

    uint32_t u24() {
        uint32_t v = static_cast<uint32_t>((data_[pos_] << 16) |
                                           (data_[pos_ + 1] << 8) |
                                           data_[pos_ + 2]);
        pos_ += 3;
        return v;
    }

    const uint8_t* ptr() const { return data_ + pos_; }
    void skip(std::size_t n) { pos_ += n; }

private:
    const uint8_t* data_;
    std::size_t len_;
    std::size_t pos_ = 0;
};

constexpr uint8_t kHandshakeContentType = 0x16;
constexpr uint8_t kClientHelloType = 0x01;
constexpr uint16_t kExtServerName = 0x0000;
constexpr uint8_t kSniHostNameType = 0x00;

std::string normalize_host(const uint8_t* p, std::size_t n) {
    std::string s(reinterpret_cast<const char*>(p), n);
    // Lowercase + strip a single trailing dot. Reject anything with control
    // chars or spaces (a real hostname has neither) by returning empty.
    for (char& c : s) {
        unsigned char uc = static_cast<unsigned char>(c);
        if (uc < 0x20 || uc == 0x7f || uc == ' ') {
            return {};
        }
        c = static_cast<char>(std::tolower(uc));
    }
    if (!s.empty() && s.back() == '.') {
        s.pop_back();
    }
    return s;
}

}  // namespace

SniParseResult parse_tls_sni(const uint8_t* data, std::size_t len) {
    if (data == nullptr || len == 0) {
        return {SniParseStatus::NotTls, {}};
    }

    Cursor c(data, len);

    // --- TLS record header (5 bytes) ---
    if (!c.has(5)) {
        return {SniParseStatus::NeedMoreData, {}};
    }
    if (c.u8() != kHandshakeContentType) {
        return {SniParseStatus::NotTls, {}};
    }
    c.u16();  // legacy record version — ignored (TLS 1.3 lies here)
    const uint16_t record_len = c.u16();
    if (record_len == 0) {
        return {SniParseStatus::NotTls, {}};
    }

    // --- Handshake header (4 bytes: type + 3-byte length) ---
    if (!c.has(4)) {
        return {SniParseStatus::NeedMoreData, {}};
    }
    if (c.u8() != kClientHelloType) {
        return {SniParseStatus::NotTls, {}};
    }
    const uint32_t hs_len = c.u24();

    // The handshake body may span more than this single segment. If we don't
    // have it all, ask for more rather than guessing.
    if (!c.has(hs_len)) {
        return {SniParseStatus::NeedMoreData, {}};
    }

    // --- ClientHello body ---
    // client_version(2) + random(32)
    if (!c.has(2 + 32)) {
        return {SniParseStatus::NeedMoreData, {}};
    }
    c.skip(2 + 32);

    // session_id
    if (!c.has(1)) return {SniParseStatus::NeedMoreData, {}};
    const uint8_t sid_len = c.u8();
    if (!c.has(sid_len)) return {SniParseStatus::NeedMoreData, {}};
    c.skip(sid_len);

    // cipher_suites
    if (!c.has(2)) return {SniParseStatus::NeedMoreData, {}};
    const uint16_t cs_len = c.u16();
    if (!c.has(cs_len)) return {SniParseStatus::NeedMoreData, {}};
    c.skip(cs_len);

    // compression_methods
    if (!c.has(1)) return {SniParseStatus::NeedMoreData, {}};
    const uint8_t comp_len = c.u8();
    if (!c.has(comp_len)) return {SniParseStatus::NeedMoreData, {}};
    c.skip(comp_len);

    // extensions block. A ClientHello with no extensions = no SNI.
    if (!c.has(2)) {
        return {SniParseStatus::NoSni, {}};
    }
    uint16_t ext_total = c.u16();
    if (!c.has(ext_total)) {
        return {SniParseStatus::NeedMoreData, {}};
    }

    // --- Walk extensions looking for server_name (0x0000) ---
    while (ext_total >= 4) {
        const uint16_t ext_type = c.u16();
        const uint16_t ext_len = c.u16();
        ext_total -= 4;
        if (ext_len > ext_total) {
            // Declared extension length runs past the extensions block.
            return {SniParseStatus::NoSni, {}};
        }

        if (ext_type != kExtServerName) {
            c.skip(ext_len);
            ext_total -= ext_len;
            continue;
        }

        // server_name extension body:
        //   server_name_list length(2)
        //   entry: name_type(1) + host_name length(2) + host_name(...)
        if (ext_len < 2) {
            return {SniParseStatus::NoSni, {}};
        }
        const uint16_t list_len = c.u16();
        uint16_t body_remaining = static_cast<uint16_t>(ext_len - 2);
        if (list_len > body_remaining) {
            return {SniParseStatus::NoSni, {}};
        }
        // First (and in practice only) name entry.
        if (body_remaining < 3) {
            return {SniParseStatus::NoSni, {}};
        }
        const uint8_t name_type = c.u8();
        const uint16_t host_len = c.u16();
        body_remaining = static_cast<uint16_t>(body_remaining - 3);
        if (host_len > body_remaining) {
            return {SniParseStatus::NoSni, {}};
        }
        if (name_type != kSniHostNameType || host_len == 0) {
            return {SniParseStatus::NoSni, {}};
        }
        std::string host = normalize_host(c.ptr(), host_len);
        if (host.empty()) {
            return {SniParseStatus::NoSni, {}};
        }
        return {SniParseStatus::Found, std::move(host)};
    }

    return {SniParseStatus::NoSni, {}};
}

}  // namespace keen_pbr3
