#pragma once

#include <cstdint>
#include <string>
#include <vector>

// Shared test fixture: synthesize TLS ClientHello records so the SNI parser,
// classifier, and router can be exercised against realistic bytes with no
// network or kernel involvement.
namespace keen_pbr3_test {

inline void push_u16(std::vector<uint8_t>& v, uint16_t x) {
    v.push_back(static_cast<uint8_t>(x >> 8));
    v.push_back(static_cast<uint8_t>(x & 0xff));
}

// Build a TLS ClientHello record. If `include_sni` and `sni` is non-empty,
// include a server_name extension carrying it. `dummy_ext_first` inserts a
// non-SNI extension BEFORE the SNI one to exercise the extension walk.
inline std::vector<uint8_t> build_client_hello(const std::string& sni,
                                               bool include_sni = true,
                                               bool dummy_ext_first = false) {
    // --- extensions block ---
    std::vector<uint8_t> exts;

    if (dummy_ext_first) {
        push_u16(exts, 0x002b);  // supported_versions (arbitrary non-SNI type)
        push_u16(exts, 3);       // ext_len
        exts.push_back(2);
        push_u16(exts, 0x0304);
    }

    if (include_sni && !sni.empty()) {
        std::vector<uint8_t> sni_ext_body;
        // server_name_list
        std::vector<uint8_t> entry;
        entry.push_back(0x00);  // name_type = host_name
        push_u16(entry, static_cast<uint16_t>(sni.size()));
        entry.insert(entry.end(), sni.begin(), sni.end());
        push_u16(sni_ext_body, static_cast<uint16_t>(entry.size()));  // list len
        sni_ext_body.insert(sni_ext_body.end(), entry.begin(), entry.end());

        push_u16(exts, 0x0000);                                      // ext type SNI
        push_u16(exts, static_cast<uint16_t>(sni_ext_body.size()));  // ext len
        exts.insert(exts.end(), sni_ext_body.begin(), sni_ext_body.end());
    }

    // --- ClientHello body ---
    std::vector<uint8_t> body;
    push_u16(body, 0x0303);             // client_version TLS1.2
    body.insert(body.end(), 32, 0xAB);  // random
    body.push_back(0x00);               // session_id length 0
    push_u16(body, 2);                  // cipher_suites length
    push_u16(body, 0x1301);             // one cipher suite
    body.push_back(0x01);               // compression_methods length
    body.push_back(0x00);               // null compression
    push_u16(body, static_cast<uint16_t>(exts.size()));  // extensions length
    body.insert(body.end(), exts.begin(), exts.end());

    // --- handshake header ---
    std::vector<uint8_t> hs;
    hs.push_back(0x01);  // ClientHello
    hs.push_back(static_cast<uint8_t>((body.size() >> 16) & 0xff));
    hs.push_back(static_cast<uint8_t>((body.size() >> 8) & 0xff));
    hs.push_back(static_cast<uint8_t>(body.size() & 0xff));
    hs.insert(hs.end(), body.begin(), body.end());

    // --- record header ---
    std::vector<uint8_t> rec;
    rec.push_back(0x16);    // handshake content type
    push_u16(rec, 0x0301);  // legacy record version
    push_u16(rec, static_cast<uint16_t>(hs.size()));
    rec.insert(rec.end(), hs.begin(), hs.end());
    return rec;
}

}  // namespace keen_pbr3_test
