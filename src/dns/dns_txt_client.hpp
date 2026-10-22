#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace keen_pbr3 {

namespace detail {
// True when the TC (truncated) flag of a DNS response is set.
bool dns_response_is_truncated(const unsigned char* packet, std::size_t size);
// True when `packet` is a response to our query: same transaction ID, QR set,
// standard opcode, and exactly one question for `domain` with `record_type`
// (ns_t_txt, ns_t_a, ...) and class IN. The RCODE is not checked.
bool dns_response_matches_query(const unsigned char* packet,
                                std::size_t size,
                                std::uint16_t transaction_id,
                                const std::string& domain,
                                int record_type);
} // namespace detail

struct ResolverConfigHashTxtValue {
    std::optional<std::int64_t> ts;
    std::string hash;
};

enum class ResolverConfigHashProbeStatus : uint8_t {
    SUCCESS,
    NO_USABLE_TXT,
    INVALID_TXT,
    QUERY_FAILED,
};

struct ResolverConfigHashProbeResult {
    ResolverConfigHashProbeStatus status{ResolverConfigHashProbeStatus::QUERY_FAILED};
    std::optional<std::string> raw_txt;
    ResolverConfigHashTxtValue parsed_value;
    std::string error;
};

// Query a single TXT record from the configured DNS resolver.
// Returns the selected TXT answer payload when available.
std::optional<std::string> query_dns_txt_record(const std::string& dns_server_address,
                                                const std::string& domain,
                                                std::chrono::milliseconds timeout,
                                                std::string* error_out = nullptr);

// Normalize TXT payload variants (quoted/value-wrapped) to a raw md5-like value.
std::string normalize_dns_txt_md5(const std::string& txt_payload);
// Parse TXT payload variants like "<ts>|<hash>" and return timestamp/hash parts.
ResolverConfigHashTxtValue parse_resolver_config_hash_txt(const std::string& txt_payload);
// Validate whether the parsed payload contains a usable md5 hash.
bool is_valid_resolver_config_hash_txt_value(const ResolverConfigHashTxtValue& value);
// Query and classify the resolver config-hash TXT payload in one step.
ResolverConfigHashProbeResult query_resolver_config_hash_txt(const std::string& dns_server_address,
                                                            const std::string& domain,
                                                            std::chrono::milliseconds timeout);

// Query A (IPv4) records for a domain from a specific resolver, bypassing the
// system stub resolver and any dnsmasq cache. Returns dotted-quad addresses.
// On failure (timeout, NXDOMAIN, malformed response) returns an empty vector;
// error_out (if provided) is populated with a human-readable reason.
std::vector<std::string> query_dns_a_records(const std::string& dns_server_address,
                                             const std::string& domain,
                                             std::chrono::milliseconds timeout,
                                             std::string* error_out = nullptr);

// Query AAAA (IPv6) records for a domain from a specific resolver. Returns
// canonical IPv6 strings (inet_ntop output). Empty result on failure.
std::vector<std::string> query_dns_aaaa_records(const std::string& dns_server_address,
                                                const std::string& domain,
                                                std::chrono::milliseconds timeout,
                                                std::string* error_out = nullptr);

} // namespace keen_pbr3
