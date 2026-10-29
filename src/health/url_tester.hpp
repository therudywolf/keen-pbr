#pragma once

#include "../config/config.hpp"

#include <cstdint>
#include <optional>
#include <string>

namespace keen_pbr3 {

// Keep urltest probe timeouts independent from circuit-breaker cooldowns.
constexpr uint32_t kDefaultUrltestProbeTimeoutMs = 5000;

struct URLTestResult {
    bool success{false};
    uint32_t latency_ms{0};
    std::string error;
};

class URLTester {
public:
    URLTester();
    ~URLTester();

    URLTester(const URLTester&) = delete;
    URLTester& operator=(const URLTester&) = delete;

    // Test a URL through an outbound identified by its fwmark.
    // Uses SO_MARK to route test traffic via the correct routing table.
    // With `bind_interface`, every probe socket is also bound to that device
    // (SO_BINDTODEVICE). An interface member whose table is empty (its link
    // is down) would otherwise fall through the ip rules to `main` and be
    // probed as healthy over another uplink; bound, the connect fails, and a
    // missing interface fails the bind. A bound probe also tries only the
    // address families that device has an address of (probe_ip_families()).
    // Retries up to retry.attempts times with retry.interval_ms delay between
    // attempts (not after a failed bind). Returns the result with latency_ms
    // from the fastest successful attempt.
    URLTestResult test(const std::string& url, uint32_t fwmark,
                       uint32_t timeout_ms, const RetryConfig& retry,
                       const std::string& bind_interface = {});

private:
    URLTestResult test_once(const std::string& url, uint32_t fwmark,
                            uint32_t timeout_ms,
                            const std::string& bind_interface,
                            bool& retryable);
};

// Why a probe through `interface_name` cannot succeed right now (the
// interface does not exist or is administratively down), or std::nullopt.
// One if_nametoindex() plus one SIOCGIFFLAGS ioctl: cheap enough to run
// before every probe, and it spares the retries of a hopeless probe.
std::optional<std::string> probe_interface_unavailable(const std::string& interface_name);

// Address families a probe bound to an interface may try.
enum class ProbeIpFamilies {
    any,
    ipv4_only,
    ipv6_only,
};

// A bound probe tries only the families its interface has an address of. A
// link-local IPv6 address does not count: every interface has one. Through a
// device without an address of the family the kernel takes the source address
// from another interface (on Keenetic, ezcfg0 holds a global IPv6 address),
// and the far end of a tunnel cannot answer it. sing-box's gvisor tun even
// completes such an IPv6 handshake by itself and drops the connection only
// afterwards; curl's happy eyeballs keeps that dead socket, and the probe
// fails although IPv4 works. With both families or neither: any.
ProbeIpFamilies probe_ip_families(bool has_ipv4, bool has_ipv6);

// probe_ip_families() for the addresses `interface_name` has now
// (getifaddrs); any for an empty name or when they cannot be read.
ProbeIpFamilies probe_interface_ip_families(const std::string& interface_name);

} // namespace keen_pbr3
