#include "url_tester.hpp"

#include "../log/logger.hpp"

#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <curl/curl.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

namespace keen_pbr3 {

namespace {

struct ProbeSocketOptions {
    uint32_t fwmark{0};
    std::string bind_interface;
    int bind_errno{0}; // errno of a failed SO_BINDTODEVICE
};

} // namespace

// Discard response body
static size_t discard_callback(char* /*ptr*/, size_t size, size_t nmemb,
                               void* /*userdata*/) {
    if (nmemb != 0 && size > SIZE_MAX / nmemb) return 0;
    return size * nmemb;
}

// Socket option callback: SO_MARK for policy routing and, for interface
// members, SO_BINDTODEVICE so the probe can only leave through that member.
static int sockopt_callback(void* clientp, curl_socket_t curlfd,
                            curlsocktype /*purpose*/) {
    if (!clientp) {
        return CURL_SOCKOPT_OK;
    }
    auto* options = static_cast<ProbeSocketOptions*>(clientp);
    const uint32_t mark = options->fwmark;
    if (mark != 0 &&
        setsockopt(curlfd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) < 0) {
        return CURL_SOCKOPT_ERROR;
    }
    if (!options->bind_interface.empty() &&
        setsockopt(curlfd, SOL_SOCKET, SO_BINDTODEVICE,
                   options->bind_interface.c_str(),
                   static_cast<socklen_t>(options->bind_interface.size() + 1)) < 0) {
        options->bind_errno = errno;
        return CURL_SOCKOPT_ERROR;
    }
    return CURL_SOCKOPT_OK;
}

std::optional<std::string> probe_interface_unavailable(const std::string& interface_name) {
    if (interface_name.empty()) {
        return std::nullopt;
    }
    if (if_nametoindex(interface_name.c_str()) == 0) {
        return "interface " + interface_name + " does not exist";
    }
    const int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        return std::nullopt; // cannot tell; let the probe decide
    }
    struct ifreq ifr {};
    std::strncpy(ifr.ifr_name, interface_name.c_str(), IFNAMSIZ - 1);
    const int rc = ioctl(fd, SIOCGIFFLAGS, &ifr);
    close(fd);
    if (rc == 0 && (ifr.ifr_flags & IFF_UP) == 0) {
        return "interface " + interface_name + " is down";
    }
    return std::nullopt;
}

URLTester::URLTester() {}

URLTester::~URLTester() = default;

URLTestResult URLTester::test_once(const std::string& url, uint32_t fwmark,
                                   uint32_t timeout_ms,
                                   const std::string& bind_interface,
                                   bool& retryable) {
    URLTestResult result;
    retryable = true;
    const auto started_at = std::chrono::steady_clock::now();
    Logger::instance().trace("url_test_once_start",
                             "url={} fwmark={} timeout_ms={}",
                             url,
                             fwmark,
                             timeout_ms);

    CURL* curl = curl_easy_init();
    if (!curl) {
        result.error = "Failed to initialize curl handle";
        Logger::instance().trace("url_test_once_error",
                                 "url={} fwmark={} duration_ms={} error={}",
                                 url,
                                 fwmark,
                                 std::chrono::duration_cast<std::chrono::milliseconds>(
                                     std::chrono::steady_clock::now() - started_at).count(),
                                 result.error);
        return result;
    }

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, discard_callback);
    // Mandatory in a threaded process: libcurl built without AsynchDNS (the
    // Entware/Keenetic build is) implements the name-resolution timeout with
    // alarm() + SIGALRM + siglongjmp. The signal is delivered to an arbitrary
    // thread, whose longjmp then unwinds a stack it does not own — a crash
    // that fires exactly when DNS is slow or the WAN is down. NOSIGNAL makes
    // libcurl use its own timeout instead.
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, static_cast<long>(timeout_ms));
    // With NOSIGNAL the connect phase needs its own bound, otherwise a black-
    // holed route can hold the probe for the full request timeout.
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS,
                     static_cast<long>(timeout_ms));
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 3L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "keen-pbr-urltest");

    // Route test traffic through the outbound's fwmark via SO_MARK, and pin
    // it to the member's interface when it has one.
    ProbeSocketOptions socket_options;
    socket_options.fwmark = fwmark;
    socket_options.bind_interface = bind_interface;
    curl_easy_setopt(curl, CURLOPT_SOCKOPTFUNCTION, sockopt_callback);
    curl_easy_setopt(curl, CURLOPT_SOCKOPTDATA, &socket_options);

    auto start = std::chrono::steady_clock::now();
    CURLcode res = curl_easy_perform(curl);
    auto end = std::chrono::steady_clock::now();

    if (res != CURLE_OK) {
        if (socket_options.bind_errno != 0) {
            // The interface vanished: retrying within this round cannot help.
            result.error = "cannot bind probe to " + bind_interface + ": " +
                           std::strerror(socket_options.bind_errno);
            retryable = false;
        } else {
            result.error = curl_easy_strerror(res);
        }
        curl_easy_cleanup(curl);
        Logger::instance().trace("url_test_once_error",
                                 "url={} fwmark={} duration_ms={} error={}",
                                 url,
                                 fwmark,
                                 std::chrono::duration_cast<std::chrono::milliseconds>(
                                     end - started_at).count(),
                                 result.error);
        return result;
    }

    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    curl_easy_cleanup(curl);

    if (http_code >= 200 && http_code < 300) {
        result.success = true;
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        result.latency_ms = static_cast<uint32_t>(ms.count());
        Logger::instance().trace("url_test_once_end",
                                 "url={} fwmark={} duration_ms={} latency_ms={} http_code={}",
                                 url,
                                 fwmark,
                                 std::chrono::duration_cast<std::chrono::milliseconds>(
                                     end - started_at).count(),
                                 result.latency_ms,
                                 http_code);
    } else {
        result.error = "HTTP " + std::to_string(http_code);
        Logger::instance().trace("url_test_once_error",
                                 "url={} fwmark={} duration_ms={} error={}",
                                 url,
                                 fwmark,
                                 std::chrono::duration_cast<std::chrono::milliseconds>(
                                     end - started_at).count(),
                                 result.error);
    }

    return result;
}

URLTestResult URLTester::test(const std::string& url, uint32_t fwmark,
                              uint32_t timeout_ms, const RetryConfig& retry,
                              const std::string& bind_interface) {
    URLTestResult best;
    best.error = "No attempts made";
    const auto total_started_at = std::chrono::steady_clock::now();
    const auto attempts = static_cast<uint32_t>(retry.attempts.value_or(1));
    Logger::instance().trace("url_test_start",
                             "url={} fwmark={} interface={} timeout_ms={} attempts={}",
                             url,
                             fwmark,
                             bind_interface.empty() ? std::string("-") : bind_interface,
                             timeout_ms,
                             attempts);

    for (uint32_t attempt = 0; attempt < attempts; ++attempt) {
        if (attempt > 0) {
            std::this_thread::sleep_for(
                std::chrono::milliseconds(retry.interval_ms.value_or(1000)));
        }

        Logger::instance().trace("url_test_attempt_start",
                                 "url={} fwmark={} attempt={} attempts={}",
                                 url,
                                 fwmark,
                                 attempt + 1,
                                 attempts);
        bool retryable = true;
        auto result = test_once(url, fwmark, timeout_ms, bind_interface, retryable);
        if (result.success) {
            if (!best.success || result.latency_ms < best.latency_ms) {
                best = result;
            }
            Logger::instance().trace("url_test_end",
                                     "url={} fwmark={} duration_ms={} success=true latency_ms={}",
                                     url,
                                     fwmark,
                                     std::chrono::duration_cast<std::chrono::milliseconds>(
                                         std::chrono::steady_clock::now() - total_started_at).count(),
                                     best.latency_ms);
            return best;
        }

        best.error = result.error;
        Logger::instance().trace("url_test_attempt_end",
                                 "url={} fwmark={} attempt={} attempts={} success=false error={}",
                                 url,
                                 fwmark,
                                 attempt + 1,
                                 attempts,
                                 best.error);
        if (!retryable) {
            break;
        }
    }

    Logger::instance().trace("url_test_end",
                             "url={} fwmark={} duration_ms={} success=false error={}",
                             url,
                             fwmark,
                             std::chrono::duration_cast<std::chrono::milliseconds>(
                                 std::chrono::steady_clock::now() - total_started_at).count(),
                             best.error);
    return best;
}

} // namespace keen_pbr3
