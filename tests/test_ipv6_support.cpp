#include "../src/util/ipv6_support.hpp"

#include "../src/config/config.hpp"
#include "../src/util/cached_probe.hpp"
#include "../src/util/firewall_backend_utils.hpp"

#include <doctest/doctest.h>

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <optional>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>
#include <utility>

namespace keen_pbr3 {

namespace {

class EnvironmentGuard {
public:
    explicit EnvironmentGuard(std::string name)
        : name_(std::move(name)) {
        if (const char* value = std::getenv(name_.c_str())) {
            previous_value_ = value;
        }
    }

    ~EnvironmentGuard() {
        if (previous_value_) {
            setenv(name_.c_str(), previous_value_->c_str(), 1);
        } else {
            unsetenv(name_.c_str());
        }
    }

    void set(const std::string& value) {
        if (setenv(name_.c_str(), value.c_str(), 1) != 0) {
            throw std::runtime_error("setenv failed");
        }
    }

private:
    std::string name_;
    std::optional<std::string> previous_value_;
};

class TempDir {
public:
    TempDir() {
        char path_template[] = "/tmp/forest-pbr-ipv6-probe-XXXXXX";
        const char* created = mkdtemp(path_template);
        if (created == nullptr) {
            throw std::runtime_error("mkdtemp failed");
        }
        path_ = created;
    }

    ~TempDir() {
        std::error_code error;
        std::filesystem::remove_all(path_, error);
    }

    const std::filesystem::path& path() const { return path_; }

private:
    std::filesystem::path path_;
};

// Probe answers are process-wide; a case that fakes the tools must not leak
// its answer into other cases.
struct ProbeCacheGuard {
    ProbeCacheGuard() { reset(); }
    ~ProbeCacheGuard() { reset(); }

    static void reset() {
        reset_ipv6_probe_cache_for_tests();
        reset_firewall_backend_probe_cache_for_tests();
    }
};

void write_executable(const std::filesystem::path& path, const std::string& content) {
    std::ofstream output(path);
    output << content;
    output.close();
    if (!output || chmod(path.c_str(), 0700) != 0) {
        throw std::runtime_error("failed to create executable");
    }
}

std::string read_file(const std::filesystem::path& path) {
    std::ifstream input(path);
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

// Fake ip6tables/ip6tables-restore that log their arguments and stdin.
// /bin/cat is used by absolute path because PATH only holds the fakes.
void write_fake_ip6tables_tools(const std::filesystem::path& dir, bool restore_succeeds) {
    write_executable(
        dir / "ip6tables",
        "#!/bin/sh\n"
        "printf '%s\\n' \"$*\" >> \"$FAKE_TOOLS_LOG\"\n"
        "[ \"$#\" -eq 3 ] && [ \"$1\" = -t ] && [ \"$2\" = mangle ] && [ \"$3\" = -S ]\n");
    write_executable(
        dir / "ip6tables-restore",
        std::string("#!/bin/sh\n"
                    "printf 'restore %s\\n' \"$*\" >> \"$FAKE_TOOLS_LOG\"\n"
                    "/bin/cat > \"$FAKE_RESTORE_STDIN\"\n") +
            (restore_succeeds ? "[ \"$#\" -eq 1 ] && [ \"$1\" = --test ]\n" : "exit 2\n"));
}

// Cheap host-level capability snapshot used to decide which arm of the
// assertion to make. The CI image and any normal developer Linux box has
// both an AF_INET6 socket and /proc/sys/net/ipv6 — but we keep the test
// portable to containers/sandboxes that mask one but not the other.
bool host_has_inet6_socket() {
    const int fd = ::socket(AF_INET6, SOCK_DGRAM, 0);
    if (fd < 0) {
        return false;
    }
    ::close(fd);
    return true;
}

bool host_has_proc_sys_net_ipv6() {
    struct stat st{};
    if (::stat("/proc/sys/net/ipv6", &st) != 0) {
        return false;
    }
    return S_ISDIR(st.st_mode);
}

} // namespace

// Positive path: when EITHER an AF_INET6 socket call works OR
// /proc/sys/net/ipv6 exists (the kernel exposes the IPv6 sysctl tree),
// system_ipv6_supported() must return true.
//
// This is what protects against the historical Keenetic regression where
// the socket() probe transiently returned EAFNOSUPPORT before NDM finished
// initialising the ipv6 module, and the daemon then latched into IPv4-only
// for the rest of its lifetime even though v6 came up moments later.
TEST_CASE("system_ipv6_supported: detects v6 via socket() when the family is usable") {
    if (!host_has_inet6_socket()) {
        // Skip this assertion on hosts where v6 socket really is unavailable
        // (locked-down CI sandboxes). The proc-fallback assertion below still
        // exercises the new code path.
        MESSAGE("AF_INET6 socket unavailable on this host; skipping socket arm");
    } else {
        CHECK(system_ipv6_supported());
    }
}

TEST_CASE("system_ipv6_supported: proc fallback signals v6 even if socket transiently fails") {
    if (!host_has_proc_sys_net_ipv6()) {
        MESSAGE("/proc/sys/net/ipv6 missing on this host; cannot exercise fallback");
        return;
    }
    // The function must accept /proc as a sufficient signal. We cannot easily
    // inject a socket() failure, but if either probe is true the function
    // returns true — and on this branch /proc is true, so the result must be
    // true regardless of whether the socket call succeeded.
    CHECK(system_ipv6_supported());
}

// resolve_ipv6_support honours the explicit config disable, even on a host
// where every system probe would otherwise return true. Guards against a
// future regression where someone removes the early-return shortcut.
TEST_CASE("resolve_ipv6_support: config flag disables v6 regardless of kernel state") {
    Config cfg;
    cfg.daemon = DaemonConfig{};
    cfg.daemon->ipv6_enabled = false;

    const auto decision = resolve_ipv6_support(cfg);
    CHECK_FALSE(decision.enabled);
    CHECK(decision.reason == Ipv6SupportDecision::Reason::DisabledByConfig);
}

// Default (no explicit ipv6_enabled) on a host that supports v6 yields the
// Enabled decision. This guards the "missing config means opt-in" semantics.
TEST_CASE("resolve_ipv6_support: default config keeps v6 enabled on a v6-capable host") {
    if (!host_has_inet6_socket() && !host_has_proc_sys_net_ipv6()) {
        MESSAGE("host has neither AF_INET6 socket nor /proc/sys/net/ipv6; skipping");
        return;
    }

    Config cfg;
    // No daemon overrides; firewall_ipv6_supported tolerates missing iptables/
    // nft binaries by returning true (see ipv6_support.cpp::firewall_ipv6_supported).
    const auto decision = resolve_ipv6_support(cfg);
    CHECK(decision.enabled);
    CHECK(decision.reason == Ipv6SupportDecision::Reason::Enabled);
}

TEST_CASE("iptables_ipv6_supported: probes ip6tables-restore with a test script") {
    ProbeCacheGuard cache_guard;
    TempDir temp_dir;
    const auto log_path = temp_dir.path() / "tools.log";
    const auto stdin_path = temp_dir.path() / "restore-stdin";
    write_fake_ip6tables_tools(temp_dir.path(), /*restore_succeeds=*/true);

    EnvironmentGuard path_guard("PATH");
    EnvironmentGuard log_guard("FAKE_TOOLS_LOG");
    EnvironmentGuard stdin_guard("FAKE_RESTORE_STDIN");
    path_guard.set(temp_dir.path());
    log_guard.set(log_path);
    stdin_guard.set(stdin_path);

    CHECK(iptables_ipv6_supported());
    CHECK(read_file(log_path) == "-t mangle -S\nrestore --test\n");
    CHECK(read_file(stdin_path) == "*mangle\nCOMMIT\n");

    // A positive answer is cached: SIGUSR1 refreshes must not spawn the
    // probes again.
    CHECK(iptables_ipv6_supported());
    CHECK(iptables_ipv6_supported());
    CHECK(read_file(log_path) == "-t mangle -S\nrestore --test\n");
}

TEST_CASE("iptables_ipv6_supported: failing restore probe reports no IPv6") {
    ProbeCacheGuard cache_guard;
    TempDir temp_dir;
    const auto log_path = temp_dir.path() / "tools.log";
    write_fake_ip6tables_tools(temp_dir.path(), /*restore_succeeds=*/false);

    EnvironmentGuard path_guard("PATH");
    EnvironmentGuard log_guard("FAKE_TOOLS_LOG");
    EnvironmentGuard stdin_guard("FAKE_RESTORE_STDIN");
    path_guard.set(temp_dir.path());
    log_guard.set(log_path);
    stdin_guard.set(temp_dir.path() / "restore-stdin");

    CHECK_FALSE(iptables_ipv6_supported());
    // Within the retry window the negative answer is reused as well.
    CHECK_FALSE(iptables_ipv6_supported());
    CHECK(read_file(log_path) == "-t mangle -S\nrestore --test\n");
}

TEST_CASE("resolve_ipv6_support: config flag is honoured on every call despite cached probes") {
    ProbeCacheGuard cache_guard;
    Config enabled_cfg;
    Config disabled_cfg;
    disabled_cfg.daemon = DaemonConfig{};
    disabled_cfg.daemon->ipv6_enabled = false;

    (void)resolve_ipv6_support(enabled_cfg);
    const auto disabled = resolve_ipv6_support(disabled_cfg);
    CHECK_FALSE(disabled.enabled);
    CHECK(disabled.reason == Ipv6SupportDecision::Reason::DisabledByConfig);

    const auto again = resolve_ipv6_support(enabled_cfg);
    CHECK(again.reason != Ipv6SupportDecision::Reason::DisabledByConfig);
}

TEST_CASE("CachedProbe keeps positive answers and retries negative ones") {
    int calls = 0;
    CachedProbe positive(std::chrono::hours{1});
    CHECK(positive.get([&calls] { ++calls; return true; }));
    CHECK(positive.get([&calls] { ++calls; return false; }));
    CHECK(calls == 1);

    calls = 0;
    CachedProbe negative(std::chrono::milliseconds{20});
    CHECK_FALSE(negative.get([&calls] { ++calls; return false; }));
    CHECK_FALSE(negative.get([&calls] { ++calls; return true; }));
    CHECK(calls == 1);
    std::this_thread::sleep_for(std::chrono::milliseconds{40});
    // The retry window passed: probe again, and a now-positive answer sticks.
    CHECK(negative.get([&calls] { ++calls; return true; }));
    CHECK(negative.get([&calls] { ++calls; return false; }));
    CHECK(calls == 2);

    negative.reset();
    CHECK_FALSE(negative.get([&calls] { ++calls; return false; }));
    CHECK(calls == 3);
}

} // namespace keen_pbr3
