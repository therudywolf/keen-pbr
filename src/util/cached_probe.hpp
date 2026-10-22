#pragma once

#include <chrono>
#include <mutex>
#include <optional>
#include <utility>

namespace keen_pbr3 {

// Remembers the answer of a capability probe that spawns helper processes
// (`which`, `ip6tables`, `ip6tables-restore --test`, `nft -c`). Those probes
// used to run on every firewall refresh, and on Keenetic NDM triggers a
// SIGUSR1 refresh roughly once a minute.
//
// A positive answer is kept for the process lifetime. A negative answer is
// only trusted for `negative_retry`: during boot a probe can fail transiently
// (IPv6 netfilter modules still loading), and the daemon must not stay in the
// degraded mode until the next restart because of that.
class CachedProbe {
public:
    explicit CachedProbe(std::chrono::steady_clock::duration negative_retry =
                             std::chrono::seconds{60})
        : negative_retry_(negative_retry) {}

    CachedProbe(const CachedProbe&) = delete;
    CachedProbe& operator=(const CachedProbe&) = delete;

    template <typename Probe>
    bool get(Probe&& probe) {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto now = std::chrono::steady_clock::now();
        if (value_.has_value() && (*value_ || now < negative_until_)) {
            return *value_;
        }
        // The lock is held while probing so concurrent callers (event loop
        // and API threads) share one probe instead of spawning duplicates.
        const bool result = std::forward<Probe>(probe)();
        value_ = result;
        negative_until_ = now + negative_retry_;
        return result;
    }

    void reset() {
        std::lock_guard<std::mutex> lock(mutex_);
        value_.reset();
        negative_until_ = {};
    }

private:
    std::mutex mutex_;
    std::chrono::steady_clock::duration negative_retry_;
    std::optional<bool> value_;
    std::chrono::steady_clock::time_point negative_until_{};
};

} // namespace keen_pbr3
