#pragma once

#include <algorithm>
#include <chrono>
#include <optional>

namespace keen_pbr3 {

// Leading-edge coalescing of runtime refresh triggers (SIGUSR1 from the
// netfilter hook, interface events).
//
// The first trigger after a quiet period is due after `leading_delay` (kept
// tiny: it only moves the refresh out of the handler that saw the trigger,
// e.g. the netlink receive loop). Triggers arriving while a refresh is
// pending, or within `min_gap` after the previous refresh, collapse into one
// trailing refresh at the end of that gap. Unlike a debounce that restarts
// its timer on every trigger, a steady stream of triggers cannot postpone
// the refresh forever, and there is at most one refresh per `min_gap`.
class RefreshCoalescer {
public:
    using Clock = std::chrono::steady_clock;

    RefreshCoalescer(std::chrono::milliseconds leading_delay,
                     std::chrono::milliseconds min_gap)
        : leading_delay_(leading_delay), min_gap_(min_gap) {}

    // Register a trigger at `now`. Returns the delay after which a refresh
    // timer must be armed, or std::nullopt when the refresh already pending
    // covers this trigger.
    std::optional<std::chrono::milliseconds> on_trigger(Clock::time_point now) {
        if (pending_) {
            return std::nullopt;
        }
        pending_ = true;
        const auto due = std::max(now + leading_delay_, quiet_until_);
        // A zero delay would disarm a timerfd: never return less than 1 ms.
        return std::max(std::chrono::milliseconds{1},
                        std::chrono::ceil<std::chrono::milliseconds>(due - now));
    }

    // The pending refresh starts running at `now`.
    void on_refresh_started(Clock::time_point now) {
        pending_ = false;
        quiet_until_ = std::max(quiet_until_, now + min_gap_);
    }

    // The refresh that started earlier has finished at `now`. The gap counts
    // from here as well, so a refresh slower than `min_gap` (weak MIPS CPU)
    // is never followed back-to-back by the next one.
    void on_refresh_finished(Clock::time_point now) {
        quiet_until_ = std::max(quiet_until_, now + min_gap_);
    }

    // A pending refresh was dropped: covered by another full refresh, or the
    // runtime was stopped. The quiet window is kept.
    void cancel() { pending_ = false; }

    bool pending() const { return pending_; }

private:
    std::chrono::milliseconds leading_delay_;
    std::chrono::milliseconds min_gap_;
    bool pending_{false};
    Clock::time_point quiet_until_{};
};

} // namespace keen_pbr3
