#pragma once

#include <exception>
#include <optional>
#include <string>
#include <utility>

namespace keen_pbr3 {

// Run `fn` and turn any exception it throws into its message.
//
// Every callback dispatched by the epoll loop (fd handlers, control tasks,
// scheduled tasks) goes through this: an exception escaping one of them
// would otherwise unwind the loop and stop the daemon, which tears down the
// routes and firewall rules it maintains. Returns std::nullopt on success.
template <typename Fn>
std::optional<std::string> invoke_guarded(Fn&& fn) {
    try {
        std::forward<Fn>(fn)();
        return std::nullopt;
    } catch (const std::exception& e) {
        return std::string(e.what());
    } catch (...) {
        return std::string("unknown error");
    }
}

// Consecutive-failure bookkeeping for one repeating scheduled task. A task
// that keeps throwing is disabled instead of logging an error on every tick.
class RepeatingTaskFailures {
public:
    static constexpr int kMaxConsecutiveFailures = 3;

    // Record the outcome of one run. Returns true when the task has now
    // failed kMaxConsecutiveFailures times in a row and should be disabled.
    bool record(bool failed) {
        consecutive_ = failed ? consecutive_ + 1 : 0;
        return consecutive_ >= kMaxConsecutiveFailures;
    }

    int consecutive() const { return consecutive_; }

private:
    int consecutive_{0};
};

} // namespace keen_pbr3
