#pragma once

#include <algorithm>
#include <chrono>
#include <map>
#include <optional>
#include <string>

namespace keen_pbr3 {

// How far back another member's failure still makes a failure of the applied
// member look like a stall of the whole router: three probe rounds, kept
// between 1 and 15 minutes.
inline std::chrono::seconds urltest_stall_window(std::chrono::seconds interval) {
    return std::clamp(interval * 3, std::chrono::seconds{60}, std::chrono::seconds{900});
}

// The longest a stall may keep a failing member applied: two probe rounds,
// kept between 3 and 10 minutes. A stall that lasts longer is treated as an
// outage of the applied member after all.
inline std::chrono::seconds urltest_stall_max_hold(std::chrono::seconds interval) {
    return std::clamp(interval * 2, std::chrono::seconds{180}, std::chrono::seconds{600});
}

// Tells a stall of the whole router from a failure of one tunnel, for one
// urltest group.
//
// On a weak router a memory or CPU stall makes the probes of every member
// fail at about the same time. Switching then walks the group through its
// members, and each switch flushes the conntrack entries of the flows it
// moves: on 2026-11-04 an OOM on the router dropped about 2800 connections in
// three switches, none of which could help. Such a stall shows as
// correlation: the applied member fails while another member that was
// working a moment ago fails too. A member that has not worked for a while
// does not count, so a reserve that is simply dead cannot keep the group on
// a dead primary.
class UrltestStallGuard {
public:
    using Clock = std::chrono::steady_clock;

    enum class Verdict {
        switch_now,     // a failure of the applied member alone: switch as before
        hold_started,   // a stall: keep the applied member, first round of the hold
        hold_continued, // still a stall, still within the hold limit
        hold_expired,   // a stall for too long: switch after all
    };

    UrltestStallGuard() = default;
    UrltestStallGuard(std::chrono::seconds window, std::chrono::seconds max_hold)
        : window_(window), max_hold_(max_hold) {}

    // Record one probe result of a member.
    void record(const std::string& member, bool success, Clock::time_point now) {
        Track& track = tracks_[member];
        if (success) {
            track.last_success = now;
        } else {
            track.last_failure = now;
        }
    }

    // The selection is about to move off `applied` because its probe failed.
    // `applied_interface_gone`: the applied member's own device is missing or
    // down, so nothing can flow through it and there is nothing to hold for.
    Verdict on_unhealthy_switch(const std::string& applied,
                                bool applied_interface_gone,
                                Clock::time_point now) {
        correlated_with_.clear();
        if (applied_interface_gone) {
            hold_since_.reset();
            return Verdict::switch_now;
        }
        for (const auto& [member, track] : tracks_) {
            if (member == applied) {
                continue;
            }
            const bool failed_recently =
                track.last_failure.has_value() && now - *track.last_failure <= window_;
            const bool worked_recently =
                track.last_success.has_value() && now - *track.last_success <= window_ * 2;
            if (failed_recently && worked_recently) {
                correlated_with_ = member;
                break;
            }
        }
        if (correlated_with_.empty()) {
            hold_since_.reset();
            return Verdict::switch_now;
        }
        if (!hold_since_.has_value()) {
            hold_since_ = now;
            return Verdict::hold_started;
        }
        if (now - *hold_since_ >= max_hold_) {
            hold_since_.reset();
            return Verdict::hold_expired;
        }
        return Verdict::hold_continued;
    }

    // The applied member works again, or the group moved: end any hold.
    // Returns whether a hold was in progress.
    bool end_hold() {
        const bool was_holding = hold_since_.has_value();
        hold_since_.reset();
        return was_holding;
    }

    bool holding() const { return hold_since_.has_value(); }

    // The member whose recent failure made the last verdict a stall.
    const std::string& correlated_with() const { return correlated_with_; }

    std::chrono::seconds window() const { return window_; }
    std::chrono::seconds max_hold() const { return max_hold_; }

private:
    struct Track {
        std::optional<Clock::time_point> last_success;
        std::optional<Clock::time_point> last_failure;
    };

    std::chrono::seconds window_{60};
    std::chrono::seconds max_hold_{180};
    std::map<std::string, Track> tracks_;
    std::optional<Clock::time_point> hold_since_;
    std::string correlated_with_;
};

} // namespace keen_pbr3
