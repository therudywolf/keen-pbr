#pragma once

#include <chrono>

namespace keen_pbr3 {

// Why a urltest outbound moved off the child its routing was built for.
// Logged with every switch; the conntrack flush that follows a switch does
// not depend on it (without CONNMARK every switch moves the flows anyway).
enum class UrltestSwitchReason {
    initial,                 // no child was applied yet
    selected_path_unhealthy, // the applied child failed its probe or its breaker opened
    healthy_policy_change,   // the applied child still works; a better candidate won
};

inline UrltestSwitchReason classify_urltest_switch(bool has_applied_child,
                                                   bool applied_child_healthy) {
    if (!has_applied_child) {
        return UrltestSwitchReason::initial;
    }
    return applied_child_healthy ? UrltestSwitchReason::healthy_policy_change
                                 : UrltestSwitchReason::selected_path_unhealthy;
}

inline const char* urltest_switch_reason_name(UrltestSwitchReason reason) {
    switch (reason) {
    case UrltestSwitchReason::initial:
        return "initial";
    case UrltestSwitchReason::selected_path_unhealthy:
        return "selected-path-unhealthy";
    case UrltestSwitchReason::healthy_policy_change:
        return "healthy-policy-change";
    }
    return "unknown";
}

// A conntrack flush that failed after a urltest switch is retried at most
// this many times (5 s, 15 s, 45 s); a newer switch of the same urltest
// cancels the pending retry.
constexpr unsigned kMaxUrltestFlushRetries = 3;

inline std::chrono::seconds urltest_flush_retry_delay(unsigned attempt) {
    std::chrono::seconds delay{5};
    for (unsigned i = 0; i < attempt && i < kMaxUrltestFlushRetries; ++i) {
        delay *= 3;
    }
    return delay;
}

} // namespace keen_pbr3
