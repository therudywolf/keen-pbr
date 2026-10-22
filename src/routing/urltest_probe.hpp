#pragma once

#include "../config/config.hpp"

#include <cctype>
#include <chrono>
#include <map>
#include <string>
#include <vector>

namespace keen_pbr3 {

// Interface each urltest candidate's probe must be bound to, by child tag.
// Interface members are probed through their own device: a member whose
// link is down has an empty table, and a probe carrying only its fwmark
// falls through the ip rules to `main` and succeeds over another uplink.
// Table members (and unknown tags) are probed by fwmark only.
inline std::map<std::string, std::string> urltest_probe_interfaces(
    const Outbound& urltest,
    const std::vector<Outbound>& outbounds) {
    std::map<std::string, std::string> interfaces;
    for (const auto& group : urltest.outbound_groups.value_or(std::vector<OutboundGroup>{})) {
        for (const auto& child_tag : group.outbounds) {
            for (const auto& outbound : outbounds) {
                if (outbound.tag != child_tag) {
                    continue;
                }
                if (outbound.type == OutboundType::INTERFACE &&
                    outbound.interface.has_value() && !outbound.interface->empty()) {
                    interfaces[child_tag] = *outbound.interface;
                }
                break;
            }
        }
    }
    return interfaces;
}

// Probe errors that differ only in numbers ("after 5001 milliseconds") are
// the same error for logging purposes.
inline std::string normalize_probe_error(const std::string& error) {
    std::string normalized;
    normalized.reserve(error.size());
    bool in_number = false;
    for (const char ch : error) {
        if (std::isdigit(static_cast<unsigned char>(ch)) != 0) {
            if (!in_number) {
                normalized += '#';
            }
            in_number = true;
            continue;
        }
        in_number = false;
        normalized += ch;
    }
    return normalized;
}

// Rate limit for "urltest probe failed" warnings on a weak router: a child's
// failure is logged when it first appears or its error changes, then at most
// once per `repeat_interval` while it persists; its recovery is logged once.
class ProbeFailureLog {
public:
    using Clock = std::chrono::steady_clock;

    enum class Action {
        none,
        log_failure,
        log_recovery,
    };

    explicit ProbeFailureLog(std::chrono::seconds repeat_interval = std::chrono::minutes{10})
        : repeat_interval_(repeat_interval) {}

    // Record one probe result of `key` (urltest tag + child) at `now`.
    Action record(const std::string& key,
                  bool success,
                  const std::string& error,
                  Clock::time_point now) {
        const auto it = failing_.find(key);
        if (success) {
            if (it == failing_.end()) {
                return Action::none;
            }
            failing_.erase(it);
            return Action::log_recovery;
        }

        const std::string error_class = normalize_probe_error(error);
        if (it == failing_.end()) {
            failing_.emplace(key, Entry{error_class, now});
            return Action::log_failure;
        }
        if (it->second.error_class != error_class ||
            now - it->second.last_logged >= repeat_interval_) {
            it->second = Entry{error_class, now};
            return Action::log_failure;
        }
        return Action::none;
    }

private:
    struct Entry {
        std::string error_class;
        Clock::time_point last_logged;
    };

    std::chrono::seconds repeat_interval_;
    std::map<std::string, Entry> failing_;
};

} // namespace keen_pbr3
