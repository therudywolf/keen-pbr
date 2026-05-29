#pragma once

#include "../cmd/test_routing.hpp"
#include "../config/config.hpp"

#include <functional>
#include <string>
#include <vector>

namespace keen_pbr3 {

// Periodic auto-heal worker (auto-heal v2).
// =========================================
// Generalizes the manual POST /api/autoheal/promote endpoint into a background
// task: every tick it re-evaluates each watchlist domain the same way
// `forest-pbr test-routing` does, and promotes any that are currently "leaking"
// (resolving to a non-auto-heal outbound) into the auto-heal list — exactly the
// same transformation promote_domains() applies for the manual endpoint.
//
// SAFETY — zero behavior unless explicitly enabled
// ------------------------------------------------
// The worker is a strict no-op unless daemon.autoheal_enabled == true AND
// daemon.autoheal_watchlist is non-empty. Both conditions are re-checked from
// the LIVE config on every tick (the worker holds a config accessor, not a
// snapshot), so disabling either one at runtime immediately neutralises it.
// When neutralised, tick() returns without resolving anything, without touching
// config, and without reapplying routing. The daemon additionally avoids even
// scheduling the worker when it is disabled (see Daemon::schedule_autoheal_worker),
// so the default configuration starts no thread and runs no DNS queries.
//
// The worker only ever ADDS domains to the auto list via promote_domains, which
// is itself purely additive and idempotent: existing list entries and the order
// of every other route rule are preserved.
//
// Lifecycle mirrors ListWarmer: the Daemon owns one instance, (re)creates it on
// every config apply, and drives tick() from a repeating Scheduler task. All
// collaborators are injected so the worker can be unit-tested without DNS, a
// kernel, or the filesystem.
class AutohealWorker {
public:
    // Resolves a target's routing exactly like `forest-pbr test-routing`. The
    // daemon wires this to compute_test_routing over the live config + cache.
    using RoutingEvaluator =
        std::function<TestRoutingResult(const std::string& target)>;
    // Persists + reapplies a mutated config using the daemon's existing
    // config-save path (atomic write to config.json followed by apply_config /
    // firewall+dnsmasq reapply). Throwing propagates the failure to tick(),
    // which logs and leaves the previous config in force.
    using ConfigApplier = std::function<void(Config promoted)>;

    AutohealWorker(std::function<const Config&()> get_app_config,
                   RoutingEvaluator routing_evaluator,
                   ConfigApplier config_applier);

    // Run one auto-heal pass over the current config. Returns the number of
    // domains promoted this tick (0 when disabled, watchlist empty, nothing
    // leaking, or everything already promoted). Never throws — collaborator
    // failures are caught and logged so a Scheduler tick can never abort the
    // daemon.
    int tick() noexcept;

private:
    std::function<const Config&()> get_app_config_;
    RoutingEvaluator routing_evaluator_;
    ConfigApplier config_applier_;
};

}  // namespace keen_pbr3
