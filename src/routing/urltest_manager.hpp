#pragma once

#include "../config/config.hpp"
#include "../health/circuit_breaker.hpp"
#include "../health/url_tester.hpp"
#include "../util/blocking_executor.hpp"
#include "../util/traced_mutex.hpp"
#include "urltest_probe.hpp"

#include <functional>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace keen_pbr3 {

class Scheduler;

// Per-urltest outbound state: test results, circuit breakers, selected child.
struct UrltestState {
    Outbound config;
    std::map<std::string, URLTestResult> last_results;
    std::map<std::string, CircuitBreaker> circuit_breakers;
    std::string selected_outbound;
    // Device each interface-type candidate is probed through (child tag ->
    // interface); table-type candidates are probed by fwmark only.
    std::map<std::string, std::string> probe_interfaces;
    int scheduler_task_id{-1};
    bool probe_inflight{false};
    std::uint64_t generation{0};
};

// Callback invoked after every committed probe round with the currently
// selected child, whether it changed or not: the daemon compares it with the
// child its routing was built for, so a switch whose apply failed (and was
// rolled back) is retried by the next round.
// Parameters: (urltest_tag, selected_child_outbound_tag)
// Guaranteed to be called without any UrltestManager lock held.
using UrltestChangeCallback = std::function<void(const std::string&, const std::string&)>;
// Hands a finished probe round to the control thread, which then calls
// commit_probe_results(). Returns false when the round could not be queued;
// the manager then releases the probe itself.
using UrltestCommitCallback = std::function<bool(const std::string&,
                                                 std::uint64_t,
                                                 std::map<std::string, URLTestResult>,
                                                 TraceId)>;

// Manages periodic URL testing for urltest outbounds, tracks per-child-outbound
// latencies and circuit breaker states, and selects the best outbound using the
// weighted group algorithm.
//
// All public methods are thread-safe.
class UrltestManager {
public:
    UrltestManager(URLTester& tester, const OutboundMarkMap& marks,
                   Scheduler& scheduler,
                   BlockingExecutor& blocking_executor,
                   UrltestChangeCallback on_change,
                   UrltestCommitCallback on_commit);
    ~UrltestManager();

    UrltestManager(const UrltestManager&) = delete;
    UrltestManager& operator=(const UrltestManager&) = delete;

    // Register a urltest outbound, queue the initial URL test, and schedule
    // periodic retests. on_change_ reports the selection once a round commits.
    // `outbounds` (the whole config) tells which candidates are interfaces, so
    // their probes can be bound to the member's own device.
    void register_urltest(const Outbound& ut,
                          const std::vector<Outbound>& outbounds = {});

    // Run tests immediately for a specific urltest outbound (e.g. on SIGUSR1).
    // Invokes on_change_ if the selection changes.
    void trigger_immediate_test(const std::string& urltest_tag);
    bool commit_probe_results(const std::string& urltest_tag,
                              std::uint64_t generation,
                              std::map<std::string, URLTestResult> results);

    // Return the currently selected child outbound tag, or "" if none.
    std::string get_selected(const std::string& urltest_tag) const;

    // Return a state snapshot for API/status reporting.
    // Returns std::nullopt if the tag is not registered.
    std::optional<UrltestState> get_state(const std::string& urltest_tag) const;

    // Cancel all scheduled tasks and unregister all outbounds.
    void clear();

private:
    // Check whether an async probe still belongs to the currently registered
    // state for the given tag. Caller must hold at least a shared_lock.
    bool is_probe_current(const std::string& tag,
                          std::uint64_t generation) const REQUIRES_SHARED(mutex_);

    // Release a probe round that will never be committed (exception, stale
    // abort, commit not queued): clear probe_inflight and end the candidates'
    // circuit-breaker requests, or the group stops probing for good.
    void abandon_probe(const std::string& tag,
                       std::uint64_t generation,
                       const std::vector<std::string>& child_tags);

    // Run URL tests for all child outbounds of the given urltest and update
    // the internal selection. Returns the new selection if it changed.
    // Must NOT be called while holding mutex_.
    bool queue_probe_unlocked(const std::string& tag, const std::string& reason);

    // Periodic test entry point (called by the scheduler).
    // Runs tests and invokes on_change_ if the selection changes.
    void run_tests(const std::string& tag);

    // Select the best outbound using the weighted group / tolerance algorithm.
    // Caller must hold at least a shared_lock on mutex_.
    std::string select_outbound(const std::string& tag) REQUIRES_SHARED(mutex_);

    URLTester& tester_;
    const OutboundMarkMap& marks_;
    Scheduler& scheduler_;
    BlockingExecutor& blocking_executor_;
    UrltestChangeCallback on_change_;
    UrltestCommitCallback on_commit_;

    mutable TracedSharedMutex mutex_;
    std::map<std::string, UrltestState> states_ GUARDED_BY(mutex_);
    std::uint64_t generation_ GUARDED_BY(mutex_){1};
    // Rate limit of the "probe failed" warnings (kept across clear(), so a
    // config apply does not repeat a warning about a failure that persists).
    ProbeFailureLog probe_failure_log_ GUARDED_BY(mutex_);
};

} // namespace keen_pbr3
