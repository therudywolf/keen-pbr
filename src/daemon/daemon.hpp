#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

#include "../config/config.hpp"
#include "../dns/dns_txt_client.hpp"
#include "config_store.hpp"
#include "../health/url_tester.hpp"
#include "../routing/interface_monitor.hpp"
#include "../routing/firewall_state.hpp"
#include "../routing/netlink.hpp"
#include "../routing/policy_rule.hpp"
#include "../routing/route_table.hpp"
#include "../firewall/firewall.hpp"
#include "../util/blocking_executor.hpp"
#include "../util/traced_mutex.hpp"
#include "list_service.hpp"
#include "pid_file.hpp"
#include "refresh_coalescer.hpp"
#include "runtime_state_store.hpp"
#include "system_resolver_hook.hpp"

namespace keen_pbr3 {

class Firewall;
class Scheduler;
class UrltestManager;
class DnsProbeServer;
class ListWarmer;
class AutohealWorker;
class ConntrackFlusher;
struct DnsProbeEvent;

#ifdef WITH_API
enum class ConfigOperationState : uint8_t;
class ApiServer;
struct ApiContext;
class SseBroadcaster;
struct ConfigApplyResult;
struct ListRefreshOperationResult;
#endif

class DaemonError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// Callback for file descriptor events
using FdCallback = std::function<void(uint32_t events)>;

// Options controlling daemon runtime behavior
struct DaemonOptions {
    bool no_api{false};
};

struct ListsRefreshExecutionResult {
    RemoteListsRefreshResult refresh_result;
    bool reloaded{false};
};

struct PreparedRuntimeInputs {
    Config config;
    OutboundMarkMap outbound_marks;
    bool remote_lists_refreshed{false};
};

// Helper to get tag from any outbound variant
std::string get_outbound_tag(const Outbound& ob);

// Find an outbound by tag, returning pointer or nullptr
const Outbound* find_outbound(const std::vector<Outbound>& outbounds,
                               const std::string& tag);

// Epoll-based daemon that owns all runtime subsystems.
// Handles signal dispatch, routing, firewall, urltest, and API lifecycle.
class Daemon {
public:
    Daemon(Config config,
           std::string config_path,
           DaemonOptions opts,
           HookCommandExecutor hook_command_executor = default_hook_command_executor);
    ~Daemon();

    // Non-copyable, non-movable
    Daemon(const Daemon&) = delete;
    Daemon& operator=(const Daemon&) = delete;
    Daemon(Daemon&&) = delete;
    Daemon& operator=(Daemon&&) = delete;

    // Register an additional file descriptor for epoll monitoring.
    void add_fd(int fd,
                uint32_t events,
                FdCallback cb,
                bool wait_for_completion = true,
                const std::string& label = "");

    // Remove a previously registered file descriptor.
    void remove_fd(int fd,
                   bool wait_for_completion = true,
                   const std::string& label = "");

    // Serialize execution of control operations in event loop.
    void enqueue_control_task(std::function<void()> task,
                              bool wait_for_completion = false,
                              const std::string& label = "");

    // Backward-compatible alias for enqueue_control_task.
    void enqueue_control_command(std::function<void()> command,
                                 bool wait_for_completion = false,
                                 const std::string& label = "");

    // Post a task to the event loop, always deferred to the next iteration.
    // Unlike enqueue_control_task, never executes inline even when called from
    // the event loop thread. Safe to call while holding any lock — the posted
    // task only runs after the current event-loop iteration completes and all
    // caller locks have been released. Use this for callbacks that must not
    // run re-entrantly inside the current controller action.
    // Returns false when the task was dropped because the daemon is shutting
    // down and no longer accepts posted tasks.
    bool post_control_task(std::function<void()> task,
                           const std::string& label = "");

    // Run the daemon lifecycle: startup, event loop, shutdown.
    void run();

    // Request the event loop to stop.
    void stop();

    // Returns true if the daemon is currently running.
    bool running() const;

private:
    // control loop and fd registration
    void setup_signals();
    void handle_signal();
    void setup_control_channel();
    void handle_control_commands();
    void wake_control_loop();
    bool is_event_loop_thread() const;

    // Signal handlers
    void handle_sigusr1();
    // Coalesced runtime refresh (routes + firewall rules) shared by SIGUSR1
    // and interface events; see RefreshCoalescer for the timing.
    void request_runtime_refresh(const std::string& reason);
    void run_coalesced_runtime_refresh();
    // Drop a pending coalesced refresh: a full refresh or apply that started
    // after it was requested covers it, or the runtime is being stopped.
    void cancel_pending_runtime_refresh(const char* why);
    void handle_sighup();
    void handle_interface_monitor_events(uint32_t events);
    void handle_interface_event(const InterfaceMonitor::Event& event);
    // Rebuild the monitor's netlink socket after a receive error or an epoll
    // error/hangup. The old fd leaves epoll before the socket closes; a
    // failed rebuild is retried every 5 s.
    void reconnect_interface_monitor();
    void register_interface_monitor_fd();
    void unregister_interface_monitor_fd();
    void schedule_interface_monitor_reconnect_retry();
    // Probe at once every urltest that has a candidate on this interface.
    void trigger_urltest_probes_for_interface(const std::string& interface_name);
    bool is_interface_outbound_in_use(const std::string& interface_name) const;
    void refresh_iproute_and_firewall_runtime();
    void dispatch_event_fd(int fd, uint32_t events);
    void run_event_loop();
    // Exception-safe teardown of all runtime subsystems. Runs on every exit
    // path of run(), so firewall rules, routes and the PID file are never
    // left behind when the daemon stops or aborts.
    void shutdown_runtime();

    // lifecycle and runtime apply
    void setup_static_routing();
    void apply_firewall(FirewallApplyMode mode = FirewallApplyMode::Destructive);
    void download_uncached_lists();
    void register_urltest_outbounds();
    void handle_urltest_selection_change(const std::string& urltest_tag,
                                         const std::string& new_child_tag);
    // Conntrack flush after a urltest switch, with a bounded retry when the
    // pass fails (5 s, 15 s, 45 s). A newer switch of the same urltest, a
    // config apply and a runtime stop cancel a pending retry.
    void flush_conntrack_after_urltest_switch(const std::string& urltest_tag);
    void start_urltest_conntrack_flush(const std::string& urltest_tag,
                                       std::uint64_t switch_id,
                                       unsigned attempt);
    void handle_urltest_conntrack_flush_result(const std::string& urltest_tag,
                                               std::uint64_t switch_id,
                                               unsigned attempt,
                                               int result);
    void cancel_urltest_conntrack_flush_retries();
    bool commit_urltest_probe_results(const std::string& urltest_tag,
                                      std::uint64_t probe_generation,
                                      std::map<std::string, URLTestResult> results,
                                      TraceId trace_id);
    void apply_config(Config config, bool refresh_remote_lists = true);
    void apply_prepared_runtime_inputs(PreparedRuntimeInputs prepared);
    PreparedRuntimeInputs prepare_runtime_inputs(const Config& config,
                                                bool refresh_remote_lists = true);
    void apply_config_with_rollback(const Config& next_config, bool& rolled_back);
    void reload_from_disk();
    void start_routing_runtime();
    void stop_routing_runtime();
    void restart_routing_runtime();
    void run_system_resolver_hook_reload();
    void schedule_lists_autoupdate();
    // (Re-)install the background list-warmer task. Cancels any prior task and
    // schedules a fresh repeating warm_once() at the configured interval.
    // No-op when warming is disabled (interval=0) or no lists carry domains.
    void schedule_list_warmer();
    // (Re-)install the background auto-heal worker task. Cancels any prior task
    // and, ONLY when daemon.autoheal_enabled is true AND autoheal_watchlist is
    // non-empty, schedules a fresh repeating tick() at autoheal_interval_seconds.
    // Otherwise the worker is destroyed and no task runs — guaranteeing zero
    // behavior in the default (disabled) configuration.
    void schedule_autoheal_worker();
    // Persist + reapply a config the auto-heal worker promoted, using the same
    // path POST /api/config/save uses: atomic write to config.json followed by
    // apply_config (firewall/dnsmasq reapply). Runs on the event-loop thread.
    void apply_autoheal_promoted_config(Config promoted);
    ListsRefreshExecutionResult execute_remote_list_refresh(
        const std::set<std::string>* target_lists = nullptr);
    // Apply a finished list refresh on the control thread: log the outcome
    // and reload the runtime when a route/DNS-relevant list changed. Returns
    // true when the runtime was reloaded; throws if that reload fails.
    bool apply_list_refresh_result(const Config& config_snapshot,
                                   const RemoteListsRefreshResult& refresh_result,
                                   bool runtime_active);
    void refresh_lists_and_maybe_reload();
    void refresh_lists_and_maybe_reload_async();
    // Background retry of URL-backed lists whose startup download failed
    // (10 s, 30 s, 2 min, then every 5 min). Cancelled by a config apply and
    // by a runtime stop; a result from an older runtime generation is dropped.
    void schedule_startup_list_retry();
    void cancel_startup_list_retry();
    void run_startup_list_retry();
    void commit_startup_list_retry_result(std::uint64_t generation,
                                          std::optional<RemoteListsRefreshResult> refresh_result,
                                          std::string error,
                                          TraceId trace_id);
    void commit_lists_refresh_async_result(Config config_snapshot,
                                           bool runtime_active_snapshot,
                                           std::uint64_t generation,
                                           std::optional<RemoteListsRefreshResult> refresh_result,
                                           std::string error,
                                           TraceId trace_id);

    // PID file management
    void write_pid_file();
    void remove_pid_file();

    // state publication and resolver sync
    void refresh_resolver_config_hash_actual_async();
    void maybe_schedule_resolver_config_hash_actual_refresh();
    void schedule_resolver_config_hash_actual_retry();
    void schedule_keenetic_dns_refresh();
    bool refresh_keenetic_dns_cache(bool force_refresh);
    void reset_resolver_actual_state();
    void commit_resolver_hash_probe_result(const std::string& resolver_addr,
                                           std::uint64_t generation,
                                           std::optional<ResolverConfigHashProbeResult> probe_result,
                                           std::optional<std::int64_t> probe_completed_ts,
                                           TraceId trace_id);

#ifdef WITH_API
    // API integration
    void setup_api();
    void finish_config_operation();
    void begin_config_operation_or_throw(ConfigOperationState state,
                                         const char* reason,
                                         bool require_runtime_running,
                                         bool require_runtime_stopped);
    ConfigApplyResult apply_validated_config_via_control_task(
        Config config,
        std::string saved_config_json);
    void run_runtime_control_operation_or_throw(const std::string& label,
                                                const char* operation_name,
                                                std::function<void()> task);
    ListRefreshOperationResult refresh_lists_via_api(std::optional<std::string> requested_name);
#endif

    // DNS probe integration
    void setup_dns_probe();
    void teardown_dns_probe();
    void handle_dns_probe_query_event(const DnsProbeEvent& event);
    void handle_dns_probe_udp_events(uint32_t events);
    void handle_dns_probe_tcp_listener_events(uint32_t events);
    void handle_dns_probe_tcp_client_events(int client_fd, uint32_t events);
    void handle_dns_probe_tcp_timer_events(uint32_t events);

    // Hash of the current domain-to-ipset mapping (matches dnsmasq txt-record)
    std::string resolver_config_hash_;
    // Hash currently published by the live system resolver TXT record.
    std::string resolver_config_hash_actual_;
    // Resolver TXT timestamp currently published by the live system resolver record.
    std::optional<std::int64_t> resolver_config_hash_actual_ts_;
    // Health of the live system resolver endpoint based on the latest TXT probe.
    api::ResolverLiveStatus resolver_live_status_{api::ResolverLiveStatus::UNKNOWN};
    // When the latest resolver TXT probe completed.
    std::optional<std::int64_t> resolver_last_probe_ts_;
    // Timestamp captured when /api/config/save apply starts (server authoritative).
    std::atomic<std::int64_t> apply_started_ts_{0};

    // Recompute resolver_config_hash_ from current config/cache state
    void update_resolver_config_hash();
    // Schedule (or reschedule) the periodic refresh of resolver_config_hash_actual_.
    void schedule_resolver_config_hash_actual_refresh();
    RuntimeStateSnapshot build_runtime_state_snapshot() const;
    void publish_runtime_state();

    // Lists autoupdate state
    int lists_autoupdate_task_id_{-1};
    // One-shot retry timer for lists that failed to download at startup.
    int startup_list_retry_task_id_{-1};
    unsigned startup_list_retry_attempt_{0};
    // Periodic refresh task for cached Keenetic DNS server values.
    int keenetic_dns_refresh_task_id_{-1};
    // Periodic refresh task for the actual resolver config hash / live status.
    int resolver_config_hash_actual_task_id_{-1};
    // Short-interval retry while resolver hash is converging after apply.
    int resolver_config_hash_actual_retry_task_id_{-1};
    // Runtime refresh requested by SIGUSR1 (netfilter hook) and by interface
    // events. The first trigger after a quiet period refreshes almost at
    // once (outside the handler that saw it); triggers within 1.5 s of a
    // refresh fold into one trailing refresh. Keenetic fires bursts (UPnP
    // rebuilds nat about once a minute, NDM reconfigures links together),
    // and a weak MT7621 cannot afford a refresh per event.
    static constexpr std::chrono::milliseconds kRuntimeRefreshLeadingDelay{1};
    static constexpr std::chrono::milliseconds kRuntimeRefreshMinGap{1500};
    RefreshCoalescer runtime_refresh_coalescer_{kRuntimeRefreshLeadingDelay,
                                                kRuntimeRefreshMinGap};
    int runtime_refresh_task_id_{-1};
    // Reason of the trigger that armed the pending refresh (for the log).
    std::string runtime_refresh_reason_;
    // Retry task for an interface monitor reconnect that failed.
    int interface_monitor_reconnect_task_id_{-1};
    // Interface monitor fd currently registered in epoll.
    std::optional<int> interface_monitor_fd_;
    // Periodic background warm-up of the dnsmasq-populated ipsets — see
    // ListWarmer for the cache-bypass rationale.
    int list_warmer_task_id_{-1};
    // Periodic auto-heal worker that promotes leaking watchlist domains into
    // the auto-heal list. -1 (no task) whenever auto-heal is disabled or the
    // watchlist is empty — see AutohealWorker and schedule_autoheal_worker.
    int autoheal_worker_task_id_{-1};

    // Epoll state
    int epoll_fd_{-1};
    int signal_fd_{-1};
    std::atomic<bool> running_{false};
    std::atomic<std::thread::id> event_loop_thread_id_{};
    std::atomic<bool> event_loop_active_{false};
    std::atomic<bool> accept_posted_control_tasks_{true};

    struct FdEntry {
        int fd;
        FdCallback callback;
    };
    mutable TracedMutex fd_entries_mutex_;
    std::vector<FdEntry> fd_entries_ GUARDED_BY(fd_entries_mutex_);
    // fds unregistered during the current epoll_wait batch. Touched only on
    // the event-loop thread; lets run_event_loop skip a stale event for an
    // fd number that was closed (and possibly recycled) mid-batch.
    std::unordered_set<int> retired_fds_;

    PidFile pid_file_;
    int control_fd_{-1};
    struct ControlTask {
        std::function<void()> callback;
        std::string label;
        TraceId trace_id{0};
    };
    TracedMutex control_tasks_mutex_;
    std::vector<ControlTask> control_tasks_ GUARDED_BY(control_tasks_mutex_);

#ifdef WITH_API
    TracedMutex config_op_mutex_;
    std::condition_variable_any config_op_cv_;
    std::atomic<ConfigOperationState> config_op_state_{static_cast<ConfigOperationState>(0)};
#endif

    // Snapshot stores
    ConfigStore config_store_;
    ListService list_service_;
    RuntimeStateStore runtime_state_store_;

    // Event-loop-owned controller state
    Config config_;
    std::string config_path_;
    DaemonOptions opts_;

    // Subsystems
    std::unique_ptr<Firewall> firewall_;
    std::unique_ptr<InterfaceMonitor> interface_monitor_;
    NetlinkManager netlink_;
    RouteTable route_table_;
    PolicyRuleManager policy_rules_;
    FirewallState firewall_state_;
    URLTester url_tester_;
    OutboundMarkMap outbound_marks_;
    std::unique_ptr<Scheduler> scheduler_;
    std::unique_ptr<UrltestManager> urltest_manager_;
    std::unique_ptr<ListWarmer> list_warmer_;
    std::unique_ptr<AutohealWorker> autoheal_worker_;
    // Invalidates conntrack entries whose dst-IP lives in a kpbr* ipset so the
    // next packet re-evaluates routing instead of riding a stale FASTNAT mark.
    // See ConntrackFlusher for the rationale.
    std::unique_ptr<ConntrackFlusher> conntrack_flusher_;
    // Latest switch per urltest whose conntrack flush is still running or
    // waiting for a retry. switch_id tells a stale result from a current one.
    struct UrltestFlushRetry {
        std::uint64_t switch_id{0};
        int task_id{-1};
    };
    std::map<std::string, UrltestFlushRetry> urltest_flush_retries_;
    std::uint64_t next_urltest_switch_id_{1};
    BlockingExecutor blocking_executor_{2, 64};
    std::atomic<std::uint64_t> runtime_generation_{1};
    std::atomic<bool> remote_list_refresh_inflight_{false};
    std::atomic<bool> resolver_hash_refresh_inflight_{false};

#ifdef WITH_API
    std::unique_ptr<ApiServer> api_server_;
    std::unique_ptr<ApiContext> api_ctx_;
    std::unique_ptr<SseBroadcaster> dns_test_broadcaster_;
#endif

    std::unique_ptr<DnsProbeServer> dns_probe_server_;

    HookCommandExecutor hook_command_executor_;
    bool routing_runtime_active_{true};
};

} // namespace keen_pbr3
