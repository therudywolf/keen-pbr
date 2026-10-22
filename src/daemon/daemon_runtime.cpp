#include "daemon.hpp"

#include <fstream>
#include <map>
#include <set>
#include <sstream>

#include "../cmd/test_routing.hpp"
#include "../config/config_writer.hpp"
#include "../config/routing_state.hpp"
#include "../firewall/firewall.hpp"
#include "../firewall/firewall_runtime.hpp"
#include "../lists/list_warmer.hpp"
#include "../log/logger.hpp"
#include "../routing/autoheal_worker.hpp"
#include "../routing/conntrack_flush.hpp"
#include "../routing/urltest_manager.hpp"
#include "../routing/urltest_switch.hpp"
#include "../util/ipv6_support.hpp"
#include "../util/time_utils.hpp"
#include "../util/cron.hpp"
#include "scheduler.hpp"
#include "system_resolver_hook.hpp"

namespace keen_pbr3 {

namespace {

std::string format_list_names(const std::vector<std::string>& list_names) {
    if (list_names.empty()) {
        return "(none)";
    }

    std::ostringstream out;
    for (size_t i = 0; i < list_names.size(); ++i) {
        if (i != 0) {
            out << ", ";
        }
        out << list_names[i];
    }
    return out.str();
}

} // namespace

void Daemon::run_system_resolver_hook_reload() {
    auto& log = Logger::instance();

    std::string command;
    int exit_code = 0;
    const bool ok = execute_system_resolver_reload_hook(
        config_,
        hook_command_executor_,
        command,
        exit_code);

    if (command.empty()) {
        return;
    }

    if (!ok) {
        log.warn("System resolver reload hook failed (exit code: {}): {}",
                 exit_code,
                 command);
        return;
    }

    log.info("System resolver reload hook complete: {}", command);
}

void Daemon::stop_routing_runtime() {
    auto& log = Logger::instance();
    if (!routing_runtime_active_) {
        return;
    }

    runtime_generation_.fetch_add(1, std::memory_order_acq_rel);
    cancel_startup_list_retry();
    cancel_pending_runtime_refresh("dropped: routing runtime stopped");
    cancel_urltest_conntrack_flush_retries();

    if (urltest_manager_) {
        urltest_manager_->clear();
    }
    route_table_.clear();
    policy_rules_.clear();
    firewall_->cleanup();
    firewall_set_cache_.invalidate();
    if (keenetic_dns_refresh_task_id_ >= 0) {
        scheduler_->cancel(keenetic_dns_refresh_task_id_);
        keenetic_dns_refresh_task_id_ = -1;
    }

    if (config_.dns.has_value() && config_.dns->system_resolver.has_value()) {
        const auto args = build_system_resolver_hook_args(config_, "deactivate");
        const int exit_code = hook_command_executor_(args);
        if (exit_code != 0) {
            throw DaemonError("System resolver deactivate hook failed with exit code " +
                              std::to_string(exit_code));
        }
    }

    routing_runtime_active_ = false;
    refresh_resolver_config_hash_actual_async();
    publish_runtime_state();
    log.info("Routing runtime stopped.");
}

void Daemon::start_routing_runtime() {
    auto& log = Logger::instance();
    if (routing_runtime_active_) {
        return;
    }

    runtime_generation_.fetch_add(1, std::memory_order_acq_rel);

    setup_static_routing();
    register_urltest_outbounds();
    (void)refresh_keenetic_dns_cache(true);
    apply_firewall(FirewallApplyMode::Destructive);

    if (config_.dns.has_value() && config_.dns->system_resolver.has_value()) {
        auto args = build_system_resolver_hook_args(config_, "activate");
        const int exit_code = hook_command_executor_(args);
        if (exit_code != 0) {
            throw DaemonError("System resolver activate hook failed with exit code " +
                              std::to_string(exit_code));
        }
    }

    routing_runtime_active_ = true;
    apply_started_ts_.store(unix_timestamp_now_seconds(), std::memory_order_release);
    schedule_keenetic_dns_refresh();
    refresh_resolver_config_hash_actual_async();
    publish_runtime_state();
    log.info("Routing runtime started.");
}

void Daemon::restart_routing_runtime() {
    if (!routing_runtime_active_) {
        throw DaemonError("Routing runtime is stopped");
    }

    apply_started_ts_.store(unix_timestamp_now_seconds(), std::memory_order_release);
    stop_routing_runtime();
    start_routing_runtime();
}

void Daemon::setup_static_routing() {
    const Ipv6SupportDecision ipv6_decision = resolve_ipv6_support(config_);
    log_ipv6_support_decision_once(ipv6_decision);
    populate_routing_state(
        config_,
        outbound_marks_,
        route_table_,
        policy_rules_,
        [this](const Outbound& outbound) {
            return is_interface_outbound_reachable(outbound, netlink_);
        },
        &firewall_state_.get_urltest_selections(),
        ipv6_decision.enabled);
}

void Daemon::apply_firewall(FirewallApplyMode mode) {
    firewall_state_.set_rules(apply_runtime_firewall(
        config_,
        outbound_marks_,
        firewall_state_.get_urltest_selections(),
        list_service_.cache_manager(),
        *firewall_,
        mode,
        &firewall_set_cache_));
}

FirewallApplyMode Daemon::runtime_refresh_firewall_mode() const {
    // The netfilter hook fires on every NDM rebuild (UPnP: about once a
    // minute). Reloading every list into `ipset restore` each time is the
    // load a weak MT7621 cannot afford; the sets are untouched by NDM.
    return firewall_->backend() == FirewallBackend::iptables
        ? FirewallApplyMode::RulesOnly
        : FirewallApplyMode::PreserveSets;
}

void Daemon::download_uncached_lists() {
    list_service_.download_uncached(config_, outbound_marks_);
}

void Daemon::handle_urltest_selection_change(const std::string& urltest_tag,
                                             const std::string& new_child_tag) {
    const auto runtime_generation = runtime_generation_.load(std::memory_order_acquire);
    post_control_task([this, urltest_tag, new_child_tag, runtime_generation]() {
        auto& log = Logger::instance();
        if (runtime_generation != runtime_generation_.load(std::memory_order_acquire) ||
            !routing_runtime_active_) {
            log.trace("urltest_selection_skip",
                      "tag={} reason=stale_runtime",
                      urltest_tag);
            return;
        }

        // The manager reports the selection after every probe round; only a
        // child different from the one routing was built for needs work.
        const auto applied_selections = firewall_state_.get_urltest_selections();
        const auto applied_it = applied_selections.find(urltest_tag);
        const bool had_applied_entry = applied_it != applied_selections.end();
        const std::string old_child_tag = had_applied_entry ? applied_it->second : std::string{};
        if (old_child_tag == new_child_tag) {
            return;
        }

        bool old_child_healthy = false;
        if (!old_child_tag.empty() && urltest_manager_) {
            if (const auto state = urltest_manager_->get_state(urltest_tag)) {
                const auto result = state->last_results.find(old_child_tag);
                const auto breaker = state->circuit_breakers.find(old_child_tag);
                const bool breaker_open = breaker != state->circuit_breakers.end() &&
                    breaker->second.state(old_child_tag) == CircuitState::open;
                old_child_healthy = !breaker_open && result != state->last_results.end() &&
                                    result->second.success;
            }
        }
        const auto reason = classify_urltest_switch(!old_child_tag.empty(), old_child_healthy);
        log.info("Urltest '{}' selected outbound: '{}' (previous: '{}', reason: {})",
                 urltest_tag,
                 new_child_tag,
                 old_child_tag.empty() ? "(none)" : old_child_tag,
                 urltest_switch_reason_name(reason));

        firewall_state_.set_urltest_selection(urltest_tag, new_child_tag);
        try {
            route_table_.clear();
            policy_rules_.clear();
            setup_static_routing();
            // Only the marks of the group's rules change: the sets stay.
            apply_firewall(runtime_refresh_firewall_mode());
            publish_runtime_state();
            log.info("Routing and firewall rebuilt after urltest change.");
        } catch (const std::exception& e) {
            // The rebuild is not atomic: it may have removed routes or rules
            // before failing. Restore the state of the applied child; the
            // next probe round reports the new child again and retries.
            if (had_applied_entry) {
                firewall_state_.set_urltest_selection(urltest_tag, old_child_tag);
            } else {
                firewall_state_.clear_urltest_selection(urltest_tag);
            }
            try {
                route_table_.clear();
                policy_rules_.clear();
                setup_static_routing();
                apply_firewall(FirewallApplyMode::PreserveSets);
                publish_runtime_state();
                log.error("Urltest '{}' switch to '{}' failed; restored '{}': {}",
                          urltest_tag,
                          new_child_tag,
                          old_child_tag.empty() ? "(none)" : old_child_tag,
                          e.what());
            } catch (const std::exception& rollback_error) {
                log.error("Urltest '{}' switch to '{}' failed: {}; restoring '{}' failed too: {}",
                          urltest_tag,
                          new_child_tag,
                          e.what(),
                          old_child_tag.empty() ? "(none)" : old_child_tag,
                          rollback_error.what());
            }
            // Routing did not move, so the flows are where they were.
            return;
        }

        // Urltest swap routed an outbound to a different interface; flows
        // that were already pinned to the previous nexthop via FASTNAT
        // would otherwise keep using the old path until they expire. Only
        // that outbound's destinations moved, so scope the flush to its sets
        // — an unscoped flush would drop every other PBR-routed session too.
        flush_conntrack_after_urltest_switch(urltest_tag);
    }, "urltest-selection-change:" + urltest_tag);
}

void Daemon::flush_conntrack_after_urltest_switch(const std::string& urltest_tag) {
    // A newer switch supersedes a retry still pending for the previous one:
    // the new flush covers the same sets.
    auto& retry = urltest_flush_retries_[urltest_tag];
    if (retry.task_id >= 0) {
        scheduler_->cancel(retry.task_id);
        retry.task_id = -1;
    }
    retry.switch_id = next_urltest_switch_id_++;
    start_urltest_conntrack_flush(urltest_tag, retry.switch_id, 0);
}

void Daemon::start_urltest_conntrack_flush(const std::string& urltest_tag,
                                           std::uint64_t switch_id,
                                           unsigned attempt) {
    auto scoped = conntrack_flusher_
        ? kpbr_set_names_for_outbound(config_, urltest_tag)
        : std::vector<std::string>{};
    if (scoped.empty()) {
        urltest_flush_retries_.erase(urltest_tag);
        return;
    }

    const auto generation = runtime_generation_.load(std::memory_order_acquire);
    const int queued = conntrack_flusher_->flush_async(
        std::move(scoped),
        [this, urltest_tag, switch_id, attempt, generation](int result) {
            // Executor thread: hand the result back to the control thread.
            post_control_task(
                [this, urltest_tag, switch_id, attempt, generation, result]() {
                    if (generation != runtime_generation_.load(std::memory_order_acquire)) {
                        return;
                    }
                    handle_urltest_conntrack_flush_result(urltest_tag, switch_id, attempt, result);
                },
                "urltest-conntrack-flush-result:" + urltest_tag);
        });
    if (queued == 0) {
        handle_urltest_conntrack_flush_result(urltest_tag, switch_id, attempt, -1);
    }
}

void Daemon::handle_urltest_conntrack_flush_result(const std::string& urltest_tag,
                                                   std::uint64_t switch_id,
                                                   unsigned attempt,
                                                   int result) {
    auto& log = Logger::instance();
    auto it = urltest_flush_retries_.find(urltest_tag);
    if (it == urltest_flush_retries_.end() || it->second.switch_id != switch_id) {
        return; // a newer switch took over
    }

    if (result >= 0) {
        if (attempt > 0) {
            log.info("Conntrack flush after urltest '{}' switch succeeded on retry {}",
                     urltest_tag,
                     attempt);
        }
        urltest_flush_retries_.erase(it);
        return;
    }

    if (attempt >= kMaxUrltestFlushRetries) {
        log.warn("Conntrack flush after urltest '{}' switch failed {} times; giving up, "
                 "flows on the old path end on their own",
                 urltest_tag,
                 attempt + 1);
        urltest_flush_retries_.erase(it);
        return;
    }

    const auto delay = urltest_flush_retry_delay(attempt);
    log.warn("Conntrack flush after urltest '{}' switch failed; retrying in {}s",
             urltest_tag,
             delay.count());
    it->second.task_id = scheduler_->schedule_oneshot(
        delay,
        [this, urltest_tag, switch_id, attempt]() {
            auto retry = urltest_flush_retries_.find(urltest_tag);
            if (retry == urltest_flush_retries_.end() || retry->second.switch_id != switch_id) {
                return;
            }
            retry->second.task_id = -1;
            start_urltest_conntrack_flush(urltest_tag, switch_id, attempt + 1);
        },
        "urltest-conntrack-flush-retry:" + urltest_tag);
}

void Daemon::cancel_urltest_conntrack_flush_retries() {
    for (auto& [tag, retry] : urltest_flush_retries_) {
        (void)tag;
        if (retry.task_id >= 0) {
            scheduler_->cancel(retry.task_id);
        }
    }
    urltest_flush_retries_.clear();
}

bool Daemon::commit_urltest_probe_results(const std::string& urltest_tag,
                                          std::uint64_t probe_generation,
                                          std::map<std::string, URLTestResult> results,
                                          TraceId trace_id) {
    return post_control_task(
        [this,
         urltest_tag,
         probe_generation,
         results = std::move(results),
         trace_id]() mutable {
            ScopedTraceContext trace_scope(trace_id);
            if (!urltest_manager_) {
                Logger::instance().trace("urltest_commit_skip",
                                         "tag={} generation={} reason=missing_manager",
                                         urltest_tag,
                                         probe_generation);
                return;
            }
            urltest_manager_->commit_probe_results(urltest_tag,
                                                   probe_generation,
                                                   std::move(results));
            publish_runtime_state();
        },
        "urltest-commit:" + urltest_tag);
}

void Daemon::register_urltest_outbounds() {
    if (!urltest_manager_) {
        urltest_manager_ = std::make_unique<UrltestManager>(
            url_tester_,
            outbound_marks_,
            *scheduler_,
            blocking_executor_,
            [this](const std::string& urltest_tag, const std::string& new_child_tag) {
                handle_urltest_selection_change(urltest_tag, new_child_tag);
            },
            [this](const std::string& urltest_tag,
                   std::uint64_t probe_generation,
                   std::map<std::string, URLTestResult> results,
                   TraceId trace_id) mutable {
                Logger::instance().trace("urltest_commit_enqueue",
                                         "tag={} generation={}",
                                         urltest_tag,
                                         probe_generation);
                return commit_urltest_probe_results(urltest_tag,
                                                    probe_generation,
                                                    std::move(results),
                                                    trace_id);
            });
    }

    const auto outbounds = config_.outbounds.value_or(std::vector<Outbound>{});
    for (const auto& ob : outbounds) {
        if (ob.type == OutboundType::URLTEST) {
            urltest_manager_->register_urltest(ob, outbounds);
        }
    }
}

void Daemon::schedule_lists_autoupdate() {
    // Idempotent: never leave an earlier timer behind when rescheduling
    // (the stale-generation commit path and apply_config both land here).
    if (lists_autoupdate_task_id_ >= 0) {
        scheduler_->cancel(lists_autoupdate_task_id_);
        lists_autoupdate_task_id_ = -1;
    }
    if (!config_.lists_autoupdate) return;
    if (!config_.lists_autoupdate->enabled.value_or(false)) return;
    const auto& expr = config_.lists_autoupdate->cron.value_or("");
    auto next = cron_next(expr);
    const auto now = std::chrono::system_clock::now();
    auto delay = std::chrono::ceil<std::chrono::seconds>(next - now);
    if (delay.count() < 1) delay = std::chrono::seconds{1};
    lists_autoupdate_task_id_ = scheduler_->schedule_oneshot(
        delay,
        [this]() {
            refresh_lists_and_maybe_reload_async();
        },
        "lists-autoupdate");
    Logger::instance().info("Lists autoupdate scheduled (next: ~{}s)", delay.count());
}

void Daemon::schedule_list_warmer() {
    // Cancel any previous schedule first — config reloads land here repeatedly.
    if (list_warmer_task_id_ >= 0) {
        scheduler_->cancel(list_warmer_task_id_);
        list_warmer_task_id_ = -1;
    }

    const auto daemon_cfg = config_.daemon.value_or(DaemonConfig{});
    const int64_t interval_seconds = daemon_cfg.list_warmer_interval_seconds.value_or(600);
    if (interval_seconds <= 0) {
        Logger::instance().info("List warmer disabled (interval=0)");
        list_warmer_.reset();
        return;
    }

    // Nothing to warm if no list carries a `domains` field — the warmer would
    // run, find no work, and quietly idle. Skip the bookkeeping entirely.
    bool any_domain_list = false;
    if (config_.lists.has_value()) {
        for (const auto& [name, list_cfg] : *config_.lists) {
            if (list_cfg.domains.has_value() && !list_cfg.domains->empty()) {
                any_domain_list = true;
                break;
            }
        }
    }
    if (!any_domain_list) {
        Logger::instance().info("List warmer: no domain-bearing lists, idle");
        list_warmer_.reset();
        return;
    }

    ListWarmer::Settings settings;
    settings.interval = std::chrono::seconds{interval_seconds};
    settings.upstream_dns_ip =
        daemon_cfg.list_warmer_upstream_dns.value_or(settings.upstream_dns_ip);

    const auto interval_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(settings.interval);

    // Hot-reload safety: the warmer captures a const-ref accessor rather than
    // a snapshot of cfg.lists. Each warm_once() reads the daemon's current
    // config_, so adding/removing lists at runtime is picked up automatically.
    list_warmer_ = std::make_unique<ListWarmer>(
        std::move(settings),
        [this]() -> const Config& { return config_; },
        &blocking_executor_);
    list_warmer_task_id_ = scheduler_->schedule_repeating(
        interval_ms,
        [this]() {
            if (!list_warmer_) return;
            const int queued = list_warmer_->warm_once();
            if (queued > 0) {
                Logger::instance().trace("list_warmer_pass", "queued={}", queued);
            }
        },
        "list-warmer");

    Logger::instance().info("List warmer scheduled (interval={}s, upstream={})",
                            interval_seconds,
                            list_warmer_->settings().upstream_dns_ip);
}

void Daemon::apply_autoheal_promoted_config(Config promoted) {
    // Same order as POST /api/config/save: apply first, persist only once the
    // runtime runs the promoted config. A promotion that fails to apply is
    // rolled back to the previous config and never becomes the one loaded on
    // the next boot; the error propagates to the scheduler, which logs it.
    // apply_config also refreshes the config_store active snapshot, so the API
    // /api/config view reflects the promotion.
    const std::string serialized = serialize_config_pretty(promoted);
    bool rolled_back = false;
    apply_config_with_rollback(promoted, rolled_back);
    write_config_atomically(config_path_, serialized);
}

void Daemon::schedule_autoheal_worker() {
    // Cancel any previous schedule first — config reloads land here repeatedly,
    // exactly like schedule_list_warmer().
    if (autoheal_worker_task_id_ >= 0) {
        scheduler_->cancel(autoheal_worker_task_id_);
        autoheal_worker_task_id_ = -1;
    }

    const auto daemon_cfg = config_.daemon.value_or(DaemonConfig{});

    // SAFETY: the worker is OFF by default. It is only ever scheduled when
    // explicitly enabled AND given a non-empty watchlist. In every other case we
    // destroy the worker and start no task, so the daemon does zero auto-heal
    // work (no thread, no DNS, no config writes) — the guarantee promised in the
    // task spec and AutohealWorker's header.
    const bool enabled = daemon_cfg.autoheal_enabled.value_or(false);
    const std::vector<std::string> watchlist =
        daemon_cfg.autoheal_watchlist.value_or(std::vector<std::string>{});
    if (!enabled || watchlist.empty()) {
        autoheal_worker_.reset();
        Logger::instance().info(
            "Auto-heal worker disabled (enabled={}, watchlist_size={})",
            enabled, watchlist.size());
        return;
    }

    int64_t interval_seconds = daemon_cfg.autoheal_interval_seconds.value_or(900);
    if (interval_seconds <= 0) {
        interval_seconds = 900;  // guard against a non-positive override
    }

    // Hot-reload safety mirrors ListWarmer: capture live accessors, not a
    // config snapshot, so each tick re-reads the daemon's current config_ and
    // re-checks the enable/watchlist gate.
    autoheal_worker_ = std::make_unique<AutohealWorker>(
        [this]() -> const Config& { return config_; },
        [this](const std::string& target) {
            return compute_test_routing(config_, list_service_.cache_manager(), target);
        },
        [this](Config promoted) { apply_autoheal_promoted_config(std::move(promoted)); });

    const auto interval_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::seconds{interval_seconds});
    autoheal_worker_task_id_ = scheduler_->schedule_repeating(
        interval_ms,
        [this]() {
            if (!autoheal_worker_) return;
            const int promoted = autoheal_worker_->tick();
            if (promoted > 0) {
                Logger::instance().trace("autoheal_worker_pass", "promoted={}", promoted);
            }
        },
        "autoheal-worker");

    Logger::instance().info(
        "Auto-heal worker scheduled (interval={}s, watchlist_size={})",
        interval_seconds, watchlist.size());
}

bool Daemon::apply_list_refresh_result(const Config& config_snapshot,
                                       const RemoteListsRefreshResult& refresh_result,
                                       bool runtime_active) {
    auto& log = Logger::instance();
    if (should_reload_runtime_after_list_refresh(runtime_active, refresh_result)) {
        log.info("Lists refresh: relevant list(s) changed ({}), reloading runtime",
                 format_list_names(refresh_result.relevant_changed_lists));
        apply_config(config_snapshot, false);
        return true;
    }

    if (refresh_result.any_relevant_changed()) {
        log.info("Lists refresh: relevant list(s) changed ({}), but runtime is stopped",
                 format_list_names(refresh_result.relevant_changed_lists));
    } else if (refresh_result.any_changed()) {
        log.info("Lists refresh: updated list(s) did not affect runtime config: {}",
                 format_list_names(refresh_result.changed_lists));
    } else if (refresh_result.any_failed()) {
        log.warn("Lists refresh: failed to refresh list(s): {}",
                 format_list_names(refresh_result.failed_lists));
    } else {
        log.info("Lists refresh: no list updates");
    }
    return false;
}

ListsRefreshExecutionResult Daemon::execute_remote_list_refresh(
    const std::set<std::string>* target_lists) {
    ListsRefreshExecutionResult result;
    const auto relevant_lists = collect_relevant_list_names(config_);
    result.refresh_result =
        list_service_.refresh_remote_lists(config_, outbound_marks_, &relevant_lists, target_lists);
    result.reloaded =
        apply_list_refresh_result(config_, result.refresh_result, routing_runtime_active_);
    return result;
}

void Daemon::refresh_lists_and_maybe_reload() {
    auto& log = Logger::instance();
    log.info("Lists autoupdate: checking for updated lists");

    try {
        (void)execute_remote_list_refresh();
    } catch (const std::exception& e) {
        log.error("Lists autoupdate failed: {}", e.what());
    }
    // The timer is a one-shot that has already fired; scheduling is
    // idempotent, so a reload that rescheduled it already is harmless.
    schedule_lists_autoupdate();
}

void Daemon::commit_lists_refresh_async_result(
    Config config_snapshot,
    bool runtime_active_snapshot,
    std::uint64_t generation,
    std::optional<RemoteListsRefreshResult> refresh_result,
    std::string error,
    TraceId trace_id) {
    post_control_task(
        [this,
         config_snapshot = std::move(config_snapshot),
         runtime_active_snapshot,
         generation,
         refresh_result = std::move(refresh_result),
         error = std::move(error),
         trace_id]() mutable {
            ScopedTraceContext trace_scope_inner(trace_id);
            remote_list_refresh_inflight_.store(false, std::memory_order_release);

            if (generation != runtime_generation_.load(std::memory_order_acquire)) {
                Logger::instance().trace("lists_refresh_skip",
                                         "source=autoupdate generation={} reason=stale_runtime",
                                         generation);
                schedule_lists_autoupdate();
                return;
            }

            if (!error.empty() || !refresh_result.has_value()) {
                Logger::instance().error("Lists autoupdate failed: {}", error);
                schedule_lists_autoupdate();
                return;
            }

            try {
                (void)apply_list_refresh_result(config_snapshot,
                                                *refresh_result,
                                                runtime_active_snapshot);
            } catch (const std::exception& e) {
                Logger::instance().error("Lists autoupdate reload failed: {}", e.what());
            }
            // Always (re)schedule: the one-shot timer has fired, and a
            // reload that already rescheduled it is a no-op here.
            schedule_lists_autoupdate();
        },
        "lists-refresh-commit");
}

void Daemon::refresh_lists_and_maybe_reload_async() {
    auto& log = Logger::instance();
    log.info("Lists autoupdate: checking for updated lists");

    bool expected = false;
    if (!remote_list_refresh_inflight_.compare_exchange_strong(expected,
                                                               true,
                                                               std::memory_order_acq_rel)) {
        Logger::instance().trace("lists_refresh_skip",
                                 "source=autoupdate reason=inflight");
        return;
    }

    const Config config_snapshot = config_;
    const OutboundMarkMap marks_snapshot = outbound_marks_;
    const bool runtime_active_snapshot = routing_runtime_active_;
    const auto relevant_lists = collect_relevant_list_names(config_snapshot);
    const auto generation = runtime_generation_.load(std::memory_order_acquire);
    const TraceId trace_id = ensure_trace_id();

    const bool enqueued = blocking_executor_.try_post(
        "lists-autoupdate",
        [this,
         config_snapshot,
         marks_snapshot,
         runtime_active_snapshot,
         relevant_lists,
         generation,
         trace_id]() mutable {
            ScopedTraceContext trace_scope(trace_id);
            std::optional<RemoteListsRefreshResult> refresh_result;
            std::string error;

            Logger::instance().trace("lists_refresh_start",
                                     "source=autoupdate generation={}",
                                     generation);
            try {
                refresh_result = list_service_.refresh_remote_lists(config_snapshot,
                                                                   marks_snapshot,
                                                                   &relevant_lists);
            } catch (const std::exception& e) {
                error = e.what();
            }

            commit_lists_refresh_async_result(config_snapshot,
                                              runtime_active_snapshot,
                                              generation,
                                              std::move(refresh_result),
                                              std::move(error),
                                              trace_id);
        },
        trace_id);

    if (!enqueued) {
        remote_list_refresh_inflight_.store(false, std::memory_order_release);
        Logger::instance().trace("lists_refresh_skip",
                                 "source=autoupdate reason=executor_unavailable");
        schedule_lists_autoupdate();
    }
}

void Daemon::cancel_startup_list_retry() {
    if (startup_list_retry_task_id_ >= 0) {
        scheduler_->cancel(startup_list_retry_task_id_);
        startup_list_retry_task_id_ = -1;
    }
}

void Daemon::schedule_startup_list_retry() {
    cancel_startup_list_retry();
    const auto delay = startup_list_retry_delay(startup_list_retry_attempt_);
    startup_list_retry_task_id_ = scheduler_->schedule_oneshot(
        delay,
        [this]() {
            startup_list_retry_task_id_ = -1;
            run_startup_list_retry();
        },
        "startup-list-retry");
    Logger::instance().info("Startup lists: retrying failed download(s) in {}s (attempt {})",
                            delay.count(),
                            startup_list_retry_attempt_ + 1);
}

void Daemon::run_startup_list_retry() {
    if (!routing_runtime_active_) {
        return;
    }

    bool expected = false;
    if (!remote_list_refresh_inflight_.compare_exchange_strong(expected,
                                                               true,
                                                               std::memory_order_acq_rel)) {
        Logger::instance().trace("lists_refresh_skip",
                                 "source=startup-retry reason=inflight");
        schedule_startup_list_retry();
        return;
    }

    const Config config_snapshot = config_;
    const OutboundMarkMap marks_snapshot = outbound_marks_;
    const auto relevant_lists = collect_relevant_list_names(config_snapshot);
    const auto generation = runtime_generation_.load(std::memory_order_acquire);
    const TraceId trace_id = ensure_trace_id();

    const bool enqueued = blocking_executor_.try_post(
        "startup-list-retry",
        [this, config_snapshot, marks_snapshot, relevant_lists, generation, trace_id]() mutable {
            ScopedTraceContext trace_scope(trace_id);
            std::optional<RemoteListsRefreshResult> refresh_result;
            std::string error;
            try {
                // Cached lists are skipped, so only the failed ones are retried.
                refresh_result = list_service_.download_uncached(
                    config_snapshot, marks_snapshot, &relevant_lists);
            } catch (const std::exception& e) {
                error = e.what();
            } catch (...) {
                error = "unknown list download error";
            }
            commit_startup_list_retry_result(
                generation, std::move(refresh_result), std::move(error), trace_id);
        },
        trace_id);

    if (!enqueued) {
        remote_list_refresh_inflight_.store(false, std::memory_order_release);
        Logger::instance().trace("lists_refresh_skip",
                                 "source=startup-retry reason=executor_unavailable");
        schedule_startup_list_retry();
    }
}

void Daemon::commit_startup_list_retry_result(
    std::uint64_t generation,
    std::optional<RemoteListsRefreshResult> refresh_result,
    std::string error,
    TraceId trace_id) {
    post_control_task(
        [this,
         generation,
         refresh_result = std::move(refresh_result),
         error = std::move(error),
         trace_id]() mutable {
            ScopedTraceContext trace_scope_inner(trace_id);
            remote_list_refresh_inflight_.store(false, std::memory_order_release);

            // A config apply or a runtime stop superseded this retry chain.
            if (generation != runtime_generation_.load(std::memory_order_acquire)) {
                Logger::instance().trace("lists_refresh_skip",
                                         "source=startup-retry generation={} reason=stale_runtime",
                                         generation);
                return;
            }

            bool failures_remain = true;
            if (!error.empty() || !refresh_result.has_value()) {
                Logger::instance().error("Startup lists retry failed: {}", error);
            } else {
                failures_remain = refresh_result->any_failed();
                try {
                    (void)apply_list_refresh_result(config_, *refresh_result,
                                                    routing_runtime_active_);
                } catch (const std::exception& e) {
                    Logger::instance().error("Startup lists retry reload failed: {}", e.what());
                }
            }

            // The retry timer is a one-shot that has already fired: schedule
            // the next attempt here while failures remain.
            if (failures_remain) {
                ++startup_list_retry_attempt_;
                schedule_startup_list_retry();
            } else {
                startup_list_retry_attempt_ = 0;
                Logger::instance().info("Startup lists: all remote lists are now available.");
            }
        },
        "startup-list-retry-commit");
}

PreparedRuntimeInputs Daemon::prepare_runtime_inputs(const Config& config,
                                                     bool refresh_remote_lists) {
    TraceSpan span("prepare-runtime-inputs");
    validate_config(config);

    PreparedRuntimeInputs prepared;
    prepared.config = config;
    prepared.outbound_marks = allocate_outbound_marks(
        config.fwmark.value_or(FwmarkConfig{}),
        config.outbounds.value_or(std::vector<Outbound>{}));

    if (refresh_remote_lists) {
        (void)list_service_.refresh_remote_lists(prepared.config, prepared.outbound_marks);
        prepared.remote_lists_refreshed = true;
    }

    return prepared;
}

void Daemon::apply_prepared_runtime_inputs(PreparedRuntimeInputs prepared) {
    if (event_loop_active_.load(std::memory_order_acquire) && !is_event_loop_thread()) {
        throw DaemonError("apply_prepared_runtime_inputs must run on the control/event-loop thread");
    }

    runtime_generation_.fetch_add(1, std::memory_order_acq_rel);

    if (lists_autoupdate_task_id_ >= 0) {
        scheduler_->cancel(lists_autoupdate_task_id_);
        lists_autoupdate_task_id_ = -1;
    }
    cancel_startup_list_retry();
    // The apply below rebuilds routes and rules from scratch.
    cancel_pending_runtime_refresh("covered by the config apply");
    cancel_urltest_conntrack_flush_retries();
    if (keenetic_dns_refresh_task_id_ >= 0) {
        scheduler_->cancel(keenetic_dns_refresh_task_id_);
        keenetic_dns_refresh_task_id_ = -1;
    }
    if (resolver_config_hash_actual_task_id_ >= 0) {
        scheduler_->cancel(resolver_config_hash_actual_task_id_);
        resolver_config_hash_actual_task_id_ = -1;
    }
    if (resolver_config_hash_actual_retry_task_id_ >= 0) {
        scheduler_->cancel(resolver_config_hash_actual_retry_task_id_);
        resolver_config_hash_actual_retry_task_id_ = -1;
    }
    if (list_warmer_task_id_ >= 0) {
        scheduler_->cancel(list_warmer_task_id_);
        list_warmer_task_id_ = -1;
    }
    if (autoheal_worker_task_id_ >= 0) {
        scheduler_->cancel(autoheal_worker_task_id_);
        autoheal_worker_task_id_ = -1;
    }

    // Keep the outgoing config so the post-apply conntrack flush can be aimed
    // at only the sets whose routing actually changed (see the flush below).
    Config previous_config = config_;

    outbound_marks_ = std::move(prepared.outbound_marks);
    config_ = std::move(prepared.config);
    firewall_state_.set_outbound_marks(outbound_marks_);
    firewall_state_.set_fwmark_mask(fwmark_mask_value(config_.fwmark.value_or(FwmarkConfig{})));

    teardown_dns_probe();

    if (urltest_manager_) {
        urltest_manager_->clear();
    }
    route_table_.clear();
    policy_rules_.clear();
    setup_static_routing();
    register_urltest_outbounds();
    (void)refresh_keenetic_dns_cache(true);
    apply_firewall(FirewallApplyMode::Destructive);
    schedule_keenetic_dns_refresh();
    schedule_lists_autoupdate();
    schedule_list_warmer();
    schedule_autoheal_worker();
    update_resolver_config_hash();
    setup_dns_probe();
    run_system_resolver_hook_reload();
    refresh_resolver_config_hash_actual_async();
    schedule_resolver_config_hash_actual_refresh();

    config_store_.replace_active(config_, outbound_marks_);
    publish_runtime_state();

    // Config (and therefore ipset membership) may have changed in a way that
    // alters routing. Existing conntrack entries cached by the kernel's
    // FASTNAT path still carry their old fwmark and would skip mangle for the
    // remainder of their natural lifetime, so those flows need a flush to be
    // re-evaluated on their next packet.
    //
    // Scope it to the lists whose contents or routing actually changed. A
    // flush is a forced disconnect: flushing every kpbr* set on any config
    // save tears every long-lived PBR-routed session on the network — IoT
    // MQTT keepalives, SSH, streaming — for an edit that may have touched one
    // unrelated list. When nothing routing-relevant changed, skip entirely.
    if (conntrack_flusher_) {
        auto changed = changed_kpbr_set_names(previous_config, config_);
        if (!changed.empty()) {
            conntrack_flusher_->flush_async(std::move(changed));
        }
    }
}

void Daemon::apply_config(Config config, bool refresh_remote_lists) {
    if (event_loop_active_.load(std::memory_order_acquire) && !is_event_loop_thread()) {
        throw DaemonError("apply_config must run on the control/event-loop thread");
    }

    apply_prepared_runtime_inputs(prepare_runtime_inputs(config, refresh_remote_lists));
    // Helper processes started from now on use the applied config's deadlines
    // (SIGHUP reloads and auto-heal promotions come through here).
    apply_exec_timeouts(config_);
}

void Daemon::apply_config_with_rollback(const Config& next_config, bool& rolled_back) {
    Config previous_config = config_;

    try {
        apply_config(next_config);
        rolled_back = false;
    } catch (...) {
        try {
            apply_config(previous_config);
            rolled_back = true;
        } catch (const std::exception& rollback_error) {
            Logger::instance().error("Rollback to previous config failed: {}", rollback_error.what());
            rolled_back = false;
        } catch (...) {
            Logger::instance().error("Rollback to previous config failed: unknown error");
            rolled_back = false;
        }
        throw;
    }
}

void Daemon::reload_from_disk() {
    std::ifstream ifs(config_path_);
    if (!ifs.is_open()) {
        throw DaemonError("Cannot open config file: " + config_path_);
    }

    std::ostringstream ss;
    ss << ifs.rdbuf();
    Config next_config = parse_config(ss.str());
    validate_config(next_config);
    apply_config(std::move(next_config));
}

} // namespace keen_pbr3
