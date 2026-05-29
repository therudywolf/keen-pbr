#include "daemon.hpp"

#include <nlohmann/json.hpp>
#include <sys/epoll.h>
#include <unistd.h>

#include <chrono>
#include <cstddef>
#include <map>
#include <optional>
#include <string>

#include "../dns/dns_probe_server.hpp"
#include "../dns/dnsmasq_gen.hpp"
#include "../log/logger.hpp"
#include "../routing/dns_split_marks.hpp"
#include "../routing/dns_split_observer.hpp"
#include "../routing/dns_split_table.hpp"
#include "../routing/nfqueue_listener.hpp"
#include "../routing/tcp_payload.hpp"
#include "scheduler.hpp"
#ifdef WITH_API
#include "../api/sse_broadcaster.hpp"
#endif

namespace keen_pbr3 {

void Daemon::handle_dns_probe_query_event(const DnsProbeEvent& event) {
#ifdef WITH_API
    if (dns_test_broadcaster_) {
        nlohmann::json payload = {
            {"type", "DNS"},
            {"domain", event.domain},
            {"source_ip", event.source_ip},
            {"ecs", event.ecs.has_value() ? nlohmann::json(*event.ecs) : nlohmann::json(nullptr)},
        };
        dns_test_broadcaster_->publish(payload.dump());
    }
#else
    (void)event;
#endif
}

void Daemon::handle_dns_probe_udp_events(uint32_t events) {
    if ((events & EPOLLIN) && dns_probe_server_) {
        dns_probe_server_->handle_udp_readable();
    }
}

void Daemon::handle_dns_probe_tcp_client_events(int client_fd, uint32_t client_events) {
    if (!dns_probe_server_) {
        remove_fd(client_fd);
        close(client_fd);
        return;
    }

    bool keep_alive = false;
    if (client_events & EPOLLIN) {
        keep_alive = dns_probe_server_->handle_tcp_client_readable(client_fd);
    }
    if (client_events & (EPOLLRDHUP | EPOLLHUP | EPOLLERR)) {
        keep_alive = false;
    }

    if (!keep_alive) {
        dns_probe_server_->remove_tcp_client(client_fd);
        remove_fd(client_fd);
        close(client_fd);
    }
}

void Daemon::handle_dns_probe_tcp_listener_events(uint32_t events) {
    if (!(events & EPOLLIN) || !dns_probe_server_) {
        return;
    }

    for (int client_fd : dns_probe_server_->accept_tcp_clients()) {
        add_fd(client_fd, EPOLLIN | EPOLLRDHUP | EPOLLHUP | EPOLLERR,
               [this, client_fd](uint32_t client_events) {
                   handle_dns_probe_tcp_client_events(client_fd, client_events);
               });
    }
}

void Daemon::handle_dns_probe_tcp_timer_events(uint32_t events) {
    if (!(events & EPOLLIN) || !dns_probe_server_) {
        return;
    }
    for (int client_fd : dns_probe_server_->handle_tcp_idle_timeout()) {
        dns_probe_server_->remove_tcp_client(client_fd);
        remove_fd(client_fd);
        close(client_fd);
    }
}

void Daemon::setup_dns_probe() {
    teardown_dns_probe();

    if (!config_.dns || !config_.dns->dns_test_server.has_value()) {
        return;
    }

    const auto& test_cfg = *config_.dns->dns_test_server;
    const std::string* answer_ip = test_cfg.answer_ipv4 ? &*test_cfg.answer_ipv4 : nullptr;
    auto settings = parse_dns_probe_server_settings(test_cfg.listen, answer_ip);

    dns_probe_server_ = std::make_unique<DnsProbeServer>(
        settings,
        [this](const DnsProbeEvent& event) {
            handle_dns_probe_query_event(event);
        });

    add_fd(dns_probe_server_->udp_fd(), EPOLLIN, [this](uint32_t events) {
        handle_dns_probe_udp_events(events);
    });

    add_fd(dns_probe_server_->tcp_fd(), EPOLLIN, [this](uint32_t events) {
        handle_dns_probe_tcp_listener_events(events);
    });

    add_fd(dns_probe_server_->tcp_idle_timer_fd(), EPOLLIN, [this](uint32_t events) {
        handle_dns_probe_tcp_timer_events(events);
    });

    Logger::instance().info("DNS test server listening on {}", settings.listen);
}

void Daemon::teardown_dns_probe() {
    if (!dns_probe_server_) {
        return;
    }

    for (int fd : dns_probe_server_->all_fds()) {
        remove_fd(fd);
    }
    dns_probe_server_.reset();
}

void Daemon::handle_dns_split_nfqueue_events(uint32_t events) {
    if ((events & EPOLLIN) && dns_split_listener_) {
        dns_split_listener_->handle_readable();
    }
}

void Daemon::setup_dns_split() {
    teardown_dns_split();

    // SAFETY: strict default-off. Unless dns_split_enabled is explicitly true we
    // build no table, start no observer, open no queue, and register no fd — the
    // daemon behaves exactly as before.
    const auto daemon_cfg = config_.daemon.value_or(DaemonConfig{});
    if (!daemon_cfg.dns_split_enabled.value_or(false)) {
        return;
    }

    const auto domain_marks = build_dns_split_domain_marks(
        config_,
        outbound_marks_,
        firewall_state_.get_urltest_selections(),
        list_service_.cache_manager());
    if (domain_marks.empty()) {
        // Enabled but no marking rule lists any domain — nothing to correlate.
        // Leave everything off; the iptables NFQUEUE rule (gated identically) is
        // harmless (queue-bypass) even if it is present.
        Logger::instance().info(
            "DNS-split enabled but no domain-bearing marking rules; observer idle");
        return;
    }

    dns_split_table_ = std::make_unique<DnsSplitTable>();

    // Observer: tails the exact log path keen-pbr told dnsmasq to write to.
    dns_split_observer_ = std::make_unique<DnsSplitObserver>(
        DnsmasqGenerator::kDnsSplitLogPath,
        domain_marks,
        dns_split_table_.get());
    dns_split_observer_task_id_ = scheduler_->schedule_repeating(
        std::chrono::seconds{2},
        [this]() {
            if (!dns_split_observer_) return;
            const int n = dns_split_observer_->tick();
            if (n > 0) {
                Logger::instance().trace("dns_split_observer_pass", "upserts={}", n);
            }
        },
        "dns-split-observer");

    // NFQUEUE listener: its decider parses each packet's destination IPv4 and
    // looks it up in the shared correlation table. Fail-open: any miss returns
    // nullopt -> the packet is accepted unchanged and routes by IP as before.
    const uint16_t queue_num = static_cast<uint16_t>(
        daemon_cfg.dns_split_queue_num.value_or(kDefaultDnsSplitQueueNum));
    DnsSplitTable* table = dns_split_table_.get();
    dns_split_listener_ = std::make_unique<NfqueueListener>(
        queue_num,
        [table](const uint8_t* ip_packet, std::size_t len) -> std::optional<uint32_t> {
            const auto dst = extract_ipv4_dst(ip_packet, len);
            if (!dst) {
                return std::nullopt;
            }
            return table->lookup(*dst);
        });

    if (dns_split_listener_->open()) {
        add_fd(dns_split_listener_->fd(), EPOLLIN, [this](uint32_t events) {
            handle_dns_split_nfqueue_events(events);
        });
        Logger::instance().info(
            "DNS-split routing active: queue {}, {} domains, log {}",
            queue_num, domain_marks.size(), DnsmasqGenerator::kDnsSplitLogPath);
    } else {
        // NFQUEUE unavailable (build without libnetfilter_queue, or bind failed).
        // The observer still runs (harmless), but without the listener no SYN is
        // marked. Fail-open: traffic routes by IP. Drop the dead listener.
        dns_split_listener_.reset();
        Logger::instance().warn(
            "DNS-split: NFQUEUE listener unavailable; SYN marking disabled (IP routing remains)");
    }
}

void Daemon::teardown_dns_split() {
    if (dns_split_observer_task_id_ >= 0) {
        scheduler_->cancel(dns_split_observer_task_id_);
        dns_split_observer_task_id_ = -1;
    }
    if (dns_split_listener_) {
        const int fd = dns_split_listener_->fd();
        if (fd >= 0) {
            remove_fd(fd);
        }
        dns_split_listener_->close();
        dns_split_listener_.reset();
    }
    dns_split_observer_.reset();
    dns_split_table_.reset();
}

} // namespace keen_pbr3
