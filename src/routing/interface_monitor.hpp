#pragma once

#include <functional>
#include <memory>
#include <stdexcept>
#include <string>

namespace keen_pbr3 {

class InterfaceMonitorError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

class InterfaceMonitor {
public:
    struct Event {
        std::string interface_name; // empty for a resync
        bool is_up{false};
        // The kernel dropped notifications (receive queue overflow). The
        // monitor reloaded its link state, but what changed is unknown.
        bool resync{false};
    };
    using InterfaceStateCallback = std::function<void(const Event& event)>;

    // How one nl_recvmsgs() call ended.
    enum class ReceiveStatus {
        Message,  // messages were processed; keep reading
        Overflow, // ENOBUFS: notifications were lost, the socket is still usable
        Drained,  // nothing left to read
        Failed,   // any other error: the socket must be rebuilt
    };

    explicit InterfaceMonitor(InterfaceStateCallback callback);
    ~InterfaceMonitor();

    InterfaceMonitor(const InterfaceMonitor&) = delete;
    InterfaceMonitor& operator=(const InterfaceMonitor&) = delete;
    InterfaceMonitor(InterfaceMonitor&&) = delete;
    InterfaceMonitor& operator=(InterfaceMonitor&&) = delete;

    int fd() const;

    // Drain the socket, invoking the callback per link state change. A
    // receive-queue overflow does not throw: the link state is reloaded and
    // the callback gets one resync event. Throws InterfaceMonitorError on
    // any other receive error.
    void handle_events();

    // Rebuild the netlink subscription after an unrecoverable receive error.
    // The caller must drop the old fd() from epoll first. Link state is
    // reloaded from the kernel; changes during the outage are not replayed.
    void reconnect();

    // Classify an nl_recvmsgs() return code. libnl reports ENOBUFS as
    // NLE_NOMEM.
    static ReceiveStatus classify_receive(int nl_error, int system_errno) noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace keen_pbr3
