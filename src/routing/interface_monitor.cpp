#include "interface_monitor.hpp"

#include "../log/logger.hpp"
#include "../util/format_compat.hpp"

#include <cerrno>
#include <cstring>
#include <ifaddrs.h>
#include <net/if.h>
#include <linux/rtnetlink.h>
#include <sys/socket.h>
#include <unordered_map>

#include <netlink/attr.h>
#include <netlink/errno.h>
#include <netlink/msg.h>
#include <netlink/netlink.h>
#include <netlink/socket.h>

namespace keen_pbr3 {

namespace {

constexpr int kLinkAttributeMax = IFLA_MAX + 1;

// Subscribing to RTNLGRP_LINK triggers a burst of RTM_NEWLINK messages, and
// NDM reconfigures many interfaces at once on network events. The kernel
// charges only what is actually queued, so a large cap costs nothing while
// the queue is drained.
constexpr int kReceiveBufferBytes = 1024 * 1024;

// One handle_events() call stops after this many overflow reports in a row;
// epoll wakes it again while data is queued. Guards against a spin should
// libnl keep returning NLE_NOMEM (it also uses it for allocation failures).
constexpr int kMaxOverflowsPerDrain = 16;

void set_receive_buffer(struct nl_sock* socket) {
    // SO_RCVBUFFORCE ignores net.core.rmem_max (which caps the plain
    // SO_RCVBUF that nl_socket_set_buffer_size uses); it needs CAP_NET_ADMIN,
    // which the daemon has. The fallback is capped by rmem_max.
    const int fd = nl_socket_get_fd(socket);
    int size = kReceiveBufferBytes;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &size, sizeof(size)) == 0) {
        return;
    }
    const int err = nl_socket_set_buffer_size(socket, kReceiveBufferBytes, 0);
    if (err < 0) {
        throw InterfaceMonitorError(format(
            "Failed to size interface monitor netlink buffer: {}", nl_geterror(err)));
    }
}

} // namespace

struct InterfaceMonitor::Impl {
    explicit Impl(InterfaceStateCallback callback)
        : callback(std::move(callback)) {}

    ~Impl() {
        close_socket();
    }

    static int on_nl_message(struct nl_msg* msg, void* arg) {
        auto* impl = static_cast<Impl*>(arg);
        if (!impl) {
            return NL_OK;
        }

        // An exception must not unwind through libnl's C frames.
        try {
            impl->handle_link_message(msg);
        } catch (const std::exception& e) {
            Logger::instance().error("Interface monitor callback failed: {}", e.what());
        } catch (...) {
            Logger::instance().error("Interface monitor callback failed: unknown error");
        }
        return NL_OK;
    }

    void handle_link_message(struct nl_msg* msg) {
        if (!msg || !callback) {
            return;
        }

        struct nlmsghdr* hdr = nlmsg_hdr(msg);
        if (!hdr) {
            return;
        }

        if (hdr->nlmsg_type != RTM_NEWLINK && hdr->nlmsg_type != RTM_DELLINK) {
            return;
        }

        auto* if_info = static_cast<ifinfomsg*>(nlmsg_data(hdr));
        if (!if_info) {
            return;
        }

        struct nlattr* attrs[kLinkAttributeMax] = {};
        const int parse_err = nlmsg_parse(hdr,
                                          sizeof(*if_info),
                                          attrs,
                                          IFLA_MAX,
                                          nullptr);
        if (parse_err < 0 || attrs[IFLA_IFNAME] == nullptr) {
            return;
        }

        const char* if_name_raw = static_cast<const char*>(nla_data(attrs[IFLA_IFNAME]));
        if (!if_name_raw || *if_name_raw == '\0') {
            return;
        }

        const std::string interface_name(if_name_raw);
        const bool is_up = (hdr->nlmsg_type == RTM_NEWLINK) && ((if_info->ifi_flags & IFF_UP) != 0);

        const auto previous = interface_state.find(interface_name);
        if (previous != interface_state.end() && previous->second == is_up) {
            return;
        }

        interface_state[interface_name] = is_up;
        Event event;
        event.interface_name = interface_name;
        event.is_up = is_up;
        callback(event);
    }

    // Reload the administrative state of every interface, so the next
    // notification is compared against the kernel's view rather than against
    // whatever the monitor saw before a disconnect or an overflow.
    void load_interface_state() {
        interface_state.clear();
        struct ifaddrs* interfaces = nullptr;
        if (getifaddrs(&interfaces) != 0) {
            return;
        }
        for (auto* current = interfaces; current != nullptr; current = current->ifa_next) {
            if (current->ifa_name != nullptr) {
                interface_state[current->ifa_name] = (current->ifa_flags & IFF_UP) != 0;
            }
        }
        freeifaddrs(interfaces);
    }

    InterfaceStateCallback callback;
    struct nl_sock* socket{nullptr};
    std::unordered_map<std::string, bool> interface_state;

    void close_socket() {
        if (!socket) {
            return;
        }
        nl_close(socket);
        nl_socket_free(socket);
        socket = nullptr;
    }

    void setup_socket() {
        close_socket();

        socket = nl_socket_alloc();
        if (!socket) {
            throw InterfaceMonitorError(
                "Failed to allocate netlink socket for interface monitor");
        }

        try {
            int err = nl_connect(socket, NETLINK_ROUTE);
            if (err < 0) {
                throw InterfaceMonitorError(format(
                    "Failed to connect interface monitor netlink socket: {}", nl_geterror(err)));
            }

            set_receive_buffer(socket);

            err = nl_socket_add_memberships(socket, RTNLGRP_LINK, 0);
            if (err < 0) {
                throw InterfaceMonitorError(format(
                    "Failed to subscribe interface monitor to link group: {}", nl_geterror(err)));
            }
        } catch (...) {
            // Never leave a half-built socket behind: fd() must then report
            // "not initialized" instead of handing out a dead descriptor.
            close_socket();
            throw;
        }

        nl_socket_set_nonblocking(socket);
        nl_socket_disable_seq_check(socket);
        nl_socket_modify_cb(socket,
                            NL_CB_VALID,
                            NL_CB_CUSTOM,
                            &InterfaceMonitor::Impl::on_nl_message,
                            this);

        load_interface_state();
    }
};

InterfaceMonitor::InterfaceMonitor(InterfaceStateCallback callback)
    : impl_(std::make_unique<Impl>(std::move(callback))) {
    impl_->setup_socket();
}

InterfaceMonitor::~InterfaceMonitor() = default;

int InterfaceMonitor::fd() const {
    if (!impl_ || !impl_->socket) {
        throw InterfaceMonitorError("Interface monitor socket is not initialized");
    }
    return nl_socket_get_fd(impl_->socket);
}

InterfaceMonitor::ReceiveStatus InterfaceMonitor::classify_receive(int nl_error,
                                                                   int system_errno) noexcept {
    if (nl_error >= 0) {
        return ReceiveStatus::Message;
    }
    if (nl_error == -NLE_NOMEM) {
        return ReceiveStatus::Overflow;
    }
    if (nl_error == -NLE_AGAIN || system_errno == EAGAIN || system_errno == EWOULDBLOCK) {
        return ReceiveStatus::Drained;
    }
    return ReceiveStatus::Failed;
}

void InterfaceMonitor::handle_events() {
    if (!impl_ || !impl_->socket) {
        return;
    }

    int overflows = 0;
    while (true) {
        errno = 0;
        const int err = nl_recvmsgs_default(impl_->socket);
        const auto status = classify_receive(err, errno);
        if (status == ReceiveStatus::Message) {
            continue;
        }
        if (status == ReceiveStatus::Overflow) {
            // The socket stays usable; only the dropped notifications are
            // lost. Keep draining what is still queued, then resync.
            if (++overflows >= kMaxOverflowsPerDrain) {
                break;
            }
            continue;
        }
        if (status == ReceiveStatus::Drained) {
            break;
        }

        throw InterfaceMonitorError(
            format("Failed to receive interface monitor netlink messages: {}", nl_geterror(err)));
    }

    if (overflows > 0) {
        impl_->load_interface_state();
        if (impl_->callback) {
            Event event;
            event.resync = true;
            impl_->callback(event);
        }
    }
}

void InterfaceMonitor::reconnect() {
    if (!impl_) {
        return;
    }

    impl_->setup_socket();
}

} // namespace keen_pbr3
