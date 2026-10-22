#include <doctest/doctest.h>

#include "../src/routing/interface_monitor.hpp"

#include <cerrno>
#include <memory>

#include <netlink/errno.h>

using namespace keen_pbr3;

namespace {

using Status = InterfaceMonitor::ReceiveStatus;

} // namespace

TEST_CASE("InterfaceMonitor::classify_receive: ENOBUFS is an overflow, not a failure") {
    // libnl maps ENOBUFS (receive queue overflow) to NLE_NOMEM. The socket
    // stays usable, so it must not trigger a reconnect.
    CHECK(InterfaceMonitor::classify_receive(-NLE_NOMEM, ENOBUFS) == Status::Overflow);
    CHECK(InterfaceMonitor::classify_receive(-NLE_NOMEM, 0) == Status::Overflow);
}

TEST_CASE("InterfaceMonitor::classify_receive: drained, processed and failed reads") {
    CHECK(InterfaceMonitor::classify_receive(0, 0) == Status::Message);
    CHECK(InterfaceMonitor::classify_receive(3, 0) == Status::Message);
    CHECK(InterfaceMonitor::classify_receive(-NLE_AGAIN, EAGAIN) == Status::Drained);
    CHECK(InterfaceMonitor::classify_receive(-NLE_AGAIN, 0) == Status::Drained);
    CHECK(InterfaceMonitor::classify_receive(-NLE_FAILURE, EWOULDBLOCK) == Status::Drained);
    CHECK(InterfaceMonitor::classify_receive(-NLE_FAILURE, 0) == Status::Failed);
    CHECK(InterfaceMonitor::classify_receive(-NLE_BAD_SOCK, EBADF) == Status::Failed);
}

TEST_CASE("InterfaceMonitor reconnect rebuilds a usable netlink socket") {
    std::unique_ptr<InterfaceMonitor> monitor;
    try {
        monitor = std::make_unique<InterfaceMonitor>([](const InterfaceMonitor::Event&) {});
    } catch (const InterfaceMonitorError&) {
        // No rtnetlink in this sandbox: nothing to exercise.
        return;
    }

    CHECK(monitor->fd() >= 0);
    CHECK_NOTHROW(monitor->handle_events());

    CHECK_NOTHROW(monitor->reconnect());
    CHECK(monitor->fd() >= 0);
    CHECK_NOTHROW(monitor->handle_events());
}
