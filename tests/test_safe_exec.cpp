#include "../src/util/safe_exec.hpp"

#include <doctest/doctest.h>

#include <signal.h>
#include <unistd.h>

namespace keen_pbr3 {

namespace {

// Restores the test runner's own stdin after a case replaced it.
struct StdinGuard {
    int saved_stdin{dup(STDIN_FILENO)};

    ~StdinGuard() {
        if (saved_stdin >= 0) {
            dup2(saved_stdin, STDIN_FILENO);
            close(saved_stdin);
        }
    }
};

// Points the runner's stdin at the read end of a pipe that stays open, like
// an interactive terminal that never sends anything.
struct OpenPipeStdin {
    int pipe_fds[2]{-1, -1};

    OpenPipeStdin() {
        REQUIRE(pipe(pipe_fds) == 0);
        REQUIRE(dup2(pipe_fds[0], STDIN_FILENO) >= 0);
        close(pipe_fds[0]);
    }

    ~OpenPipeStdin() {
        close(pipe_fds[1]);
    }
};

struct SignalMaskGuard {
    sigset_t saved_mask{};
    bool valid{false};

    SignalMaskGuard() {
        valid = (sigprocmask(SIG_SETMASK, nullptr, &saved_mask) == 0);
    }

    ~SignalMaskGuard() {
        if (valid) {
            sigprocmask(SIG_SETMASK, &saved_mask, nullptr);
        }
    }
};

} // namespace

TEST_CASE("safe_exec_capture: child process does not inherit blocked signal mask") {
    SignalMaskGuard guard;
    REQUIRE(guard.valid);

    sigset_t blocked_mask;
    sigemptyset(&blocked_mask);
    sigaddset(&blocked_mask, SIGTERM);
    sigaddset(&blocked_mask, SIGINT);
    sigaddset(&blocked_mask, SIGHUP);
    REQUIRE(sigprocmask(SIG_BLOCK, &blocked_mask, nullptr) == 0);

    const auto result = safe_exec_capture(
        {"/bin/sh", "-c", "awk '/^SigBlk:/{print $2}' /proc/self/status"},
        true);

    CHECK(result.exit_code == 0);
    CHECK(result.stdout_output == "0000000000000000\n");
}

TEST_CASE("safe_exec: child process receives devnull stdin") {
    StdinGuard stdin_guard;
    REQUIRE(stdin_guard.saved_stdin >= 0);
    OpenPipeStdin terminal_like_stdin;

    const int exit_code = safe_exec({
        "/bin/sh",
        "-c",
        "[ \"$(readlink /proc/self/fd/0)\" = /dev/null ]",
    });

    CHECK(exit_code == 0);
}

TEST_CASE("safe_exec_capture: child process receives devnull stdin") {
    StdinGuard stdin_guard;
    REQUIRE(stdin_guard.saved_stdin >= 0);
    OpenPipeStdin terminal_like_stdin;

    // `cat` would block forever on the inherited pipe; with /dev/null it
    // sees EOF immediately.
    const auto result = safe_exec_capture({"/bin/sh", "-c", "cat; readlink /proc/self/fd/0"},
                                          true);

    CHECK(result.exit_code == 0);
    CHECK(result.stdout_output == "/dev/null\n");
}

} // namespace keen_pbr3
