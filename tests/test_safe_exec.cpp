#include "../src/util/safe_exec.hpp"

#include <doctest/doctest.h>

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <optional>
#include <signal.h>
#include <stdexcept>
#include <string>
#include <unistd.h>
#include <utility>

namespace keen_pbr3 {

namespace {

class EnvironmentGuard {
public:
    explicit EnvironmentGuard(std::string name)
        : name_(std::move(name)) {
        if (const char* value = std::getenv(name_.c_str())) {
            previous_value_ = value;
        }
    }

    ~EnvironmentGuard() {
        if (previous_value_) {
            setenv(name_.c_str(), previous_value_->c_str(), 1);
        } else {
            unsetenv(name_.c_str());
        }
    }

    void set(const std::string& value) {
        if (setenv(name_.c_str(), value.c_str(), 1) != 0) {
            throw std::runtime_error("setenv failed");
        }
    }

private:
    std::string name_;
    std::optional<std::string> previous_value_;
};

class TempDir {
public:
    TempDir() {
        char path_template[] = "/tmp/forest-pbr-safe-exec-XXXXXX";
        const char* created = mkdtemp(path_template);
        if (created == nullptr) {
            throw std::runtime_error("mkdtemp failed");
        }
        path_ = created;
    }

    ~TempDir() {
        std::error_code error;
        std::filesystem::remove_all(path_, error);
    }

    const std::filesystem::path& path() const { return path_; }

private:
    std::filesystem::path path_;
};

class SafeExecTimeoutGuard {
public:
    SafeExecTimeoutGuard() : previous_(safe_exec_timeouts()) {}
    ~SafeExecTimeoutGuard() {
        set_safe_exec_timeouts(previous_.timeout, previous_.kill_grace);
    }

private:
    SafeExecTimeouts previous_;
};

// Captures log lines and points the command-failure record at a temp file.
class FailureCapture {
public:
    FailureCapture() {
        failure_log_guard_.set(failure_log_path());
        Logger::instance().set_sink([this](const std::string& line) {
            log += line;
            log += '\n';
        });
    }

    ~FailureCapture() {
        Logger::instance().clear_sink();
    }

    std::filesystem::path failure_log_path() const { return temp_dir_.path() / "cmdfail.log"; }

    std::string failure_log() const {
        std::ifstream input(failure_log_path());
        return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
    }

    std::string log;

private:
    TempDir temp_dir_;
    EnvironmentGuard failure_log_guard_{"KEEN_PBR_CMDFAIL_LOG_PATH"};
};

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

TEST_CASE("safe_exec: timeout escalates to SIGKILL") {
    SafeExecTimeoutGuard guard;
    FailureCapture capture;
    set_safe_exec_timeouts(std::chrono::milliseconds{100},
                           std::chrono::milliseconds{50});
    const auto started = std::chrono::steady_clock::now();
    const int exit_code = safe_exec({
        "/bin/sh", "-c", "trap '' TERM; while :; do sleep 1; done",
    }, true);
    const auto elapsed = std::chrono::steady_clock::now() - started;

    CHECK(exit_code == -1);
    CHECK(elapsed < std::chrono::seconds{2});
    CHECK(capture.log.find("safe_exec timed out") != std::string::npos);
}

TEST_CASE("safe_exec: a fast command is not slowed down by the deadline polling") {
    const auto started = std::chrono::steady_clock::now();
    for (int i = 0; i < 10; ++i) {
        REQUIRE(safe_exec({"/bin/true"}) == 0);
    }
    CHECK(std::chrono::steady_clock::now() - started < std::chrono::seconds{2});
    CHECK(safe_exec({"/bin/sh", "-c", "exit 3"}) == 3);
}

TEST_CASE("safe_exec_pipe_stdin: child that does not read is bounded by deadline") {
    SafeExecTimeoutGuard guard;
    FailureCapture capture;
    set_safe_exec_timeouts(std::chrono::milliseconds{100},
                           std::chrono::milliseconds{50});
    const std::string input(2U * 1024U * 1024U, 'x');
    const auto started = std::chrono::steady_clock::now();
    const int exit_code = safe_exec_pipe_stdin(
        {"/bin/sh", "-c", "trap '' TERM; sleep 10"}, input);
    const auto elapsed = std::chrono::steady_clock::now() - started;

    CHECK(exit_code == -1);
    CHECK(elapsed < std::chrono::seconds{2});
    // Only a bounded preview of the 2 MiB input reaches the log.
    CHECK(capture.log.size() < 16U * 1024U);
    CHECK(capture.log.find("reason=timeout") != std::string::npos);
    CHECK(capture.log.find("input_bytes=2097152") != std::string::npos);
    CHECK(capture.log.find("truncated=true") != std::string::npos);
    const std::string failure_log = capture.failure_log();
    CHECK(failure_log.find("reason: timeout") != std::string::npos);
    CHECK(failure_log.find("stdin_bytes: 2097152 (first 1048576 kept)") != std::string::npos);
    CHECK(failure_log.size() < 2U * 1024U * 1024U);
}

TEST_CASE("safe_exec_pipe_stdin: failed command logs arguments, input and output") {
    FailureCapture capture;
    const std::string input = "*mangle\nCOMMIT\n";
    const int exit_code = safe_exec_pipe_stdin(
        {"/bin/sh", "-c", "cat >/dev/null; echo restore-failed >&2; exit 42"}, input);

    CHECK(exit_code == 42);
    CHECK(capture.log.find("cmd=/bin/sh -c cat >/dev/null; echo restore-failed >&2; exit 42")
          != std::string::npos);
    CHECK(capture.log.find(input) != std::string::npos);
    CHECK(capture.log.find("restore-failed") != std::string::npos);

    const std::string failure_log = capture.failure_log();
    CHECK(failure_log.find("command: /bin/sh -c cat >/dev/null; echo restore-failed >&2; exit 42")
          != std::string::npos);
    CHECK(failure_log.find("exit_code: 42") != std::string::npos);
    CHECK(failure_log.find(input) != std::string::npos);
    CHECK(failure_log.find("restore-failed") != std::string::npos);
}

TEST_CASE("safe_exec_pipe_stdin: the newest failure replaces the record atomically") {
    FailureCapture capture;
    CHECK(safe_exec_pipe_stdin({"/bin/sh", "-c", "cat >/dev/null; echo first-failure; exit 7"},
                               "a\n") == 7);
    std::ifstream old_snapshot(capture.failure_log_path());
    REQUIRE(old_snapshot);

    CHECK(safe_exec_pipe_stdin({"/bin/sh", "-c", "cat >/dev/null; echo second-failure; exit 8"},
                               "b\n") == 8);
    const std::string replaced = capture.failure_log();
    CHECK(replaced.find("second-failure") != std::string::npos);
    CHECK(replaced.find("first-failure") == std::string::npos);

    // A reader that opened the old record keeps a consistent copy.
    const std::string old_content{std::istreambuf_iterator<char>(old_snapshot),
                                  std::istreambuf_iterator<char>()};
    CHECK(old_content.find("first-failure") != std::string::npos);
    CHECK(old_content.find("second-failure") == std::string::npos);
}

TEST_CASE("safe_exec_pipe_stdin: successful and quiet commands leave no failure record") {
    FailureCapture capture;
    CHECK(safe_exec_pipe_stdin({"/bin/sh", "-c", "cat >/dev/null; echo ok"}, "x\n") == 0);
    CHECK(safe_exec_pipe_stdin({"/bin/sh", "-c", "cat >/dev/null; exit 2"}, "x\n",
                               ExecFailureReport::Quiet) == 2);
    CHECK_FALSE(std::filesystem::exists(capture.failure_log_path()));
    CHECK(capture.log.find("safe_exec_pipe_failed") == std::string::npos);
}

TEST_CASE("safe_exec_capture: ignored SIGTERM cannot hang capture") {
    SafeExecTimeoutGuard guard;
    FailureCapture capture;
    set_safe_exec_timeouts(std::chrono::milliseconds{100},
                           std::chrono::milliseconds{50});
    const auto started = std::chrono::steady_clock::now();
    const auto result = safe_exec_capture(
        {"/bin/sh", "-c", "trap '' TERM; echo partial; while :; do sleep 1; done"}, true);
    const auto elapsed = std::chrono::steady_clock::now() - started;

    CHECK(result.exit_code == -1);
    CHECK(result.timed_out);
    CHECK(result.stdout_output == "partial\n");
    CHECK(elapsed < std::chrono::seconds{2});
}

TEST_CASE("safe_exec_capture: output limit still kills the child") {
    const auto result = safe_exec_capture({"/bin/sh", "-c", "yes"}, true, 4096);
    CHECK(result.truncated);
    CHECK(result.stdout_output.size() > 4096);
}

} // namespace keen_pbr3
