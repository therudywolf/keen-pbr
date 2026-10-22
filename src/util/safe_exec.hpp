#pragma once

#include "../log/logger.hpp"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <fcntl.h>
#include <mutex>
#include <poll.h>
#include <signal.h>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

namespace keen_pbr3 {

struct ExecCaptureResult {
    std::string stdout_output;
    int exit_code{-1};
    bool truncated{false};
    bool timed_out{false};
};

// Every child started through safe_exec* runs in its own process group and
// is bounded by a deadline: when it expires the group gets SIGTERM and, after
// the grace period, SIGKILL. A hung helper (the dnsmasq hook waiting on RCI,
// a stuck ipset/iptables-restore) can then no longer block the event loop
// forever. The defaults are generous because restores and dnsmasq restarts
// are slow on the MIPS routers this daemon targets; daemon.exec_timeout_seconds
// and daemon.exec_kill_grace_seconds override them.
inline constexpr std::int64_t kDefaultExecTimeoutSeconds = 90;
inline constexpr std::int64_t kDefaultExecKillGraceSeconds = 2;

struct SafeExecTimeouts {
    std::chrono::milliseconds timeout{std::chrono::seconds{kDefaultExecTimeoutSeconds}};
    std::chrono::milliseconds kill_grace{std::chrono::seconds{kDefaultExecKillGraceSeconds}};
};

inline std::atomic<std::int64_t>& safe_exec_timeout_ms_storage() {
    static std::atomic<std::int64_t> value{kDefaultExecTimeoutSeconds * 1000};
    return value;
}

inline std::atomic<std::int64_t>& safe_exec_kill_grace_ms_storage() {
    static std::atomic<std::int64_t> value{kDefaultExecKillGraceSeconds * 1000};
    return value;
}

inline void set_safe_exec_timeouts(std::chrono::milliseconds timeout,
                                   std::chrono::milliseconds kill_grace) {
    safe_exec_timeout_ms_storage().store(std::max<std::int64_t>(1, timeout.count()),
                                         std::memory_order_release);
    safe_exec_kill_grace_ms_storage().store(std::max<std::int64_t>(0, kill_grace.count()),
                                            std::memory_order_release);
}

inline SafeExecTimeouts safe_exec_timeouts() {
    return {
        std::chrono::milliseconds{safe_exec_timeout_ms_storage().load(std::memory_order_acquire)},
        std::chrono::milliseconds{safe_exec_kill_grace_ms_storage().load(std::memory_order_acquire)},
    };
}

struct ChildWaitResult {
    int status{0};
    bool reaped{false};
    bool timed_out{false};
};

inline void prepare_child_process_group() {
    (void)setpgid(0, 0);
}

inline void prepare_parent_process_group(pid_t pid) {
    // Also done here so the group exists even if the deadline fires before
    // the child ran its own setpgid(); an EACCES after exec() is harmless.
    (void)setpgid(pid, pid);
}

inline void signal_child_process_group(pid_t pid, int signal_number) {
    if (kill(-pid, signal_number) != 0 && errno == ESRCH) {
        (void)kill(pid, signal_number);
    }
}

// Waits for `pid` until `deadline`; on expiry sends SIGTERM to its process
// group, then SIGKILL after `kill_grace`, and reaps it.
inline ChildWaitResult wait_for_child_until(
    pid_t pid,
    std::chrono::steady_clock::time_point deadline,
    std::chrono::milliseconds kill_grace) {
    ChildWaitResult result;
    auto wait_until = [&](std::chrono::steady_clock::time_point until) {
        // Poll with a short, growing interval: most helpers exit within a
        // few milliseconds and should not pay a fixed 20 ms latency each.
        std::int64_t delay_ms = 1;
        while (true) {
            const pid_t waited = waitpid(pid, &result.status, WNOHANG);
            if (waited == pid) {
                result.reaped = true;
                return true;
            }
            if (waited < 0 && errno != EINTR) return true;
            const auto now = std::chrono::steady_clock::now();
            if (now >= until) return false;
            const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(until - now);
            const int delay = static_cast<int>(std::max<std::int64_t>(1,
                std::min<std::int64_t>(delay_ms, remaining.count())));
            (void)poll(nullptr, 0, delay);
            delay_ms = std::min<std::int64_t>(20, delay_ms * 2);
        }
    };

    if (wait_until(deadline)) return result;
    result.timed_out = true;
    signal_child_process_group(pid, SIGTERM);
    if (wait_until(std::chrono::steady_clock::now() + kill_grace)) {
        // The direct child may exit while descendants keep running.
        signal_child_process_group(pid, SIGKILL);
        return result;
    }
    signal_child_process_group(pid, SIGKILL);
    while (waitpid(pid, &result.status, 0) < 0) {
        if (errno != EINTR) return result;
    }
    result.reaped = true;
    return result;
}

inline int child_exit_code(const ChildWaitResult& wait_result) {
    if (!wait_result.reaped || wait_result.timed_out || !WIFEXITED(wait_result.status)) return -1;
    return WEXITSTATUS(wait_result.status);
}

inline const char* child_failure_reason(const ChildWaitResult& wait_result) {
    return wait_result.timed_out ? "timeout" : "abnormal_exit";
}

inline void reset_child_signal_mask() {
    sigset_t empty_mask;
    sigemptyset(&empty_mask);
    sigprocmask(SIG_SETMASK, &empty_mask, nullptr);
}

// Children never read the daemon's stdin. When the CLI or the init script is
// started from an SSH session, an inherited terminal stdin could otherwise
// make a probe block waiting for input.
inline bool redirect_child_stdin_to_devnull() {
    const int devnull = open("/dev/null", O_RDONLY);
    if (devnull < 0) {
        return false;
    }
    if (dup2(devnull, STDIN_FILENO) < 0) {
        close(devnull);
        return false;
    }
    if (devnull != STDIN_FILENO) {
        close(devnull);
    }
    return true;
}

inline std::string safe_exec_command_string(const std::vector<std::string>& args) {
    std::ostringstream out;
    for (size_t i = 0; i < args.size(); ++i) {
        if (i != 0) {
            out << ' ';
        }
        out << args[i];
    }
    return out.str();
}

inline std::int64_t elapsed_ms_since(std::chrono::steady_clock::time_point started_at) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - started_at).count();
}

// --- Failed command diagnostics -------------------------------------------
//
// The last failed piped command (ipset/iptables-restore, nft -f) is kept in a
// small file so the reason of a failed apply survives the daemon's stdout and
// stderr going to /dev/null under the init script. The file is replaced
// atomically; KEEN_PBR_CMDFAIL_LOG_PATH overrides the location.

inline const char* command_failure_log_path() {
    if (const char* override_path = std::getenv("KEEN_PBR_CMDFAIL_LOG_PATH")) {
        if (*override_path != '\0') return override_path;
    }
    return "/tmp/forest-pbr/cmdfail.log";
}

inline bool write_all_to_fd(int fd, const char* data, std::size_t size) {
    while (size > 0) {
        const ssize_t written = ::write(fd, data, size);
        if (written < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        data += written;
        size -= static_cast<std::size_t>(written);
    }
    return true;
}

inline void record_command_failure(const std::string& command,
                                   int exit_code,
                                   const std::string& input,
                                   const std::string& response,
                                   const std::string& reason = {}) {
    // /tmp is RAM on the router: keep the record bounded.
    constexpr std::size_t kMaxRecordedInputBytes = std::size_t{1024} * 1024U;
    constexpr std::size_t kMaxRecordedResponseBytes = std::size_t{64} * 1024U;
    static std::mutex mutex;
    const std::lock_guard<std::mutex> lock(mutex);

    const std::string final_path = command_failure_log_path();
    const auto slash = final_path.rfind('/');
    if (slash != std::string::npos && slash > 0) {
        (void)::mkdir(final_path.substr(0, slash).c_str(), 0755);
    }
    const std::string temporary_path = final_path + ".tmp." + std::to_string(getpid());
    const int fd = ::open(temporary_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) return;

    const auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    std::tm timestamp{};
    gmtime_r(&now, &timestamp);
    char timestamp_buffer[32];
    std::strftime(timestamp_buffer, sizeof(timestamp_buffer), "%Y-%m-%dT%H:%M:%SZ", &timestamp);

    const auto bounded = [](const std::string& value, std::size_t limit) {
        return value.size() > limit ? value.substr(0, limit) : value;
    };
    const std::string recorded_input = bounded(input, kMaxRecordedInputBytes);
    const std::string recorded_response = bounded(response, kMaxRecordedResponseBytes);

    std::ostringstream out;
    out << "=== " << timestamp_buffer << " ===\n"
        << "command: " << command << '\n'
        << "exit_code: " << exit_code << '\n';
    if (!reason.empty()) out << "reason: " << reason << '\n';
    out << "stdin_bytes: " << input.size();
    if (recorded_input.size() < input.size()) out << " (first " << recorded_input.size() << " kept)";
    out << "\n--- stdin ---\n" << recorded_input
        << (recorded_input.empty() || recorded_input.back() == '\n' ? "" : "\n")
        << "response_bytes: " << response.size();
    if (recorded_response.size() < response.size()) {
        out << " (first " << recorded_response.size() << " kept)";
    }
    out << "\n--- response ---\n" << recorded_response
        << (recorded_response.empty() || recorded_response.back() == '\n' ? "" : "\n")
        << "=== end ===\n";
    const std::string record = out.str();

    const bool written = write_all_to_fd(fd, record.data(), record.size());
    const bool closed = ::close(fd) == 0;
    if (!written || !closed || std::rename(temporary_path.c_str(), final_path.c_str()) != 0) {
        (void)::unlink(temporary_path.c_str());
    }
}

inline std::string read_temporary_file(FILE* file) {
    if (file == nullptr) return {};
    std::string content;
    if (std::fseek(file, 0, SEEK_SET) != 0) return {};
    char buffer[4096];
    while (const size_t count = std::fread(buffer, 1, sizeof(buffer), file)) {
        content.append(buffer, count);
    }
    return content;
}

// Error-log a failed piped command: its output and at most 4 KiB of the
// input (an ipset restore of all lists can be megabytes).
inline void log_failed_pipe_input(const std::string& command,
                                  const std::string& input,
                                  const std::string& response) {
    if (!response.empty()) {
        constexpr std::size_t max_response_bytes = 2048;
        const bool response_truncated = response.size() > max_response_bytes;
        Logger::instance().error(
            "safe_exec_pipe_output cmd={} output_bytes={} truncated={}:\n{}",
            command,
            response.size(),
            response_truncated ? "true" : "false",
            response.substr(0, max_response_bytes));
    }
    constexpr std::size_t max_preview_bytes = 4096;
    const bool truncated = input.size() > max_preview_bytes;
    const std::string preview = input.substr(0, std::min(input.size(), max_preview_bytes));
    Logger::instance().error(
        "safe_exec_pipe_input cmd={} input_bytes={} preview_bytes={} truncated={}:\n{}",
        command,
        input.size(),
        preview.size(),
        truncated ? "true" : "false",
        preview);
}

// Whether a failed safe_exec_pipe_stdin() is reported (error log and the
// command-failure record). Capability probes that may legitimately fail use
// Quiet so they never mask the last real failure.
enum class ExecFailureReport {
    Log,
    Quiet,
};

// Execute a command with arguments directly via fork()+execvp(), bypassing
// the shell entirely. This prevents shell injection attacks.
// Returns the process exit code (0-255), or -1 on fork/exec failure or when
// the deadline expired.
inline int safe_exec(const std::vector<std::string>& args, bool suppress_output = false) {
    if (args.empty()) return -1;
    const std::string command = safe_exec_command_string(args);
    const auto started_at = std::chrono::steady_clock::now();
    Logger::instance().debug("safe_exec_start cmd={} suppress_output={}",
                             command,
                             suppress_output ? "true" : "false");

    std::vector<const char*> argv;
    argv.reserve(args.size() + 1);
    for (const auto& arg : args) {
        argv.push_back(arg.c_str());
    }
    argv.push_back(nullptr);

    const pid_t pid = fork();
    if (pid == -1) {
        Logger::instance().verbose("safe_exec_error cmd={} duration_ms={} reason=fork_failed errno={}",
                                 command,
                                 elapsed_ms_since(started_at),
                                 errno);
        return -1;
    }

    if (pid == 0) {
        // Child process
        prepare_child_process_group();
        reset_child_signal_mask();
        if (!redirect_child_stdin_to_devnull()) {
            _exit(127);
        }
        if (suppress_output) {
            const int devnull = open("/dev/null", O_WRONLY);
            if (devnull >= 0) {
                dup2(devnull, STDOUT_FILENO);
                dup2(devnull, STDERR_FILENO);
                close(devnull);
            }
        }
        execvp(argv[0], const_cast<char* const*>(argv.data()));
        _exit(127); // execvp failed
    }

    prepare_parent_process_group(pid);
    const auto timeouts = safe_exec_timeouts();
    const auto wait_result = wait_for_child_until(pid, started_at + timeouts.timeout,
                                                  timeouts.kill_grace);
    const auto duration_ms = elapsed_ms_since(started_at);
    const int exit_code = child_exit_code(wait_result);
    if (exit_code >= 0) {
        Logger::instance().trace("safe_exec_end",
                                 "cmd={} exit_code={} duration_ms={}",
                                 command,
                                 exit_code,
                                 duration_ms);
        return exit_code;
    }
    if (wait_result.timed_out) {
        Logger::instance().warn("safe_exec timed out after {} ms and was killed: cmd={}",
                                duration_ms,
                                command);
    } else {
        Logger::instance().verbose("safe_exec_error cmd={} duration_ms={} reason=abnormal_exit",
                                   command,
                                   duration_ms);
    }
    return -1;
}

// Execute a command with arguments, piping input data to its stdin.
// The child's stdout and stderr are captured; when the command fails (or
// times out) they are error-logged together with a preview of the input and
// stored as the last command failure, unless `report` is Quiet.
// Returns the process exit code (0-255), or -1 on fork/exec/pipe failure or
// when the deadline expired.
inline int safe_exec_pipe_stdin(const std::vector<std::string>& args,
                                const std::string& input,
                                ExecFailureReport report = ExecFailureReport::Log) {
    if (args.empty()) return -1;
    const std::string command = safe_exec_command_string(args);
    const auto started_at = std::chrono::steady_clock::now();
    Logger::instance().trace("safe_exec_pipe_start",
                             "cmd={} input_bytes={}",
                             command,
                             input.size());

    std::vector<const char*> argv;
    argv.reserve(args.size() + 1);
    for (const auto& arg : args) {
        argv.push_back(arg.c_str());
    }
    argv.push_back(nullptr);

    int pipefd[2];
    if (pipe2(pipefd, O_CLOEXEC) == -1) {
        Logger::instance().trace("safe_exec_pipe_error",
                                 "cmd={} duration_ms={} reason=pipe_failed errno={}",
                                 command,
                                 elapsed_ms_since(started_at),
                                 errno);
        return -1;
    }

    // Output goes to an unlinked temporary file (no pipe that could fill up
    // while we are still writing stdin). Without one (e.g. /tmp is full) the
    // command still runs, just with the daemon's own stdout/stderr.
    FILE* response_file = tmpfile();
    if (response_file != nullptr) {
        (void)fcntl(fileno(response_file), F_SETFD, FD_CLOEXEC);
    }
    const int response_fd = response_file != nullptr ? fileno(response_file) : -1;

    const pid_t pid = fork();
    if (pid == -1) {
        close(pipefd[0]);
        close(pipefd[1]);
        if (response_file != nullptr) std::fclose(response_file);
        Logger::instance().trace("safe_exec_pipe_error",
                                 "cmd={} duration_ms={} reason=fork_failed errno={}",
                                 command,
                                 elapsed_ms_since(started_at),
                                 errno);
        return -1;
    }

    if (pid == 0) {
        // Child: read end becomes stdin. Only async-signal-safe calls here.
        prepare_child_process_group();
        reset_child_signal_mask();
        close(pipefd[1]);
        dup2(pipefd[0], STDIN_FILENO);
        close(pipefd[0]);
        if (response_fd >= 0) {
            dup2(response_fd, STDOUT_FILENO);
            dup2(response_fd, STDERR_FILENO);
        }
        execvp(argv[0], const_cast<char* const*>(argv.data()));
        _exit(127);
    }

    prepare_parent_process_group(pid);
    const auto timeouts = safe_exec_timeouts();
    const auto deadline = started_at + timeouts.timeout;

    // Parent: write input without allowing a child that stops reading to block
    // past the execution deadline.
    close(pipefd[0]);
    const int current_flags = fcntl(pipefd[1], F_GETFL, 0);
    if (current_flags >= 0) (void)fcntl(pipefd[1], F_SETFL, current_flags | O_NONBLOCK);
    const char* data = input.data();
    size_t remaining = input.size();
    while (remaining > 0) {
        if (std::chrono::steady_clock::now() >= deadline) break;
        const ssize_t written = write(pipefd[1], data, remaining);
        if (written < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                const auto now = std::chrono::steady_clock::now();
                if (now >= deadline) break;
                const auto wait_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    deadline - now);
                pollfd descriptor{pipefd[1], POLLOUT, 0};
                (void)poll(&descriptor, 1, static_cast<int>(
                    std::max<std::int64_t>(1, std::min<std::int64_t>(50, wait_ms.count()))));
                continue;
            }
            break;
        }
        data += written;
        remaining -= static_cast<size_t>(written);
    }
    close(pipefd[1]);

    const auto wait_result = wait_for_child_until(pid, deadline, timeouts.kill_grace);
    const std::string response = read_temporary_file(response_file);
    if (response_file != nullptr) std::fclose(response_file);
    const auto duration_ms = elapsed_ms_since(started_at);
    const int exit_code = child_exit_code(wait_result);
    if (exit_code == 0) {
        Logger::instance().trace("safe_exec_pipe_end",
                                 "cmd={} exit_code={} duration_ms={}",
                                 command,
                                 exit_code,
                                 duration_ms);
        return exit_code;
    }

    if (report == ExecFailureReport::Quiet) {
        Logger::instance().verbose("safe_exec_pipe_failed cmd={} exit_code={} duration_ms={} reason={}",
                                   command,
                                   exit_code,
                                   duration_ms,
                                   exit_code < 0 ? child_failure_reason(wait_result) : "exit_code");
        return exit_code;
    }
    if (exit_code > 0) {
        Logger::instance().error("safe_exec_pipe_failed cmd={} exit_code={} duration_ms={}",
                                 command,
                                 exit_code,
                                 duration_ms);
        log_failed_pipe_input(command, input, response);
        record_command_failure(command, exit_code, input, response);
        return exit_code;
    }
    Logger::instance().error("safe_exec_pipe_failed cmd={} duration_ms={} reason={}",
                             command,
                             duration_ms,
                             child_failure_reason(wait_result));
    log_failed_pipe_input(command, input, response);
    record_command_failure(command, -1, input, response, child_failure_reason(wait_result));
    return -1;
}

// Execute a command with arguments and capture its stdout output.
// Returns stdout, exit status, whether capture exceeded max_bytes and whether
// the deadline expired (the child is killed in both cases).
inline ExecCaptureResult safe_exec_capture(const std::vector<std::string>& args,
                                           bool suppress_stderr = false,
                                           size_t max_bytes = 0) {
    ExecCaptureResult result;
    if (args.empty()) return result;
    const std::string command = safe_exec_command_string(args);
    const auto started_at = std::chrono::steady_clock::now();
    Logger::instance().trace("safe_exec_capture_start",
                             "cmd={} suppress_stderr={} max_bytes={}",
                             command,
                             suppress_stderr ? "true" : "false",
                             max_bytes);

    std::vector<const char*> argv;
    argv.reserve(args.size() + 1);
    for (const auto& arg : args) {
        argv.push_back(arg.c_str());
    }
    argv.push_back(nullptr);

    int pipefd[2];
    if (pipe2(pipefd, O_CLOEXEC) == -1) {
        Logger::instance().trace("safe_exec_capture_error",
                                 "cmd={} duration_ms={} reason=pipe_failed errno={}",
                                 command,
                                 elapsed_ms_since(started_at),
                                 errno);
        return result;
    }

    const pid_t pid = fork();
    if (pid == -1) {
        close(pipefd[0]);
        close(pipefd[1]);
        Logger::instance().trace("safe_exec_capture_error",
                                 "cmd={} duration_ms={} reason=fork_failed errno={}",
                                 command,
                                 elapsed_ms_since(started_at),
                                 errno);
        return result;
    }

    if (pid == 0) {
        // Child: write end becomes stdout
        prepare_child_process_group();
        reset_child_signal_mask();
        if (!redirect_child_stdin_to_devnull()) {
            _exit(127);
        }
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        if (suppress_stderr) {
            const int devnull = open("/dev/null", O_WRONLY);
            if (devnull >= 0) {
                dup2(devnull, STDERR_FILENO);
                close(devnull);
            }
        }
        close(pipefd[1]);
        execvp(argv[0], const_cast<char* const*>(argv.data()));
        _exit(127);
    }

    prepare_parent_process_group(pid);
    const auto timeouts = safe_exec_timeouts();
    const auto deadline = started_at + timeouts.timeout;

    // Parent: read captured output without allowing a silent or stalled child
    // to hold the read indefinitely.
    close(pipefd[1]);
    const int current_flags = fcntl(pipefd[0], F_GETFL, 0);
    if (current_flags >= 0) (void)fcntl(pipefd[0], F_SETFL, current_flags | O_NONBLOCK);
    char buf[4096];
    while (true) {
        if (std::chrono::steady_clock::now() >= deadline) {
            result.timed_out = true;
            break;
        }
        const ssize_t n = read(pipefd[0], buf, sizeof(buf));
        if (n > 0) {
            result.stdout_output.append(buf, static_cast<size_t>(n));
            if (max_bytes > 0 && result.stdout_output.size() > max_bytes) {
                result.truncated = true;
                close(pipefd[0]);
                const auto wait_result = wait_for_child_until(
                    pid, std::chrono::steady_clock::now(), timeouts.kill_grace);
                result.exit_code = child_exit_code(wait_result);
                Logger::instance().trace("safe_exec_capture_end",
                                         "cmd={} exit_code={} duration_ms={} bytes={} truncated=true",
                                         command,
                                         result.exit_code,
                                         elapsed_ms_since(started_at),
                                         result.stdout_output.size());
                return result;
            }
        } else if (n == 0) {
            break;
        } else {
            if (errno == EINTR) continue;
            if (errno != EAGAIN && errno != EWOULDBLOCK) break;
            const auto now = std::chrono::steady_clock::now();
            if (now >= deadline) {
                result.timed_out = true;
                break;
            }
            const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                deadline - now);
            pollfd descriptor{pipefd[0], POLLIN | POLLHUP, 0};
            (void)poll(&descriptor, 1, static_cast<int>(
                std::max<std::int64_t>(1, std::min<std::int64_t>(50, remaining.count()))));
        }
    }
    close(pipefd[0]);

    const auto wait_result = wait_for_child_until(
        pid,
        result.timed_out ? std::chrono::steady_clock::now() : deadline,
        timeouts.kill_grace);
    result.timed_out = result.timed_out || wait_result.timed_out;
    result.exit_code = child_exit_code(wait_result);
    if (result.timed_out) {
        Logger::instance().warn("safe_exec_capture timed out after {} ms and was killed: cmd={}",
                                elapsed_ms_since(started_at),
                                command);
    }
    Logger::instance().trace("safe_exec_capture_end",
                             "cmd={} exit_code={} duration_ms={} bytes={} truncated={} timed_out={}",
                             command,
                             result.exit_code,
                             elapsed_ms_since(started_at),
                             result.stdout_output.size(),
                             result.truncated ? "true" : "false",
                             result.timed_out ? "true" : "false");
    return result;
}

} // namespace keen_pbr3
