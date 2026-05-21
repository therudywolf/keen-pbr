#include "logger.hpp"

#include "trace.hpp"

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#if defined(__unix__) || defined(__APPLE__)
#include <syslog.h>
#endif

namespace keen_pbr3 {

namespace {

std::string format_wall_clock_now() {
    const auto now = std::chrono::system_clock::now();
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % std::chrono::seconds(1);
    const std::time_t time = std::chrono::system_clock::to_time_t(now);

    std::tm tm {};
#if defined(_WIN32)
    localtime_s(&tm, &time);
#else
    localtime_r(&time, &tm);
#endif

    std::ostringstream out;
    out << std::put_time(&tm, "%Y-%m-%dT%H:%M:%S")
        << '.'
        << std::setw(3) << std::setfill('0') << ms.count();
    return out.str();
}

std::string current_thread_id_string() {
    std::ostringstream out;
    out << std::this_thread::get_id();
    return out.str();
}

#if defined(__unix__) || defined(__APPLE__)
void emit_syslog_line(const std::string& line, int priority) {
    static std::once_flag openlog_once;
    std::call_once(openlog_once, []() {
        openlog("keen-pbr", LOG_PID, LOG_DAEMON);
    });
    syslog(priority, "%s", line.c_str());
}
#else
void emit_syslog_line(const std::string&, int) {}
#endif

// Returns the current size of an open file, or 0 if it cannot be determined.
// Used to seed the running byte counter when appending to a pre-existing log.
std::uintmax_t current_file_size(std::FILE* file) {
    if (file == nullptr) {
        return 0;
    }
    if (std::fseek(file, 0, SEEK_END) != 0) {
        return 0;
    }
    const long pos = std::ftell(file);
    return pos > 0 ? static_cast<std::uintmax_t>(pos) : 0;
}

} // namespace

LogLevel parse_log_level(std::string_view s) {
    if (s == "error") return LogLevel::error;
    if (s == "warn") return LogLevel::warn;
    if (s == "info") return LogLevel::info;
    if (s == "verbose") return LogLevel::verbose;
    if (s == "debug") return LogLevel::debug;
    throw std::runtime_error(
        keen_pbr3::format("Unknown log level '{}'. Valid: error, warn, info, verbose, debug", s));
}

Logger::Logger() {
    // The optional file sink is enabled purely via the environment so that the
    // default stdout/stderr behaviour is unchanged unless explicitly opted in.
    const char* env_path = std::getenv("KEEN_PBR_LOG_FILE");
    if (env_path != nullptr && env_path[0] != '\0') {
        std::lock_guard<std::mutex> lock(sink_mutex_);
        open_file_sink_locked(env_path);
    }
}

Logger& Logger::instance() {
    static Logger logger;
    return logger;
}

void Logger::set_sink(Sink sink) {
    std::lock_guard<std::mutex> lock(sink_mutex_);
    sink_ = std::move(sink);
}

void Logger::clear_sink() {
    std::lock_guard<std::mutex> lock(sink_mutex_);
    sink_ = nullptr;
}

void Logger::open_file_sink_locked(const std::string& path) {
    close_file_sink_locked();
    if (path.empty()) {
        return;
    }
    // Append mode: never clobber an existing log on (re)start. A failure here
    // (missing directory, permissions, read-only fs) is intentionally silent --
    // logging must never block startup or crash the daemon.
    std::FILE* file = std::fopen(path.c_str(), "ae");
    if (file == nullptr) {
        // Retry without the glibc "e" (O_CLOEXEC) extension for portability.
        file = std::fopen(path.c_str(), "a");
    }
    if (file == nullptr) {
        return;
    }
    file_sink_ = file;
    file_sink_path_ = path;
    file_sink_bytes_ = current_file_size(file);
}

void Logger::close_file_sink_locked() {
    if (file_sink_ != nullptr) {
        std::fclose(file_sink_);
        file_sink_ = nullptr;
    }
    file_sink_path_.clear();
    file_sink_bytes_ = 0;
}

void Logger::write_file_sink_locked(const std::string& line) {
    if (file_sink_ == nullptr) {
        return;
    }

    const std::uintmax_t pending = static_cast<std::uintmax_t>(line.size()) + 1;

    // Size-based rotation: once the cap is reached, move the current file to
    // "<path>.1" (replacing any prior backup) and reopen a fresh primary file.
    // Only a single backup is kept to bound disk use on small routers.
    if (file_sink_rotate_bytes_ > 0 &&
        file_sink_bytes_ + pending > file_sink_rotate_bytes_ &&
        file_sink_bytes_ > 0) {
        const std::string path = file_sink_path_;
        const std::string rotated = path + ".1";
        std::fclose(file_sink_);
        file_sink_ = nullptr;
        std::remove(rotated.c_str());
        std::rename(path.c_str(), rotated.c_str());
        // Reopen the primary path. If rename succeeded this starts empty; if it
        // failed we simply keep appending. Either way disk use stays bounded.
        std::FILE* file = std::fopen(path.c_str(), "ae");
        if (file == nullptr) {
            file = std::fopen(path.c_str(), "a");
        }
        if (file == nullptr) {
            // Lost the sink during rotation; degrade to stdout/stderr only.
            file_sink_path_.clear();
            file_sink_bytes_ = 0;
            return;
        }
        file_sink_ = file;
        file_sink_bytes_ = current_file_size(file);
    }

    if (std::fwrite(line.data(), 1, line.size(), file_sink_) != line.size()) {
        return;
    }
    if (std::fputc('\n', file_sink_) == EOF) {
        return;
    }
    std::fflush(file_sink_);
    file_sink_bytes_ += pending;
}

void Logger::emit_line(const std::string& line, int syslog_priority) {
    std::lock_guard<std::mutex> lock(sink_mutex_);
    std::cerr << line << "\n";
    emit_syslog_line(line, syslog_priority);
    write_file_sink_locked(line);
    if (sink_) {
        sink_(line);
    }
}

#if defined(KEEN_PBR3_TESTING)
void Logger::set_log_file_for_testing(const std::string& path) {
    std::lock_guard<std::mutex> lock(sink_mutex_);
    open_file_sink_locked(path);
}

void Logger::set_log_file_rotate_bytes_for_testing(std::uintmax_t bytes) {
    std::lock_guard<std::mutex> lock(sink_mutex_);
    file_sink_rotate_bytes_ = bytes;
}
#endif

void Logger::error(std::string_view msg) {
    if (is_enabled(LogLevel::error))
        emit_line("[E] " + std::string(msg),
#if defined(__unix__) || defined(__APPLE__)
                  LOG_ERR
#else
                  0
#endif
        );
}

void Logger::warn(std::string_view msg) {
    if (is_enabled(LogLevel::warn))
        emit_line("[W] " + std::string(msg),
#if defined(__unix__) || defined(__APPLE__)
                  LOG_WARNING
#else
                  0
#endif
        );
}

void Logger::info(std::string_view msg) {
    if (is_enabled(LogLevel::info))
        emit_line(std::string(msg),
#if defined(__unix__) || defined(__APPLE__)
                  LOG_INFO
#else
                  0
#endif
        );
}

void Logger::verbose(std::string_view msg) {
    if (is_enabled(LogLevel::verbose))
        emit_line("[V] " + std::string(msg),
#if defined(__unix__) || defined(__APPLE__)
                  LOG_INFO
#else
                  0
#endif
        );
}

void Logger::debug(std::string_view msg) {
    if (is_enabled(LogLevel::debug))
        emit_line("[D] " + std::string(msg),
#if defined(__unix__) || defined(__APPLE__)
                  LOG_DEBUG
#else
                  0
#endif
        );
}

void Logger::trace(std::string_view event, std::string_view details) {
    if (!is_enabled(LogLevel::debug)) {
        return;
    }

    const auto mono_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - started_at_).count();
    std::ostringstream out;
    out << "[T] "
        << format_wall_clock_now()
        << " mono_ms=" << mono_ms
        << " tid=" << current_thread_id_string()
        << " trace=" << current_trace_id()
        << " event=" << event;
    if (!details.empty()) {
        out << " " << details;
    }
    emit_line(out.str(),
#if defined(__unix__) || defined(__APPLE__)
              LOG_DEBUG
#else
              0
#endif
    );
}

} // namespace keen_pbr3
