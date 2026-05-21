#pragma once

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <mutex>
#include <string>
#include <string_view>

#include "../util/format_compat.hpp"

namespace keen_pbr3 {

enum class LogLevel { error, warn, info, verbose, debug };

LogLevel parse_log_level(std::string_view s);

class Logger {
public:
    using Sink = std::function<void(const std::string&)>;

    static Logger& instance();

    void set_level(LogLevel level) { level_ = level; }
    LogLevel level() const { return level_; }
    bool is_enabled(LogLevel level) const { return level <= level_; }

    void set_sink(Sink sink);
    void clear_sink();

    void error(std::string_view msg);
    void warn(std::string_view msg);
    void info(std::string_view msg);
    void verbose(std::string_view msg);
    void debug(std::string_view msg);
    void trace(std::string_view event, std::string_view details = {});

    template<typename... Args>
    void error(format_string<Args...> fmt, Args&&... args) {
        if (is_enabled(LogLevel::error))
            error(std::string_view(keen_pbr3::format(fmt, std::forward<Args>(args)...)));
    }

    template<typename... Args>
    void warn(format_string<Args...> fmt, Args&&... args) {
        if (is_enabled(LogLevel::warn))
            warn(std::string_view(keen_pbr3::format(fmt, std::forward<Args>(args)...)));
    }

    template<typename... Args>
    void info(format_string<Args...> fmt, Args&&... args) {
        if (is_enabled(LogLevel::info))
            info(std::string_view(keen_pbr3::format(fmt, std::forward<Args>(args)...)));
    }

    template<typename... Args>
    void verbose(format_string<Args...> fmt, Args&&... args) {
        if (is_enabled(LogLevel::verbose))
            verbose(std::string_view(keen_pbr3::format(fmt, std::forward<Args>(args)...)));
    }

    template<typename... Args>
    void debug(format_string<Args...> fmt, Args&&... args) {
        if (is_enabled(LogLevel::debug))
            debug(std::string_view(keen_pbr3::format(fmt, std::forward<Args>(args)...)));
    }

    template<typename... Args>
    void trace(std::string_view event, format_string<Args...> fmt, Args&&... args) {
        if (is_enabled(LogLevel::debug))
            trace(event, std::string_view(keen_pbr3::format(fmt, std::forward<Args>(args)...)));
    }

#if defined(KEEN_PBR3_TESTING)
    // Test-only: redirect the optional file sink to an explicit path, bypassing
    // the KEEN_PBR_LOG_FILE environment variable. An empty path closes the sink.
    void set_log_file_for_testing(const std::string& path);
    // Test-only: byte cap that triggers rotation (defaults to 1 MiB).
    void set_log_file_rotate_bytes_for_testing(std::uintmax_t bytes);
#endif

private:
    Logger();

    void emit_line(const std::string& line, int syslog_priority);

    // Opens the optional file sink for `path` (append mode). Must be called
    // while `sink_mutex_` is held. A failure leaves the sink disabled.
    void open_file_sink_locked(const std::string& path);
    // Closes the optional file sink. Must be called while `sink_mutex_` is held.
    void close_file_sink_locked();
    // Appends `line` (plus a newline) to the file sink, rotating first if the
    // configured size cap would be exceeded. Must be called while
    // `sink_mutex_` is held; a no-op when no file sink is open.
    void write_file_sink_locked(const std::string& line);

    LogLevel level_{LogLevel::info};
    std::mutex sink_mutex_;
    Sink sink_;
    std::chrono::steady_clock::time_point started_at_{std::chrono::steady_clock::now()};

    // Optional file sink, all fields guarded by sink_mutex_.
    std::FILE* file_sink_{nullptr};
    std::string file_sink_path_;
    std::uintmax_t file_sink_bytes_{0};
    std::uintmax_t file_sink_rotate_bytes_{1024 * 1024};
};

} // namespace keen_pbr3
