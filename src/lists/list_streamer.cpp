#include "list_streamer.hpp"
#include "../config/list_parser.hpp"

#include <array>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <stdexcept>
#include <sys/stat.h>
#include <unistd.h>

namespace keen_pbr3 {

ListStreamer::ListStreamer(const CacheManager& cache) : cache_(cache) {}

void ListStreamer::stream_list(const std::string& name, const ListConfig& config, ListEntryVisitor& visitor) {
    // The cached URL file is used only while the list still declares a URL
    // source; a stale cache for a removed URL is ignored here.
    const bool include_cache = config.url.has_value() && cache_.has_cache(name);
    stream_all_sources(name, config, visitor, include_cache);
}

void ListStreamer::stream_list_preferring_cache(const std::string& name,
                                                const ListConfig& config,
                                                ListEntryVisitor& visitor) {
    // Use the cached file whenever it exists, even if the URL source was
    // removed from the config. The local file and inline entries are always
    // streamed too — they must not be dropped just because a cache exists.
    stream_all_sources(name, config, visitor, cache_.has_cache(name));
}

void ListStreamer::stream_all_sources(const std::string& name,
                                      const ListConfig& config,
                                      ListEntryVisitor& visitor,
                                      bool include_cache) {
    // 1. Cached URL file. Downloaded lists routinely carry junk lines;
    // they are skipped without logging.
    if (include_cache) {
        stream_file(cache_.cache_path(name), visitor, /*log_invalid_entries=*/false);
    }

    // 2. Local file (if configured)
    if (config.file.has_value()) {
        stream_file(config.file.value(), visitor, /*log_invalid_entries=*/true);
    }

    // 3+4. Inline entries go through the same parser as file and URL
    // sources: comments and blanks are skipped, domains are normalized
    // ("*." and the root dot removed), a CIDR placed among the domains is
    // routed as a CIDR, and a malformed entry (e.g. one carrying a newline
    // that would inject a dnsmasq directive) is skipped with a warning
    // instead of being passed on. The config itself is never rejected for
    // its list entries.
    const std::string inline_source = "inline list '" + name + "'";
    std::size_t inline_line_number = 1;
    ListParser::ParseContext inline_context;
    for (const auto& entry : config.ip_cidrs.value_or(std::vector<std::string>{})) {
        ListParser::parse_line(entry, visitor, inline_source, inline_line_number++, &inline_context);
    }
    for (const auto& domain : config.domains.value_or(std::vector<std::string>{})) {
        ListParser::parse_line(domain, visitor, inline_source, inline_line_number++, &inline_context);
    }
    ListParser::finish_source(inline_source, inline_context);

    // Signal that all sources for this list have been processed
    visitor.on_list_complete(name);
}

void ListStreamer::stream_cache(const std::string& name, ListEntryVisitor& visitor) {
    if (cache_.has_cache(name)) {
        stream_file(cache_.cache_path(name), visitor, /*log_invalid_entries=*/false);
    }
}

void ListStreamer::stream_file(const std::filesystem::path& path,
                               ListEntryVisitor& visitor,
                               bool log_invalid_entries) {
    // O_NONBLOCK keeps a FIFO from blocking the daemon in open(); fstat()
    // below then rejects anything that is not a regular file (FIFOs,
    // devices such as /dev/zero), which could otherwise stall the event
    // loop or never reach EOF.
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) {
        throw std::runtime_error("Failed to open list file " + path.string() + ": " +
                                 std::strerror(errno));
    }
    const auto close_fd = [fd]() { ::close(fd); };

    struct stat st {};
    if (::fstat(fd, &st) != 0) {
        const std::string error = std::strerror(errno);
        close_fd();
        throw std::runtime_error("Failed to inspect list file " + path.string() + ": " + error);
    }
    if (!S_ISREG(st.st_mode)) {
        close_fd();
        throw std::runtime_error("List source is not a regular file: " + path.string());
    }

    const std::string source = path.string();
    ListParser::ParseContext context;
    context.log_invalid_entries = log_invalid_entries;

    // Lines are bounded: a line longer than kMaxLineBytes is skipped (with a
    // warning for local files) and the rest of the list is still loaded.
    std::array<char, 4096> buffer {};
    std::string line;
    line.reserve(256);
    bool line_overlong = false;
    std::size_t line_number = 1;
    const auto finish_line = [&]() {
        if (line_overlong) {
            ListParser::report_overlong_line(source, line_number, context);
        } else {
            ListParser::parse_line(line, visitor, source, line_number, &context);
        }
        ++line_number;
        line.clear();
        line_overlong = false;
    };

    while (true) {
        const ssize_t count = ::read(fd, buffer.data(), buffer.size());
        if (count < 0) {
            if (errno == EINTR) continue;
            const std::string error = std::strerror(errno);
            close_fd();
            throw std::runtime_error("Failed to read list file " + path.string() + ": " + error);
        }
        if (count == 0) break;
        for (ssize_t i = 0; i < count; ++i) {
            const char ch = buffer[static_cast<std::size_t>(i)];
            if (ch == '\n') {
                finish_line();
                continue;
            }
            if (line_overlong) continue;
            if (line.size() >= kMaxLineBytes) {
                line_overlong = true;
                line.clear();
                continue;
            }
            line.push_back(ch);
        }
    }
    close_fd();
    if (!line.empty() || line_overlong) {
        finish_line();
    }
    ListParser::finish_source(source, context);
}

} // namespace keen_pbr3
