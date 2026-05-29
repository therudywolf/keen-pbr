#include "dns_split_observer.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <utility>
#include <vector>

#include "../dns/dnsmasq_reply_parser.hpp"
#include "../log/logger.hpp"
#include "dns_split_table.hpp"
#include "tcp_payload.hpp"  // parse_ipv4_to_key

namespace keen_pbr3 {

namespace {

// Read at most this many bytes per tick so one burst of DNS traffic can never
// make a tick walk an unbounded amount of log at once on a weak router. Anything
// beyond this is picked up on the following tick (offset_ advances by what we
// actually consumed).
constexpr std::size_t kMaxBytesPerTick = 256 * 1024;
constexpr std::size_t kReadChunk = 8192;

// Cap the partial-line carry so a pathological log with no newlines cannot grow
// memory without bound. A dnsmasq reply line is well under 1 KiB.
constexpr std::size_t kMaxCarry = 16 * 1024;

}  // namespace

DnsSplitObserver::DnsSplitObserver(std::string log_path,
                                   std::map<std::string, uint32_t> domain_marks,
                                   DnsSplitTable* table)
    : log_path_(std::move(log_path)),
      classifier_(std::move(domain_marks)),
      table_(table) {}

DnsSplitObserver::~DnsSplitObserver() {
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
}

bool DnsSplitObserver::ensure_open() {
    if (fd_ >= 0) {
        return true;
    }
    fd_ = ::open(log_path_.c_str(), O_RDONLY | O_CLOEXEC | O_NONBLOCK);
    if (fd_ < 0) {
        // Common and benign: dnsmasq may not have created the file yet (no
        // restart since enabling) — retried on the next tick, no error spam.
        return false;
    }
    struct stat st {};
    inode_ = (::fstat(fd_, &st) == 0) ? static_cast<std::uint64_t>(st.st_ino) : 0;
    // Start tailing from our recorded offset. On first open offset_ is 0, so we
    // read the whole current file once; thereafter we only see appended lines.
    if (offset_ > 0) {
        ::lseek(fd_, static_cast<off_t>(offset_), SEEK_SET);
    }
    return true;
}

int DnsSplitObserver::tick() noexcept {
    if (table_ == nullptr) {
        return 0;
    }

    int upserts = 0;
    try {
        // Periodic GC so the table cannot grow unbounded across ticks even for
        // IPs that are never looked up again.
        table_->expire();

        if (!ensure_open()) {
            return 0;
        }

        // Detect rename-based rotation: logrotate's default renames the live
        // file away and creates a fresh one at the same path. Our open fd still
        // points at the renamed-away inode, so compare the path's current inode
        // with the one we opened — if it changed, reopen the new file.
        {
            struct stat path_st {};
            if (::stat(log_path_.c_str(), &path_st) == 0 &&
                static_cast<std::uint64_t>(path_st.st_ino) != inode_) {
                Logger::instance().verbose(
                    "dns_split: log {} rotated (inode changed), reopening", log_path_);
                ::close(fd_);
                fd_ = -1;
                offset_ = 0;
                carry_.clear();
                if (!ensure_open()) {
                    return 0;
                }
            }
        }

        // Detect in-place truncation (logrotate copytruncate): if the file is now
        // smaller than what we have already consumed, re-read from the start so
        // we don't skip the fresh content.
        struct stat st {};
        if (::fstat(fd_, &st) == 0) {
            const auto size = static_cast<std::uint64_t>(st.st_size);
            if (size < offset_) {
                Logger::instance().verbose(
                    "dns_split: log {} shrank ({} < {}), re-reading from start",
                    log_path_, size, offset_);
                offset_ = 0;
                carry_.clear();
                ::lseek(fd_, 0, SEEK_SET);
            }
        }

        std::size_t consumed_this_tick = 0;
        std::vector<char> buf(kReadChunk);
        bool done = false;
        while (!done && consumed_this_tick < kMaxBytesPerTick) {
            const ssize_t n = ::read(fd_, buf.data(), buf.size());
            if (n > 0) {
                offset_ += static_cast<std::uint64_t>(n);
                consumed_this_tick += static_cast<std::size_t>(n);
                carry_.append(buf.data(), static_cast<std::size_t>(n));

                // Split the accumulated buffer into complete lines.
                std::size_t start = 0;
                for (std::size_t i = 0; i < carry_.size(); ++i) {
                    if (carry_[i] != '\n') {
                        continue;
                    }
                    std::string_view line(carry_.data() + start, i - start);
                    if (const auto reply = parse_dnsmasq_reply_line(line)) {
                        if (const auto mark = classifier_.classify(reply->domain)) {
                            if (const auto key = parse_ipv4_to_key(
                                    reply->ipv4.data(), reply->ipv4.size())) {
                                table_->upsert(*key, *mark);
                                ++upserts;
                                Logger::instance().trace(
                                    "dns_split_correlate",
                                    "domain={} ip={} mark=0x{:x}",
                                    reply->domain, reply->ipv4, *mark);
                            }
                        }
                    }
                    start = i + 1;
                }
                // Keep the trailing partial line (if any) for the next read.
                carry_.erase(0, start);
                if (carry_.size() > kMaxCarry) {
                    // No newline in an absurd amount of data — drop it to bound
                    // memory; a real reply line is tiny.
                    carry_.clear();
                }
            } else if (n == 0) {
                done = true;  // reached current EOF
            } else {
                if (errno == EINTR) {
                    continue;
                }
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    done = true;  // nothing more right now
                } else {
                    Logger::instance().warn("dns_split: read {} failed: {}", log_path_,
                                            std::strerror(errno));
                    // Drop the fd so the next tick reopens cleanly.
                    ::close(fd_);
                    fd_ = -1;
                    done = true;
                }
            }
        }
    } catch (const std::exception& e) {
        Logger::instance().warn("dns_split: observer tick failed: {}", e.what());
    } catch (...) {
        Logger::instance().warn("dns_split: observer tick failed: unknown error");
    }
    return upserts;
}

}  // namespace keen_pbr3
