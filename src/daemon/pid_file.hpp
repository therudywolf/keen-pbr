#pragma once

#include <cstdint>
#include <filesystem>

namespace keen_pbr3 {

// Exclusive, crash-safe ownership of the daemon PID file.
//
// The init script and the netfilter.d hook signal the daemon through this
// file (SIGUSR1 / SIGHUP), so a second instance must never damage it: the
// file is opened without O_TRUNC, locked, and only then truncated and
// rewritten. A start that loses the lock leaves the running daemon's PID in
// place. On release only our own inode is unlinked, so a file another
// instance recreated meanwhile survives.
class PidFile {
public:
    PidFile() = default;
    ~PidFile();

    PidFile(const PidFile&) = delete;
    PidFile& operator=(const PidFile&) = delete;

    // Create (or take over a stale) PID file at `path` and write getpid().
    // No-op for an empty path. Throws std::runtime_error when another
    // instance holds the lock or the path is not a plain PID file (symlink,
    // hard link, foreign owner, group/world-writable, non-PID contents).
    void acquire(const std::filesystem::path& path);

    // Unlink the file if it is still our inode, then drop the lock.
    void remove();

    bool acquired() const noexcept { return fd_ >= 0; }

private:
    int fd_{-1};
    std::filesystem::path path_;
    std::uint64_t device_{0};
    std::uint64_t inode_{0};
};

} // namespace keen_pbr3
