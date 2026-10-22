#include "pid_file.hpp"

#include <cctype>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <stdexcept>
#include <string>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

namespace keen_pbr3 {

namespace {

std::runtime_error pid_error(const std::string& message,
                             const std::filesystem::path& path,
                             int error_number) {
    return std::runtime_error(message + ": " + path.string() + ": " +
                              std::strerror(error_number));
}

// A stale PID file left by a crashed daemon is empty or holds one decimal PID
// with an optional trailing newline. Anything else is not ours to overwrite.
bool valid_stale_pid_contents(const std::string& contents) {
    if (contents.empty()) {
        return true;
    }
    std::size_t end = contents.size();
    if (contents.back() == '\n') {
        --end;
    }
    if (end == 0) {
        return false;
    }
    for (std::size_t i = 0; i < end; ++i) {
        if (!std::isdigit(static_cast<unsigned char>(contents[i]))) {
            return false;
        }
    }
    return true;
}

void write_all(int fd, const std::string& value) {
    std::size_t offset = 0;
    while (offset < value.size()) {
        const ssize_t written = ::write(fd, value.data() + offset, value.size() - offset);
        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            throw std::runtime_error(std::string("Failed to write PID file: ") +
                                     std::strerror(errno));
        }
        offset += static_cast<std::size_t>(written);
    }
}

} // namespace

PidFile::~PidFile() {
    try {
        remove();
    } catch (...) {
    }
}

void PidFile::acquire(const std::filesystem::path& path) {
    if (path.empty()) {
        return;
    }
    if (fd_ >= 0) {
        throw std::runtime_error("PID file is already acquired: " + path_.string());
    }

    const auto parent = path.parent_path();
    if (!parent.empty()) {
        std::filesystem::create_directories(parent);
    }

    // No O_TRUNC: the file may belong to a running daemon. It is truncated
    // only after the exclusive lock below proves it is stale.
    const int fd = ::open(path.c_str(), O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW,
                          S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (fd < 0) {
        throw pid_error("Cannot open PID file", path, errno);
    }

    if (::flock(fd, LOCK_EX | LOCK_NB) != 0) {
        const int lock_errno = errno;
        ::close(fd);
        if (lock_errno == EWOULDBLOCK || lock_errno == EAGAIN) {
            throw std::runtime_error("Another instance is already running (PID file locked): " +
                                     path.string());
        }
        throw pid_error("Cannot lock PID file", path, lock_errno);
    }

    struct stat st {};
    if (::fstat(fd, &st) != 0) {
        const int stat_errno = errno;
        ::close(fd);
        throw pid_error("Cannot inspect PID file", path, stat_errno);
    }
    if (!S_ISREG(st.st_mode) || st.st_nlink != 1 || st.st_uid != ::geteuid() ||
        (st.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        ::close(fd);
        throw std::runtime_error(
            "PID file must be a single-link regular file owned by the daemon user "
            "and not group/world-writable: " + path.string());
    }
    if (st.st_size < 0 || st.st_size > 64) {
        ::close(fd);
        throw std::runtime_error("PID file has invalid existing contents: " + path.string());
    }

    std::string existing(static_cast<std::size_t>(st.st_size), '\0');
    if (!existing.empty()) {
        const ssize_t bytes = ::pread(fd, existing.data(), existing.size(), 0);
        if (bytes < 0 || static_cast<std::size_t>(bytes) != existing.size()) {
            const int read_errno = bytes < 0 ? errno : EIO;
            ::close(fd);
            throw pid_error("Cannot read PID file", path, read_errno);
        }
    }
    if (!valid_stale_pid_contents(existing)) {
        ::close(fd);
        throw std::runtime_error("Refusing to overwrite non-PID file: " + path.string());
    }

    if (::ftruncate(fd, 0) != 0 || ::lseek(fd, 0, SEEK_SET) < 0) {
        const int truncate_errno = errno;
        ::close(fd);
        throw pid_error("Cannot truncate PID file", path, truncate_errno);
    }
    try {
        write_all(fd, std::to_string(::getpid()) + "\n");
    } catch (...) {
        ::close(fd);
        throw;
    }

    fd_ = fd;
    path_ = path;
    device_ = static_cast<std::uint64_t>(st.st_dev);
    inode_ = static_cast<std::uint64_t>(st.st_ino);
}

void PidFile::remove() {
    if (fd_ < 0) {
        return;
    }

    // Unlink only while the path still names our inode (still holding the
    // lock): a replacement written by someone else is left alone.
    struct stat current {};
    if (::lstat(path_.c_str(), &current) == 0 &&
        static_cast<std::uint64_t>(current.st_dev) == device_ &&
        static_cast<std::uint64_t>(current.st_ino) == inode_) {
        (void)::unlink(path_.c_str());
    }
    ::close(fd_);
    fd_ = -1;
    path_.clear();
    device_ = 0;
    inode_ = 0;
}

} // namespace keen_pbr3
