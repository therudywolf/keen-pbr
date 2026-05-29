#include "config_writer.hpp"

#include "../log/logger.hpp"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

namespace keen_pbr3 {

namespace {

std::runtime_error make_errno_error(const std::string& prefix) {
    return std::runtime_error(prefix + ": " + std::strerror(errno));
}

void cleanup_tmp_file(const std::string& tmp_path) {
    if (std::remove(tmp_path.c_str()) != 0 && errno != ENOENT) {
        Logger::instance().warn("Failed to remove temporary config file '{}': {}",
                                tmp_path, std::strerror(errno));
    }
}

void write_all_or_throw(int fd, const std::string& body) {
    const char* data = body.data();
    size_t total_written = 0;
    while (total_written < body.size()) {
        const ssize_t written = ::write(fd, data + total_written, body.size() - total_written);
        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            throw make_errno_error("Cannot write config file");
        }
        total_written += static_cast<size_t>(written);
    }
}

void fsync_or_throw(int fd, const std::string& what) {
    if (::fsync(fd) != 0) {
        throw make_errno_error("Cannot fsync " + what);
    }
}

}  // namespace

void write_config_atomically(const std::string& config_path,
                             const std::string& body) {
    const std::filesystem::path config_fs_path(config_path);
    const std::filesystem::path dir_path = config_fs_path.has_parent_path()
                                               ? config_fs_path.parent_path()
                                               : std::filesystem::path(".");
    const std::string tmp_path = config_path + ".tmp";

    int tmp_fd = -1;
    try {
        tmp_fd = ::open(tmp_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
                        S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
        if (tmp_fd < 0) {
            throw make_errno_error("Cannot open temporary config file");
        }

        write_all_or_throw(tmp_fd, body);
        fsync_or_throw(tmp_fd, "temporary config file");

        if (::close(tmp_fd) != 0) {
            tmp_fd = -1;
            throw make_errno_error("Cannot close temporary config file");
        }
        tmp_fd = -1;

        if (std::rename(tmp_path.c_str(), config_path.c_str()) != 0) {
            throw make_errno_error("Cannot replace config file");
        }

        const auto dir_path_string = dir_path.string();
        const int dir_fd = ::open(dir_path_string.c_str(), O_RDONLY | O_CLOEXEC);
        if (dir_fd < 0) {
            throw make_errno_error("Cannot open config directory for fsync");
        }

        try {
            fsync_or_throw(dir_fd, "config directory");
        } catch (...) {
            ::close(dir_fd);
            throw;
        }

        if (::close(dir_fd) != 0) {
            throw make_errno_error("Cannot close config directory after fsync");
        }
    } catch (...) {
        if (tmp_fd >= 0) {
            ::close(tmp_fd);
        }
        cleanup_tmp_file(tmp_path);
        throw;
    }
}

}  // namespace keen_pbr3
