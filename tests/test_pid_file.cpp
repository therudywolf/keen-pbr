#include <doctest/doctest.h>

#include "../src/daemon/pid_file.hpp"

#include <filesystem>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

namespace keen_pbr3 {

namespace {

class TempDirectory {
public:
    TempDirectory() {
        char pattern[] = "/tmp/forest-pbr-pid-XXXXXX";
        const char* path = ::mkdtemp(pattern);
        if (!path) {
            throw std::runtime_error("mkdtemp failed");
        }
        path_ = path;
    }
    ~TempDirectory() { std::filesystem::remove_all(path_); }
    const std::filesystem::path& path() const { return path_; }

private:
    std::filesystem::path path_;
};

std::string read_file(const std::filesystem::path& path) {
    std::ifstream input(path);
    std::ostringstream out;
    out << input.rdbuf();
    return out.str();
}

std::string own_pid_line() {
    return std::to_string(::getpid()) + "\n";
}

} // namespace

TEST_CASE("PidFile acquires, writes, and removes its file") {
    TempDirectory temp;
    const auto path = temp.path() / "run" / "daemon.pid";
    PidFile pid;
    pid.acquire(path);
    CHECK(pid.acquired());
    CHECK(read_file(path) == own_pid_line());
    pid.remove();
    CHECK_FALSE(pid.acquired());
    CHECK_FALSE(std::filesystem::exists(path));
}

TEST_CASE("PidFile: a second instance neither acquires nor truncates the live PID file") {
    TempDirectory temp;
    const auto path = temp.path() / "daemon.pid";
    PidFile live;
    live.acquire(path);

    PidFile second;
    CHECK_THROWS_WITH_AS(second.acquire(path),
                         doctest::Contains("Another instance is already running"),
                         std::runtime_error);
    CHECK_FALSE(second.acquired());
    // The live daemon's PID must still be there for SIGUSR1/SIGHUP senders.
    CHECK(read_file(path) == own_pid_line());

    live.remove();
    CHECK_FALSE(std::filesystem::exists(path));
}

TEST_CASE("PidFile refuses symlinks and unrelated regular files") {
    TempDirectory temp;
    const auto sentinel = temp.path() / "sentinel";
    const auto link = temp.path() / "daemon.pid";
    {
        std::ofstream out(sentinel);
        out << "do not touch\n";
    }
    std::filesystem::create_symlink(sentinel, link);

    PidFile pid;
    CHECK_THROWS(pid.acquire(link));
    CHECK(read_file(sentinel) == "do not touch\n");

    std::filesystem::remove(link);
    CHECK_THROWS_WITH(pid.acquire(sentinel), doctest::Contains("non-PID file"));
    CHECK(read_file(sentinel) == "do not touch\n");
    CHECK_FALSE(pid.acquired());
}

TEST_CASE("PidFile refuses a group-writable file") {
    TempDirectory temp;
    const auto path = temp.path() / "daemon.pid";
    {
        std::ofstream out(path);
        out << "12345\n";
    }
    REQUIRE(::chmod(path.c_str(), 0664) == 0);

    PidFile pid;
    CHECK_THROWS(pid.acquire(path));
    CHECK(read_file(path) == "12345\n");
}

TEST_CASE("PidFile removal preserves a replacement inode") {
    TempDirectory temp;
    const auto path = temp.path() / "daemon.pid";
    const auto old_path = temp.path() / "old.pid";
    PidFile pid;
    pid.acquire(path);
    std::filesystem::rename(path, old_path);
    {
        std::ofstream out(path);
        out << "sentinel\n";
    }

    pid.remove();
    CHECK(std::filesystem::exists(path));
    CHECK(read_file(path) == "sentinel\n");
}

TEST_CASE("PidFile takes over a stale PID file left by a crashed daemon") {
    TempDirectory temp;
    const auto path = temp.path() / "daemon.pid";
    {
        std::ofstream out(path);
        out << "12345\n";
    }
    REQUIRE(::chmod(path.c_str(), 0644) == 0);

    PidFile pid;
    CHECK_NOTHROW(pid.acquire(path));
    CHECK(read_file(path) == own_pid_line());
}

TEST_CASE("PidFile: an empty path is a no-op") {
    PidFile pid;
    CHECK_NOTHROW(pid.acquire(std::filesystem::path{}));
    CHECK_FALSE(pid.acquired());
    CHECK_NOTHROW(pid.remove());
}

} // namespace keen_pbr3
