#include <doctest/doctest.h>

#include "../src/log/logger.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unistd.h>

namespace keen_pbr3 {

namespace {

namespace fs = std::filesystem;

fs::path make_temp_dir() {
    char path_template[] = "/tmp/keen-pbr-log-sink-XXXXXX";
    const char* created = mkdtemp(path_template);
    if (created == nullptr) {
        throw std::runtime_error("mkdtemp failed");
    }
    return fs::path(created);
}

// Restores the logger to its default (no file sink, prior level/cap) so the
// shared singleton does not leak state into other test cases.
class LogFileSinkGuard {
public:
    explicit LogFileSinkGuard(const fs::path& dir)
        : dir_(dir), previous_level_(Logger::instance().level()) {
        Logger::instance().set_level(LogLevel::debug);
    }

    ~LogFileSinkGuard() {
        Logger::instance().set_log_file_for_testing("");
        Logger::instance().set_log_file_rotate_bytes_for_testing(1024 * 1024);
        Logger::instance().set_level(previous_level_);
        std::error_code ec;
        fs::remove_all(dir_, ec);
    }

private:
    fs::path dir_;
    LogLevel previous_level_;
};

std::string read_file(const fs::path& path) {
    std::ifstream stream(path, std::ios::binary);
    std::ostringstream buffer;
    buffer << stream.rdbuf();
    return buffer.str();
}

} // namespace

TEST_CASE("file sink appends log output to the configured file") {
    const fs::path dir = make_temp_dir();
    LogFileSinkGuard guard(dir);
    const fs::path log_path = dir / "keen-pbr.log";

    Logger::instance().set_log_file_for_testing(log_path.string());
    Logger::instance().info("file-sink-marker-one");
    Logger::instance().error("file-sink-marker-two");

    REQUIRE(fs::exists(log_path));
    const std::string contents = read_file(log_path);
    CHECK(contents.find("file-sink-marker-one") != std::string::npos);
    CHECK(contents.find("[E] file-sink-marker-two") != std::string::npos);
}

TEST_CASE("file sink appends to a pre-existing log rather than truncating it") {
    const fs::path dir = make_temp_dir();
    LogFileSinkGuard guard(dir);
    const fs::path log_path = dir / "keen-pbr.log";

    {
        std::ofstream seed(log_path, std::ios::binary);
        seed << "pre-existing-line\n";
    }

    Logger::instance().set_log_file_for_testing(log_path.string());
    Logger::instance().info("post-open-line");

    const std::string contents = read_file(log_path);
    CHECK(contents.find("pre-existing-line") != std::string::npos);
    CHECK(contents.find("post-open-line") != std::string::npos);
}

TEST_CASE("file sink rotates to <path>.1 once the size cap is exceeded") {
    const fs::path dir = make_temp_dir();
    LogFileSinkGuard guard(dir);
    const fs::path log_path = dir / "keen-pbr.log";
    const fs::path rotated_path = dir / "keen-pbr.log.1";

    // "rotation-line-NNNN" plus the newline emit_line adds is a fixed 19 bytes.
    // With a 200-byte cap, 10 lines (190 bytes) fit and the 11th forces a single
    // rotation. Writing exactly 19 lines therefore yields one deterministic
    // rotation: lines 0..9 in the backup, lines 10..18 in the active file.
    Logger::instance().set_log_file_for_testing(log_path.string());
    Logger::instance().set_log_file_rotate_bytes_for_testing(200);

    for (int i = 0; i < 19; ++i) {
        Logger::instance().info("rotation-line-{:04}", i);
    }

    REQUIRE(fs::exists(log_path));
    REQUIRE(fs::exists(rotated_path));
    // Only a single backup is ever kept.
    CHECK_FALSE(fs::exists(dir / "keen-pbr.log.2"));

    const std::string rotated = read_file(rotated_path);
    const std::string active = read_file(log_path);

    // The earliest lines moved into the backup, the most recent stay active.
    CHECK(rotated.find("rotation-line-0000") != std::string::npos);
    CHECK(rotated.find("rotation-line-0009") != std::string::npos);
    CHECK(active.find("rotation-line-0010") != std::string::npos);
    CHECK(active.find("rotation-line-0018") != std::string::npos);

    // No line is lost or duplicated across the rotation boundary.
    CHECK(rotated.find("rotation-line-0010") == std::string::npos);
    CHECK(active.find("rotation-line-0009") == std::string::npos);
}

TEST_CASE("file sink keeps disk use bounded across repeated rotations") {
    const fs::path dir = make_temp_dir();
    LogFileSinkGuard guard(dir);
    const fs::path log_path = dir / "keen-pbr.log";
    const fs::path rotated_path = dir / "keen-pbr.log.1";

    Logger::instance().set_log_file_for_testing(log_path.string());
    Logger::instance().set_log_file_rotate_bytes_for_testing(256);

    // Many lines force several rotations; only the active file plus one backup
    // must ever exist, so total disk use stays bounded regardless of volume.
    for (int i = 0; i < 200; ++i) {
        Logger::instance().info("bounded-line-{:04}-padding-padding", i);
    }

    REQUIRE(fs::exists(log_path));
    REQUIRE(fs::exists(rotated_path));
    CHECK_FALSE(fs::exists(dir / "keen-pbr.log.2"));

    // Active file is bounded by the cap plus at most one trailing line.
    CHECK(fs::file_size(log_path) <= static_cast<std::uintmax_t>(256) * 2);
    CHECK(fs::file_size(rotated_path) <= static_cast<std::uintmax_t>(256) * 2);

    // The most recent line survives in the active file.
    const std::string active = read_file(log_path);
    CHECK(active.find("bounded-line-0199") != std::string::npos);
}

TEST_CASE("file sink rotation replaces a stale <path>.1 backup") {
    const fs::path dir = make_temp_dir();
    LogFileSinkGuard guard(dir);
    const fs::path log_path = dir / "keen-pbr.log";
    const fs::path rotated_path = dir / "keen-pbr.log.1";

    {
        std::ofstream stale(rotated_path, std::ios::binary);
        stale << "stale-backup-content\n";
    }

    Logger::instance().set_log_file_for_testing(log_path.string());
    Logger::instance().set_log_file_rotate_bytes_for_testing(200);

    for (int i = 0; i < 19; ++i) {
        Logger::instance().info("replace-stale-{:04}", i);
    }

    REQUIRE(fs::exists(rotated_path));
    const std::string rotated = read_file(rotated_path);
    // The stale backup is overwritten by the rotation, not preserved.
    CHECK(rotated.find("stale-backup-content") == std::string::npos);
    CHECK(rotated.find("replace-stale-0000") != std::string::npos);
}

TEST_CASE("file sink falls back silently when the file cannot be opened") {
    const fs::path dir = make_temp_dir();
    LogFileSinkGuard guard(dir);
    // Parent directory does not exist -> fopen fails. The logger must not throw.
    const fs::path bad_path = dir / "missing-subdir" / "keen-pbr.log";

    Logger::instance().set_log_file_for_testing(bad_path.string());
    CHECK_NOTHROW(Logger::instance().info("fallback-line-must-not-crash"));
    CHECK_FALSE(fs::exists(bad_path));
}

} // namespace keen_pbr3
