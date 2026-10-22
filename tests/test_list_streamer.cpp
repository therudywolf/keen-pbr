#include <doctest/doctest.h>

#include "../src/lists/list_streamer.hpp"
#include "../src/log/logger.hpp"

#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace keen_pbr3 {
namespace {

class TempDirectory {
public:
    TempDirectory() {
        char pattern[] = "/tmp/forest-pbr-list-streamer-XXXXXX";
        const char* value = ::mkdtemp(pattern);
        if (!value) throw std::runtime_error("mkdtemp failed");
        path_ = value;
    }
    ~TempDirectory() {
        std::error_code ec;
        std::filesystem::remove_all(path_, ec);
    }
    const std::filesystem::path& path() const { return path_; }

private:
    std::filesystem::path path_;
};

class RecordingVisitor : public ListEntryVisitor {
public:
    void on_entry(EntryType type, std::string_view entry) override {
        entries.emplace_back(type, std::string(entry));
    }
    std::vector<std::pair<EntryType, std::string>> entries;
};

struct WarningCapture {
    WarningCapture() : previous_level(Logger::instance().level()) {
        ListParser::reset_reported_invalid_entries_for_tests();
        Logger::instance().set_level(LogLevel::warn);
        Logger::instance().set_sink([this](const std::string& line) {
            log += line;
            log.push_back('\n');
        });
    }
    ~WarningCapture() {
        Logger::instance().clear_sink();
        Logger::instance().set_level(previous_level);
        ListParser::reset_reported_invalid_entries_for_tests();
    }
    LogLevel previous_level;
    std::string log;
};

std::vector<std::pair<EntryType, std::string>> stream_local(const std::filesystem::path& path) {
    CacheManager cache(path.parent_path() / "cache");
    ListStreamer streamer(cache);
    ListConfig config;
    config.file = path.string();
    RecordingVisitor visitor;
    streamer.stream_list("local", config, visitor);
    return visitor.entries;
}

} // namespace

TEST_CASE("ListStreamer reads regular local files") {
    TempDirectory temp;
    const auto path = temp.path() / "list.txt";
    { std::ofstream out(path); out << "example.com\n192.0.2.0/24\n# comment\n\nlast.example"; }

    const auto entries = stream_local(path);
    REQUIRE(entries.size() == 3);
    CHECK(entries[0] == std::make_pair(EntryType::Domain, std::string("example.com")));
    CHECK(entries[1] == std::make_pair(EntryType::Cidr, std::string("192.0.2.0/24")));
    CHECK(entries[2] == std::make_pair(EntryType::Domain, std::string("last.example")));
}

TEST_CASE("ListStreamer rejects FIFOs and devices without blocking") {
    TempDirectory temp;
    const auto fifo = temp.path() / "fifo";
    REQUIRE(::mkfifo(fifo.c_str(), 0600) == 0);

    CHECK_THROWS_AS(stream_local(fifo), std::runtime_error);
    CHECK_THROWS_AS(stream_local("/dev/zero"), std::runtime_error);
    CHECK_THROWS_AS(stream_local(temp.path() / "missing.txt"), std::runtime_error);
}

TEST_CASE("ListStreamer follows symlinks to regular list files") {
    TempDirectory temp;
    const auto regular = temp.path() / "regular.txt";
    const auto symlink = temp.path() / "symlink.txt";
    { std::ofstream out(regular); out << "example.com\n"; }
    std::filesystem::create_symlink(regular, symlink);

    CHECK(stream_local(symlink).size() == 1);
}

TEST_CASE("ListStreamer skips overlong lines and keeps the rest of the list") {
    WarningCapture capture;
    TempDirectory temp;
    const auto path = temp.path() / "long-line.txt";
    {
        std::ofstream out(path);
        out << "first.example\n"
            << std::string(ListStreamer::kMaxLineBytes + 1, 'a') << "\n"
            << std::string(ListStreamer::kMaxLineBytes, 'b') << "\n"
            << "second.example\n"
            << std::string(3 * ListStreamer::kMaxLineBytes, 'c');
    }

    const auto entries = stream_local(path);
    REQUIRE(entries.size() == 2);
    CHECK(entries[0].second == "first.example");
    CHECK(entries[1].second == "second.example");
    CHECK(capture.log.find("longer than 4096 bytes in " + path.string() + " at line 2") !=
          std::string::npos);
    // A line of exactly kMaxLineBytes is parsed (and rejected as a domain),
    // not treated as overlong.
    CHECK(capture.log.find("at line 3") != std::string::npos);
    CHECK(capture.log.find("longer than 4096 bytes in " + path.string() + " at line 5") !=
          std::string::npos);
}

TEST_CASE("ListStreamer parses inline entries like file entries") {
    WarningCapture capture;
    CacheManager cache("/nonexistent/cache");
    ListStreamer streamer(cache);
    ListConfig config;
    config.ip_cidrs = std::vector<std::string>{"10.0.0.0/8", " 192.0.2.1 ", "", "# note"};
    config.domains = std::vector<std::string>{
        "*.example.com", "plain.example.", "24.105.30.0/24", "bad/domain",
        "evil.example\nserver=/x/1.1.1.1", "   "};
    RecordingVisitor visitor;
    streamer.stream_list("mixed", config, visitor);

    REQUIRE(visitor.entries.size() == 5);
    CHECK(visitor.entries[0] == std::make_pair(EntryType::Cidr, std::string("10.0.0.0/8")));
    CHECK(visitor.entries[1] == std::make_pair(EntryType::Ip, std::string("192.0.2.1")));
    CHECK(visitor.entries[2] == std::make_pair(EntryType::Domain, std::string("example.com")));
    CHECK(visitor.entries[3] == std::make_pair(EntryType::Domain, std::string("plain.example")));
    // A CIDR listed among the domains is routed as a CIDR, not handed to
    // dnsmasq as a bogus domain.
    CHECK(visitor.entries[4] == std::make_pair(EntryType::Cidr, std::string("24.105.30.0/24")));
    CHECK(capture.log.find("'bad/domain' in inline list 'mixed'") != std::string::npos);
    CHECK(capture.log.find("'evil.example\\nserver=/x/1.1.1.1'") != std::string::npos);
}

TEST_CASE("ListStreamer does not log junk lines of downloaded caches") {
    WarningCapture capture;
    TempDirectory temp;
    CacheManager cache(temp.path());
    cache.ensure_dir();
    { std::ofstream out(cache.cache_path("remote")); out << "example.com\n<html>junk</html>\n"; }

    ListStreamer streamer(cache);
    ListConfig config;
    config.url = "https://example.com/list.txt";
    RecordingVisitor visitor;
    streamer.stream_list("remote", config, visitor);

    REQUIRE(visitor.entries.size() == 1);
    CHECK(visitor.entries[0].second == "example.com");
    CHECK(capture.log.empty());
}

} // namespace keen_pbr3
