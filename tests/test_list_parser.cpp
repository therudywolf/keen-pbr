#include <doctest/doctest.h>

#include <optional>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "../src/config/list_parser.hpp"
#include "../src/lists/list_entry_visitor.hpp"
#include "../src/log/logger.hpp"

using namespace keen_pbr3;

namespace {

// Records every entry classify_entry()/stream_parse() dispatches.
struct RecordingVisitor final : ListEntryVisitor {
    void on_entry(EntryType type, std::string_view /*entry*/) override {
        last_type = type;
        ++count;
    }

    std::optional<EntryType> last_type;
    int count = 0;
};

// Classify a single entry, returning its type or nullopt when the parser
// does not recognize it.
std::optional<EntryType> classify(std::string_view entry) {
    RecordingVisitor visitor;
    if (!ListParser::classify_entry(entry, visitor)) {
        return std::nullopt;
    }
    return visitor.last_type;
}

} // namespace

TEST_CASE("ListParser::classify_entry recognizes IPs, CIDRs, and domains") {
    CHECK(classify("10.0.0.1") == EntryType::Ip);
    CHECK(classify("2001:db8::1") == EntryType::Ip);
    CHECK(classify("10.0.0.0/8") == EntryType::Cidr);
    CHECK(classify("2001:db8::/32") == EntryType::Cidr);
    CHECK(classify("example.com") == EntryType::Domain);
    CHECK(classify("*.example.com") == EntryType::Domain);
}

TEST_CASE("ListParser::classify_entry rejects unrecognized entries") {
    RecordingVisitor visitor;
    CHECK_FALSE(ListParser::classify_entry("not a valid entry", visitor));
    CHECK_FALSE(ListParser::classify_entry("", visitor));
    CHECK(visitor.count == 0);
}

TEST_CASE("ListParser::stream_parse skips comments and blank lines") {
    std::istringstream input(
        "\n"
        "\n"
        "# comment\n"
        "10.0.0.1\n"
        "192.168.0.0/24\n"
        "\n"
        "example.com\n");

    EntryCounter counter;
    ListParser::stream_parse(input, counter);

    CHECK(counter.ips() == 1);
    CHECK(counter.cidrs() == 1);
    CHECK(counter.domains() == 1);
    CHECK(counter.total() == 3);
}

TEST_CASE("ListParser::stream_parse drops unrecognized lines silently") {
    std::istringstream input("10.0.0.1\nnot a valid entry\nexample.com\n");

    EntryCounter counter;
    ListParser::stream_parse(input, counter);

    // The invalid middle line is skipped, never dispatched to the visitor.
    CHECK(counter.total() == 2);
    CHECK(counter.ips() == 1);
    CHECK(counter.domains() == 1);
}

namespace {

// Records the entries themselves, for normalization checks.
struct EntryRecorder final : ListEntryVisitor {
    void on_entry(EntryType type, std::string_view entry) override {
        entries.emplace_back(type, std::string(entry));
    }

    std::vector<std::pair<EntryType, std::string>> entries;
};

// Captures warn-level log lines for the duration of a test case and makes
// the "already reported" memory of malformed entries start empty.
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

    std::size_t count(const std::string& needle) const {
        std::size_t found = 0;
        for (auto pos = log.find(needle); pos != std::string::npos;
             pos = log.find(needle, pos + needle.size())) {
            ++found;
        }
        return found;
    }

    LogLevel previous_level;
    std::string log;
};

} // namespace

TEST_CASE("ListParser normalizes wildcard and root-dot domains") {
    EntryRecorder visitor;
    CHECK(ListParser::classify_entry("*.google.com", visitor));
    CHECK(ListParser::classify_entry("_dns._udp.example.com.", visitor));
    REQUIRE(visitor.entries.size() == 2);
    CHECK(visitor.entries[0].second == "google.com");
    CHECK(visitor.entries[1].second == "_dns._udp.example.com");
}

TEST_CASE("ListParser applies identical domain rules to streamed sources") {
    WarningCapture capture;
    std::istringstream input(
        "*.google.com\n"
        "valid_example.test.\n"
        "bad/domain.test\n"
        "bad label.test\n"
        "-bad.example\n");
    EntryRecorder visitor;
    ListParser::stream_parse(input, visitor, "test-list");
    REQUIRE(visitor.entries.size() == 2);
    CHECK(visitor.entries[0].second == "google.com");
    CHECK(visitor.entries[1].second == "valid_example.test");
    CHECK(capture.count("Skipping invalid list entry") == 3);
}

TEST_CASE("ListParser rejects malformed DNS labels") {
    const std::vector<std::string> invalid = {
             "", "*", "*.*.example.com", "example..com", ".example.com",
             "example.com..", "bad-.example", "-bad.example",
             std::string(64, 'a') + ".example",
             "example.com\nserver=/evil/1.1.1.1",
             "www.capcut.com/editor", "yandex.net:443",
             "chatgpt-async-webps-prod-*.webpubsub.azure.com"};
    for (const std::string& value : invalid) {
        CAPTURE(value);
        CHECK_FALSE(ListParser::normalize_domain(value).has_value());
    }
    CHECK(ListParser::normalize_domain(std::string(63, 'a') + ".example").has_value());
    CHECK_FALSE(ListParser::normalize_domain(std::string(250, 'a') + ".com").has_value());
}

TEST_CASE("ListParser skips blank and comment entries") {
    std::istringstream input(
        "\n"
        "   \t\r\n"
        "  # comment\n"
        "example.com\n");
    EntryRecorder visitor;
    ListParser::stream_parse(input, visitor, "test-list");
    REQUIRE(visitor.entries.size() == 1);
    CHECK(visitor.entries[0].second == "example.com");
}

TEST_CASE("ListParser limits malformed-entry warnings per source") {
    WarningCapture capture;
    EntryRecorder visitor;
    ListParser::ParseContext context;
    for (std::size_t line = 1; line <= 7; ++line) {
        ListParser::parse_line("bad/domain" + std::to_string(line), visitor,
                               "limited-test-list", line, &context);
    }
    ListParser::finish_source("limited-test-list", context);

    CHECK(capture.log.find("Skipping invalid list entry 'bad/domain1' in limited-test-list") !=
          std::string::npos);
    CHECK(capture.log.find("Skipping invalid list entry 'bad/domain5' in limited-test-list") !=
          std::string::npos);
    CHECK(capture.log.find("'bad/domain6'") == std::string::npos);
    CHECK(capture.log.find("Too many invalid list entries in limited-test-list: skipped 7") !=
          std::string::npos);
    CHECK(visitor.entries.empty());
}

TEST_CASE("ListParser reports the same malformed entries only once across passes") {
    WarningCapture capture;
    const auto parse_pass = [](const std::string& text) {
        std::istringstream input(text);
        EntryCounter counter;
        ListParser::stream_parse(input, counter, "refreshed-list");
        return counter.total();
    };

    // Firewall refreshes re-stream every list; an unchanged list must not
    // repeat its warnings each time.
    CHECK(parse_pass("example.com\nbad entry\n") == 1);
    CHECK(parse_pass("example.com\nbad entry\n") == 1);
    CHECK(parse_pass("example.com\nbad entry\n") == 1);
    CHECK(capture.count("Skipping invalid list entry 'bad entry'") == 1);

    // A changed set of malformed entries is reported again.
    CHECK(parse_pass("example.com\nbad entry\nother bad\n") == 1);
    CHECK(capture.count("Skipping invalid list entry 'bad entry'") == 2);
    CHECK(capture.count("'other bad'") == 1);
}

TEST_CASE("ListParser escapes malformed entries in warnings") {
    WarningCapture capture;
    EntryRecorder visitor;
    ListParser::parse_line(std::string("evil.example\nserver=/x/1.1.1.1"), visitor,
                           "escape-test", 1);
    CHECK(visitor.entries.empty());
    CHECK(capture.log.find("'evil.example\\nserver=/x/1.1.1.1'") != std::string::npos);
    CHECK(capture.count("\n") == 1);
}

TEST_CASE("ListParser skips overlong lines instead of failing the list") {
    WarningCapture capture;
    std::istringstream input("first.example\n" + std::string(ListParser::kMaxLineBytes + 1, 'a') +
                             "\nsecond.example\n");
    EntryRecorder visitor;
    ListParser::stream_parse(input, visitor, "overlong-list");
    REQUIRE(visitor.entries.size() == 2);
    CHECK(visitor.entries[0].second == "first.example");
    CHECK(visitor.entries[1].second == "second.example");
    CHECK(capture.log.find("Skipping list line longer than 4096 bytes in overlong-list at line 2") !=
          std::string::npos);
}
