#include <doctest/doctest.h>

#include <optional>
#include <sstream>

#include "../src/config/list_parser.hpp"
#include "../src/lists/list_entry_visitor.hpp"

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
