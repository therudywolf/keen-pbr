#pragma once

#include <cstddef>
#include <istream>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "../lists/list_entry_visitor.hpp"

namespace keen_pbr3 {

class ListParser {
public:
    // Lines longer than this are skipped with a warning, never truncated.
    static constexpr std::size_t kMaxLineBytes = 4096;
    // Malformed entries reported in detail per source and pass; the rest
    // are summed up in one line.
    static constexpr std::size_t kMaxDetailedInvalidEntries = 5;

    // Per-source state for parse_line(). Malformed entries never fail a
    // list, they are skipped. Their warnings are collected here and written
    // by finish_source(), which stays silent when the same source yields the
    // same malformed entries as in its previous pass: lists are re-streamed
    // on every firewall refresh (on Keenetic about once a minute), and
    // repeating identical warnings would flood the rotating log file.
    struct ParseContext {
        bool log_invalid_entries{true};
        std::size_t invalid_entry_count{0};
        std::size_t invalid_entries_signature{0};
        std::vector<std::string> pending_warnings;
    };

    // Stream-parse from an istream, dispatching each entry to the visitor.
    static void stream_parse(std::istream& input,
                             ListEntryVisitor& visitor,
                             std::string_view source_name = {});

    // Classify a single trimmed entry and dispatch to the visitor.
    // Returns true if the entry was recognized and dispatched.
    static bool classify_entry(std::string_view entry, ListEntryVisitor& visitor);

    // Trim one line or inline entry, skip blanks and '#' comments and
    // dispatch the entry. A malformed entry is recorded in `context`; without
    // a context it is logged right away.
    static void parse_line(std::string_view line,
                           ListEntryVisitor& visitor,
                           std::string_view source_name,
                           std::size_t line_number,
                           ParseContext* context = nullptr);

    // Record a line that was skipped for exceeding kMaxLineBytes.
    static void report_overlong_line(std::string_view source_name,
                                     std::size_t line_number,
                                     ParseContext& context);

    // Write the warnings collected for one pass over `source_name`.
    static void finish_source(std::string_view source_name, ParseContext& context);

    // Validate and normalize a DNS-compatible domain. Leading "*." and one
    // trailing root dot are removed from the returned value.
    static std::optional<std::string> normalize_domain(std::string_view domain);

#ifdef KEEN_PBR3_TESTING
    // Forget which malformed entries were already reported.
    static void reset_reported_invalid_entries_for_tests();
#endif

private:
    static bool is_ipv4(std::string_view s);
    static bool is_ipv6(std::string_view s);
    static bool is_cidr_v4(std::string_view s);
    static bool is_cidr_v6(std::string_view s);
};

} // namespace keen_pbr3
