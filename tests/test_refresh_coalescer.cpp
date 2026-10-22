#include <doctest/doctest.h>

#include "../src/daemon/refresh_coalescer.hpp"

#include <chrono>
#include <optional>
#include <vector>

using namespace keen_pbr3;
using std::chrono::milliseconds;

namespace {

constexpr milliseconds kLeading{1};
constexpr milliseconds kGap{1500};

RefreshCoalescer::Clock::time_point at(milliseconds offset) {
    return RefreshCoalescer::Clock::time_point{} + std::chrono::hours{1} + offset;
}

} // namespace

TEST_CASE("RefreshCoalescer: the first trigger refreshes almost at once") {
    RefreshCoalescer coalescer(kLeading, kGap);
    const auto delay = coalescer.on_trigger(at(milliseconds{0}));
    REQUIRE(delay.has_value());
    CHECK(*delay == kLeading);
    CHECK(coalescer.pending());

    // Anything before the refresh runs is covered by it.
    CHECK_FALSE(coalescer.on_trigger(at(milliseconds{0})).has_value());
    CHECK_FALSE(coalescer.on_trigger(at(milliseconds{1})).has_value());
}

TEST_CASE("RefreshCoalescer: triggers right after a refresh fold into one trailing refresh") {
    RefreshCoalescer coalescer(kLeading, kGap);
    REQUIRE(coalescer.on_trigger(at(milliseconds{0})).has_value());
    coalescer.on_refresh_started(at(milliseconds{1}));
    coalescer.on_refresh_finished(at(milliseconds{101}));

    // 0.5 s later: due at the end of the gap counted from the finish.
    const auto trailing = coalescer.on_trigger(at(milliseconds{500}));
    REQUIRE(trailing.has_value());
    CHECK(*trailing == milliseconds{1101});
    CHECK_FALSE(coalescer.on_trigger(at(milliseconds{900})).has_value());
    CHECK_FALSE(coalescer.on_trigger(at(milliseconds{1500})).has_value());
}

TEST_CASE("RefreshCoalescer: a trigger after the quiet window refreshes at once again") {
    RefreshCoalescer coalescer(kLeading, kGap);
    REQUIRE(coalescer.on_trigger(at(milliseconds{0})).has_value());
    coalescer.on_refresh_started(at(milliseconds{1}));
    coalescer.on_refresh_finished(at(milliseconds{50}));

    const auto delay = coalescer.on_trigger(at(milliseconds{5000}));
    REQUIRE(delay.has_value());
    CHECK(*delay == kLeading);
}

TEST_CASE("RefreshCoalescer: a slow refresh is not followed back to back") {
    RefreshCoalescer coalescer(kLeading, kGap);
    REQUIRE(coalescer.on_trigger(at(milliseconds{0})).has_value());
    coalescer.on_refresh_started(at(milliseconds{1}));
    // The refresh took longer than the gap (weak CPU).
    coalescer.on_refresh_finished(at(milliseconds{2000}));

    const auto delay = coalescer.on_trigger(at(milliseconds{2100}));
    REQUIRE(delay.has_value());
    CHECK(*delay == milliseconds{1400});
}

TEST_CASE("RefreshCoalescer: a steady trigger stream cannot postpone the refresh forever") {
    RefreshCoalescer coalescer(kLeading, kGap);
    std::optional<milliseconds> due;
    std::vector<milliseconds> refreshes;

    // A trigger every 100 ms for 10 s, refreshes taking 200 ms. The old
    // restart-the-timer debounce never fired in this situation.
    for (milliseconds now{0}; now <= milliseconds{10000}; now += milliseconds{50}) {
        if (due && *due <= now) {
            due.reset();
            coalescer.on_refresh_started(at(now));
            refreshes.push_back(now);
            coalescer.on_refresh_finished(at(now + milliseconds{200}));
        }
        if (now.count() % 100 == 0) {
            if (const auto delay = coalescer.on_trigger(at(now))) {
                due = now + *delay;
            }
        }
    }

    REQUIRE(refreshes.size() >= 5);
    CHECK(refreshes.front() <= milliseconds{50});
    for (size_t i = 1; i < refreshes.size(); ++i) {
        const auto gap = refreshes[i] - refreshes[i - 1];
        CHECK(gap >= kGap);
        CHECK(gap <= kGap + milliseconds{300});
    }
}

TEST_CASE("RefreshCoalescer: cancel drops the pending refresh but keeps the quiet window") {
    RefreshCoalescer coalescer(kLeading, kGap);
    REQUIRE(coalescer.on_trigger(at(milliseconds{0})).has_value());
    coalescer.on_refresh_started(at(milliseconds{1}));
    coalescer.on_refresh_finished(at(milliseconds{1}));
    REQUIRE(coalescer.on_trigger(at(milliseconds{100})).has_value());
    CHECK(coalescer.pending());

    coalescer.cancel();
    CHECK_FALSE(coalescer.pending());
    const auto delay = coalescer.on_trigger(at(milliseconds{200}));
    REQUIRE(delay.has_value());
    CHECK(*delay == milliseconds{1301});
}
