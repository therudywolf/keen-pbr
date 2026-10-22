#include <doctest/doctest.h>

#include "../src/daemon/guarded_invoke.hpp"

#include <stdexcept>
#include <string>

using namespace keen_pbr3;

TEST_CASE("invoke_guarded: a successful callback reports no error") {
    bool ran = false;
    const auto error = invoke_guarded([&ran]() { ran = true; });
    CHECK(ran);
    CHECK_FALSE(error.has_value());
}

TEST_CASE("invoke_guarded: a std::exception becomes its message") {
    const auto error = invoke_guarded([]() { throw std::runtime_error("list warmer exploded"); });
    REQUIRE(error.has_value());
    CHECK(*error == "list warmer exploded");
}

TEST_CASE("invoke_guarded: a non-std exception is reported as unknown") {
    const auto error = invoke_guarded([]() { throw 42; });
    REQUIRE(error.has_value());
    CHECK(*error == "unknown error");
}

TEST_CASE("RepeatingTaskFailures: only consecutive failures disable a task") {
    RepeatingTaskFailures failures;
    CHECK_FALSE(failures.record(true));
    CHECK_FALSE(failures.record(true));
    CHECK(failures.consecutive() == 2);

    // A successful run resets the streak.
    CHECK_FALSE(failures.record(false));
    CHECK(failures.consecutive() == 0);

    CHECK_FALSE(failures.record(true));
    CHECK_FALSE(failures.record(true));
    CHECK(failures.record(true));
    CHECK(failures.consecutive() == RepeatingTaskFailures::kMaxConsecutiveFailures);
}
