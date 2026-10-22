#include <doctest/doctest.h>

#include "../src/routing/urltest_switch.hpp"

#include <chrono>
#include <string>

using namespace keen_pbr3;

TEST_CASE("classify_urltest_switch: first selection, failed path, healthy change") {
    CHECK(classify_urltest_switch(false, false) == UrltestSwitchReason::initial);
    CHECK(classify_urltest_switch(false, true) == UrltestSwitchReason::initial);
    CHECK(classify_urltest_switch(true, false) == UrltestSwitchReason::selected_path_unhealthy);
    CHECK(classify_urltest_switch(true, true) == UrltestSwitchReason::healthy_policy_change);
}

TEST_CASE("urltest_switch_reason_name: stable log names") {
    CHECK(std::string(urltest_switch_reason_name(UrltestSwitchReason::initial)) == "initial");
    CHECK(std::string(urltest_switch_reason_name(UrltestSwitchReason::selected_path_unhealthy)) ==
          "selected-path-unhealthy");
    CHECK(std::string(urltest_switch_reason_name(UrltestSwitchReason::healthy_policy_change)) ==
          "healthy-policy-change");
}

TEST_CASE("urltest_flush_retry_delay: bounded backoff") {
    CHECK(kMaxUrltestFlushRetries == 3);
    CHECK(urltest_flush_retry_delay(0) == std::chrono::seconds{5});
    CHECK(urltest_flush_retry_delay(1) == std::chrono::seconds{15});
    CHECK(urltest_flush_retry_delay(2) == std::chrono::seconds{45});
    // Never grows past the last retry's delay.
    CHECK(urltest_flush_retry_delay(10) == std::chrono::seconds{135});
}
