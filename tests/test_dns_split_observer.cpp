#include <doctest/doctest.h>

#include "../src/routing/dns_split_observer.hpp"
#include "../src/routing/dns_split_table.hpp"
#include "../src/routing/tcp_payload.hpp"

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <map>
#include <string>
#include <unistd.h>

using namespace keen_pbr3;

namespace {

constexpr uint32_t kVpn = 0x50000;
constexpr uint32_t kWan = 0x20000;

std::map<std::string, uint32_t> sample_marks() {
    return {
        {"youtube.com", kVpn},
        {"googlevideo.com", kVpn},
        {"drive.google.com", kWan},
    };
}

// A throwaway log file that cleans itself up.
struct TempLog {
    std::filesystem::path path;
    TempLog() {
        path = std::filesystem::temp_directory_path() /
               ("dns_split_obs_" + std::to_string(::getpid()) + "_" +
                std::to_string(reinterpret_cast<uintptr_t>(this)) + ".log");
        std::filesystem::remove(path);
    }
    ~TempLog() {
        std::error_code ec;
        std::filesystem::remove(path, ec);
    }
    void append(const std::string& text) {
        std::ofstream f(path, std::ios::app | std::ios::binary);
        f << text;
    }
    void truncate_to_empty() {
        std::ofstream f(path, std::ios::trunc | std::ios::binary);
    }
};

uint32_t key_of(const std::string& ip) {
    return *parse_ipv4_to_key(ip.data(), ip.size());
}

}  // namespace

TEST_CASE("dns_split_observer: missing log file is a benign no-op") {
    DnsSplitTable table;
    DnsSplitObserver obs("/nonexistent/path/forest-pbr-dns.log", sample_marks(), &table);
    CHECK(obs.tick() == 0);
    CHECK(table.size() == 0);
}

TEST_CASE("dns_split_observer: matching reply lines upsert (ip -> mark)") {
    TempLog log;
    log.append(
        "Jan  1 00:00:00 dnsmasq[1]: 1 192.168.1.5/5 reply drive.google.com is 142.250.1.2\n"
        "Jan  1 00:00:00 dnsmasq[1]: 2 192.168.1.5/5 reply rr3.googlevideo.com is 142.250.1.9\n");

    DnsSplitTable table;
    DnsSplitObserver obs(log.path.string(), sample_marks(), &table);

    CHECK(obs.tick() == 2);
    CHECK(table.lookup(key_of("142.250.1.2")) == kWan);   // drive -> WAN
    CHECK(table.lookup(key_of("142.250.1.9")) == kVpn);   // googlevideo -> VPN
}

TEST_CASE("dns_split_observer: unmatched domains and non-replies are skipped") {
    TempLog log;
    log.append(
        "reply example.org is 1.2.3.4\n"            // not in the rule lists
        "query[A] youtube.com from 192.168.1.5\n"  // not a reply
        "reply youtube.com is <NXDOMAIN>\n");      // negative answer

    DnsSplitTable table;
    DnsSplitObserver obs(log.path.string(), sample_marks(), &table);

    CHECK(obs.tick() == 0);
    CHECK(table.size() == 0);
}

TEST_CASE("dns_split_observer: reads incrementally across ticks") {
    TempLog log;
    DnsSplitTable table;
    DnsSplitObserver obs(log.path.string(), sample_marks(), &table);

    log.append("reply youtube.com is 10.0.0.1\n");
    CHECK(obs.tick() == 1);
    CHECK(table.lookup(key_of("10.0.0.1")) == kVpn);

    // Second tick must only see the newly-appended line, not re-process the old.
    log.append("reply drive.google.com is 10.0.0.2\n");
    CHECK(obs.tick() == 1);
    CHECK(table.lookup(key_of("10.0.0.2")) == kWan);
}

TEST_CASE("dns_split_observer: a partial trailing line is held until completed") {
    TempLog log;
    DnsSplitTable table;
    DnsSplitObserver obs(log.path.string(), sample_marks(), &table);

    log.append("reply youtube.com is 10.0.0");  // no newline yet
    CHECK(obs.tick() == 0);
    CHECK(table.size() == 0);

    log.append(".5\n");  // completes the line
    CHECK(obs.tick() == 1);
    CHECK(table.lookup(key_of("10.0.0.5")) == kVpn);
}

TEST_CASE("dns_split_observer: copytruncate rotation is detected and re-read") {
    TempLog log;
    DnsSplitTable table;
    DnsSplitObserver obs(log.path.string(), sample_marks(), &table);

    log.append("reply youtube.com is 10.0.0.1\n");
    CHECK(obs.tick() == 1);

    // logrotate copytruncate: the file is truncated in place. A tick now sees a
    // file shorter than our offset and resets to the start.
    log.truncate_to_empty();
    CHECK(obs.tick() == 0);  // nothing to read yet, but offset reset detected

    // dnsmasq resumes logging from the (now empty) file.
    log.append("reply drive.google.com is 10.0.0.9\n");
    CHECK(obs.tick() == 1);
    CHECK(table.lookup(key_of("10.0.0.9")) == kWan);
}

TEST_CASE("dns_split_observer: rename-based rotation (new inode) is re-read from start") {
    TempLog log;
    DnsSplitTable table;
    DnsSplitObserver obs(log.path.string(), sample_marks(), &table);

    log.append("reply youtube.com is 10.0.0.1\n");
    CHECK(obs.tick() == 1);

    // logrotate default: rename the live file away and create a fresh one at the
    // same path (new inode). The observer must reopen and read it from the start.
    std::error_code ec;
    std::filesystem::rename(log.path, log.path.string() + ".1", ec);
    REQUIRE_FALSE(static_cast<bool>(ec));
    log.append("reply drive.google.com is 10.0.0.9\n");  // creates a new file
    CHECK(obs.tick() == 1);
    CHECK(table.lookup(key_of("10.0.0.9")) == kWan);

    std::filesystem::remove(log.path.string() + ".1", ec);
}

TEST_CASE("dns_split_observer: null table is a safe no-op") {
    TempLog log;
    log.append("reply youtube.com is 10.0.0.1\n");
    DnsSplitObserver obs(log.path.string(), sample_marks(), nullptr);
    CHECK(obs.tick() == 0);
}
