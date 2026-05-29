#pragma once

#include <cstdint>
#include <map>
#include <string>

#include "../routing/sni_classifier.hpp"

namespace keen_pbr3 {

class DnsSplitTable;

// DNS-correlation split-routing observer (DNS-split v1).
// ======================================================
// Tails the dnsmasq reply log (written because keen-pbr injects
// log-queries=extra + log-facility only when dns_split_enabled) and, for each
// `reply <domain> is <ipv4>` line, resolves the domain to an outbound fwmark via
// a SniClassifier built once from the route-rule lists. When the domain matches
// a rule, it upserts (resolved-IPv4 -> mark) into the shared DnsSplitTable that
// the NFQUEUE SYN handler consults. This is what lets two domains sharing one
// CDN IP take different outbounds: the mark follows the NAME the client just
// resolved, applied at connection setup so flows never break mid-stream.
//
// SAFETY — zero behavior unless explicitly enabled
// ------------------------------------------------
// The daemon only constructs and schedules this worker when
// daemon.dns_split_enabled == true. There is no fallback that tails any file by
// default; in the default config the worker does not exist, no file is opened,
// and the table stays empty.
//
// Lifecycle mirrors ListWarmer / AutohealWorker: the Daemon owns one instance,
// (re)creates it on every config apply while the feature is enabled, and drives
// tick() from a repeating Scheduler task. The observer reads incrementally from
// its last byte offset, tolerating the file being absent (dnsmasq not yet
// restarted), truncated, or rotated (re-reads from the start on shrink). tick()
// never throws — I/O failures are logged and the next tick retries.
class DnsSplitObserver {
public:
    // log_path:  the dnsmasq log-facility file to tail.
    // domain_marks: bare-domain -> outbound fwmark, built from the route rules.
    // table:     shared correlation table the NFQUEUE handler reads (not owned).
    DnsSplitObserver(std::string log_path,
                     std::map<std::string, uint32_t> domain_marks,
                     DnsSplitTable* table);
    ~DnsSplitObserver();

    DnsSplitObserver(const DnsSplitObserver&) = delete;
    DnsSplitObserver& operator=(const DnsSplitObserver&) = delete;

    // Read everything appended since the previous tick, parse reply lines,
    // classify, and upsert matches into the table. Also expires stale entries.
    // Returns the number of (ip -> mark) correlations upserted this tick.
    // Never throws.
    int tick() noexcept;

    // Test/observability accessor: number of domains in the classifier.
    std::size_t domain_count() const { return classifier_.size(); }

private:
    // Open (or reopen) the log file and seek to offset_. Returns false when the
    // file cannot be opened (e.g. dnsmasq has not created it yet).
    bool ensure_open();

    std::string log_path_;
    SniClassifier classifier_;
    DnsSplitTable* table_;

    int fd_{-1};
    std::uint64_t inode_{0};    // st_ino of the currently-open file (0 = none)
    std::uint64_t offset_{0};   // bytes consumed so far
    std::string carry_;         // bytes after the last newline, awaiting more
};

}  // namespace keen_pbr3
