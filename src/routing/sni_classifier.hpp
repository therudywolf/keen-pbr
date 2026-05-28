#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace keen_pbr3 {

// Maps an SNI hostname to the fwmark of the outbound it should use, by reusing
// the same list/rule structure that drives ipset-based routing. This is the
// hostname-side twin of the ipset match: where the firewall matches a packet's
// dst IP against kpbrm_X, this matches the TLS SNI against the domains that
// populate those same lists — so a flow can be routed by NAME even when the IP
// is shared (drive.google.com vs www.youtube.com on one Google edge).
//
// Pure and table-driven: the daemon builds the (domain -> mark) tables from
// config once, the NFQUEUE handler calls classify() per connection.
class SniClassifier {
public:
    // Build from a domain->mark mapping. `domain_marks` keys are bare domains
    // (no leading "*."). A hostname matches a domain if it equals the domain
    // or is a sub-label of it (foo.bar.com matches bar.com). The most specific
    // (longest) matching domain wins, so a more-specific rule can override a
    // broader one.
    explicit SniClassifier(std::map<std::string, uint32_t> domain_marks);

    // Returns the mark for the best (longest) domain that `hostname` falls
    // under, or nullopt when no configured domain matches (caller then leaves
    // the flow to IP-based routing / default).
    std::optional<uint32_t> classify(const std::string& hostname) const;

    std::size_t size() const { return exact_.size(); }

private:
    // domain -> mark. Lookup walks parent suffixes of the hostname.
    std::map<std::string, uint32_t> exact_;
};

}  // namespace keen_pbr3
