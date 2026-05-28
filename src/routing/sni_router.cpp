#include "sni_router.hpp"

#include <utility>

#include "sni_parser.hpp"

namespace keen_pbr3 {

SniRouter::SniRouter(std::map<std::string, uint32_t> domain_marks)
    : classifier_(std::move(domain_marks)) {}

SniDecision SniRouter::decide(const uint8_t* tcp_payload, std::size_t len) const {
    const SniParseResult parsed = parse_tls_sni(tcp_payload, len);
    switch (parsed.status) {
        case SniParseStatus::Found: {
            SniDecision d;
            d.hostname = parsed.hostname;
            if (const auto mark = classifier_.classify(parsed.hostname)) {
                d.action = SniAction::SetMark;
                d.mark = *mark;
            } else {
                // Known TLS host but no configured rule: leave it to IP routing.
                d.action = SniAction::Accept;
            }
            return d;
        }
        case SniParseStatus::NeedMoreData:
            return SniDecision{SniAction::NeedMoreData, 0, {}};
        case SniParseStatus::NoSni:
        case SniParseStatus::NotTls:
        default:
            return SniDecision{SniAction::Accept, 0, {}};
    }
}

}  // namespace keen_pbr3
