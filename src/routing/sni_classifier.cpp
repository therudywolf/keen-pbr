#include "sni_classifier.hpp"

#include <algorithm>
#include <cctype>

namespace keen_pbr3 {

namespace {

std::string strip_wildcard_lower(std::string d) {
    // Drop a leading "*." (dnsmasq-style wildcard) and lowercase.
    if (d.size() > 2 && d[0] == '*' && d[1] == '.') {
        d = d.substr(2);
    }
    for (char& c : d) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    if (!d.empty() && d.back() == '.') {
        d.pop_back();
    }
    return d;
}

}  // namespace

SniClassifier::SniClassifier(std::map<std::string, uint32_t> domain_marks) {
    for (auto& [domain, mark] : domain_marks) {
        std::string d = strip_wildcard_lower(domain);
        if (!d.empty()) {
            exact_[d] = mark;
        }
    }
}

std::optional<uint32_t> SniClassifier::classify(const std::string& hostname) const {
    if (hostname.empty() || exact_.empty()) {
        return std::nullopt;
    }

    std::string host = hostname;
    for (char& c : host) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    if (!host.empty() && host.back() == '.') {
        host.pop_back();
    }

    // Walk from the full hostname up through its parent suffixes:
    //   a.b.example.com -> b.example.com -> example.com -> com
    // The first (longest / most specific) match wins.
    std::string candidate = host;
    while (true) {
        auto it = exact_.find(candidate);
        if (it != exact_.end()) {
            return it->second;
        }
        const auto dot = candidate.find('.');
        if (dot == std::string::npos) {
            break;
        }
        candidate = candidate.substr(dot + 1);
    }
    return std::nullopt;
}

}  // namespace keen_pbr3
