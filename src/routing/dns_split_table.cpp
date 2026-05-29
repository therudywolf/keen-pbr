#include "dns_split_table.hpp"

namespace keen_pbr3 {

DnsSplitTable::DnsSplitTable(std::chrono::seconds ttl) : ttl_(ttl) {}

void DnsSplitTable::upsert(uint32_t ipv4, uint32_t mark, Clock::time_point now) {
    std::lock_guard<std::mutex> lock(mu_);
    map_[ipv4] = Entry{mark, now};
}

std::optional<uint32_t> DnsSplitTable::lookup(uint32_t ipv4, Clock::time_point now) {
    std::lock_guard<std::mutex> lock(mu_);
    auto it = map_.find(ipv4);
    if (it == map_.end()) {
        return std::nullopt;
    }
    if (now - it->second.stamped_at > ttl_) {
        // Stale: drop it and behave as if absent (fail-open to IP routing).
        map_.erase(it);
        return std::nullopt;
    }
    return it->second.mark;
}

std::size_t DnsSplitTable::expire(Clock::time_point now) {
    std::lock_guard<std::mutex> lock(mu_);
    std::size_t removed = 0;
    for (auto it = map_.begin(); it != map_.end();) {
        if (now - it->second.stamped_at > ttl_) {
            it = map_.erase(it);
            ++removed;
        } else {
            ++it;
        }
    }
    return removed;
}

void DnsSplitTable::clear() {
    std::lock_guard<std::mutex> lock(mu_);
    map_.clear();
}

std::size_t DnsSplitTable::size() const {
    std::lock_guard<std::mutex> lock(mu_);
    return map_.size();
}

}  // namespace keen_pbr3
