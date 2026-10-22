#pragma once

#include "firewall.hpp"

#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

namespace keen_pbr3 {

class IptablesFirewall : public Firewall {
public:
    // Initialize the iptables backend; does not modify firewall state yet.
    IptablesFirewall();
    // Destructor performs best-effort cleanup without virtual dispatch.
    ~IptablesFirewall() override;

    // Buffer an ipset create command (hash:net family, optional timeout).
    void create_ipset(const std::string& set_name, int family,
                      uint32_t timeout = 0) override;

    // Buffer an iptables/ip6tables -j MARK --set-mark rule for the given ipset.
    void create_mark_rule(uint32_t fwmark,
                          const FirewallRuleCriteria& criteria = {}) override;
    // Buffer an iptables/ip6tables -j DROP rule for the given criteria.
    void create_drop_rule(const FirewallRuleCriteria& criteria = {}) override;
    // Buffer an iptables/ip6tables -j RETURN rule for the given criteria.
    void create_pass_rule(const FirewallRuleCriteria& criteria = {}) override;

    // Return an IpsetRestoreVisitor that appends 'add' lines to the pending
    // element buffer for set_name; entries are flushed during apply().
    std::unique_ptr<ListEntryVisitor> create_batch_loader(
        const std::string& set_name) override;

    // Atomically apply all pending ipsets (via ipset restore) and rules
    // (via iptables-restore / ip6tables-restore), always materializing the
    // KeenPbrTable chain scaffold and PREROUTING jump for diagnostics.
    // RulesOnly skips the sets entirely (after checking them) and rebuilds
    // each chain in one iptables-restore transaction, without the window
    // in which the jump and chain are deleted.
    void apply(FirewallApplyMode mode = FirewallApplyMode::Destructive) override;
    // Destroy all buffered ipsets (ipset destroy) and flush/delete the
    // KeenPbrTable chain from both iptables and ip6tables mangle tables.
    void cleanup() override;
    // Returns FirewallBackend::iptables.
    FirewallBackend backend() const override;

private:
    static constexpr const char* CHAIN_NAME = "KeenPbrTable";
    void cleanup_live_impl();
    void cleanup_impl();
    void cleanup_rules_impl();

    // Describes a hash:net set to be created via 'ipset restore'.
    struct PendingSet {
        std::string name;
        std::string family_str; // "inet" or "inet6"
        uint32_t timeout;       // entry TTL in seconds (0 = no timeout)
    };

    // Describes a list:set set (a set whose members are other ipsets) created
    // to back one consolidated mangle rule. Must be created after its members.
    struct PendingListSet {
        std::string name;
        std::vector<std::string> members; // contained per-list ipset names
    };

    // Layout of one live set as reported by `ipset list -t`.
    struct LiveSetInfo {
        std::string type;                  // "hash:net", "list:set", ...
        std::string family;                // "inet" / "inet6" (hash types)
        std::optional<uint32_t> timeout;   // present when created with a timeout
        std::optional<size_t> entries;     // "Number of entries", if reported
    };

    // Describes an iptables/ip6tables rule to be added to KeenPbrTable.
    struct PendingRule {
        std::string set_name; // ipset name to match with --match-set
        bool ipv6;            // true → ip6tables, false → iptables
        enum Action { Mark, Drop, Pass } action; // MARK, DROP, or RETURN target
        uint32_t fwmark; // only for Mark
        uint32_t fwmark_mask{0xFFFFFFFFu}; // only for Mark
        FirewallRuleCriteria criteria; // optional packet match criteria
    };

    // Build the 'create <name> hash:net family <f> [timeout <t>]' line.
    static std::string build_ipset_create_line(const PendingSet& ps);
    // Build the 'create <name> list:set size <n>' + member 'add' lines for a
    // consolidated list:set. The set is flushed first so a config change cannot
    // leave stale members behind when sets are preserved across applies.
    static std::string build_list_set_lines(const PendingListSet& pls);
    // Collapse per-list match rules that share a family/verb/fwmark/selector
    // into one list:set-backed rule each. Returns the consolidated rules and,
    // via out_list_sets, the list:set definitions they reference.
    static std::vector<PendingRule> consolidate_rules(
        const std::vector<PendingRule>& rules,
        std::vector<PendingListSet>* out_list_sets);
    // Build a complete iptables-restore script for the given protocol and rules.
    // Per-list match rules are consolidated into list:set-backed rules first.
    // The PREROUTING jump is appended only when `add_prerouting_jump` is set
    // (a RulesOnly rebuild omits it when the jump is still in place, so it is
    // not duplicated).
    static std::string build_ipt_script(bool ipv6,
                                        const std::vector<PendingRule>& rules,
                                        const FirewallGlobalPrefilter& prefilter = {},
                                        bool add_prerouting_jump = true);
    // Parse the output of `ipset list -t` (names and headers only).
    static std::map<std::string, LiveSetInfo> parse_ipset_terse_listing(
        const std::string& output);
    // Why the live set cannot back `expected` as is, or std::nullopt if it can.
    static std::optional<std::string> live_hash_set_mismatch(
        const std::map<std::string, LiveSetInfo>& live,
        const PendingSet& expected);
    // RulesOnly: check every set the rules use, then rebuild the chains.
    void apply_rules_only(bool effective_ipv6,
                          const std::vector<PendingListSet>& list_sets);
    // Build early RETURN lines for the global prefilter.
    static std::string build_prefilter_lines(
        const FirewallGlobalPrefilter& prefilter);
    // Build the proto/port fragment for a single rule (single proto, not tcp/udp).
    static std::string build_proto_port_fragment(L4Proto proto,
                                                 const PortSpec& src_port,
                                                 const PortSpec& dst_port,
                                                 bool negate_src_port = false,
                                                 bool negate_dst_port = false);
    // Build one or more iptables-restore lines for a queued rule.
    static std::vector<std::string> build_rule_lines(
        const PendingRule& pr,
        const FirewallGlobalPrefilter& prefilter);
    bool ipv6_backend_available() const;
    // Expand filter (proto, src_addr, dst_addr) into cross-product of PendingRules
    // and append them to out.  tcp/udp is split into two entries.  Multiple CIDRs
    // in src_addr / dst_addr each become separate rules (OR semantics when combined).
    void append_rules_for_family(bool ipv6,
                                 PendingRule::Action action,
                                 uint32_t fwmark,
                                 const FirewallRuleCriteria& criteria);

    // Sets queued for creation, flushed by apply().
    std::vector<PendingSet> pending_sets_;
    // Per-set element buffers for ipset restore lines, keyed by set name.
    std::map<std::string, std::ostringstream> pending_elements_;
    // Rules queued for insertion into KeenPbrTable, flushed by apply().
    std::vector<PendingRule> pending_rules_;

    // Track created ipsets: set_name -> family (AF_INET/AF_INET6)
    std::map<std::string, int> created_sets_;

    // Names of synthesized list:set ipsets created by the most recent apply().
    // Tracked separately so cleanup can destroy them before their member sets
    // (ipset refuses to destroy a set that a list:set still references).
    std::vector<std::string> created_list_sets_;

    // Members each list:set was loaded with by the last full apply. A
    // RulesOnly apply may reuse a list:set only with exactly these members.
    std::map<std::string, std::vector<std::string>> applied_list_set_members_;

    // Track whether chain + jump rule exist for each protocol
    bool chain_v4_created_ = false;
    bool chain_v6_created_ = false;

#ifdef KEEN_PBR3_TESTING
    friend class IptablesBuilderTest;
    // Allow test access to build_proto_port_fragment
    friend struct IptablesBuilderTestHelper;
#endif
};

// Factory function called from firewall.cpp
std::unique_ptr<Firewall> create_iptables_firewall();

} // namespace keen_pbr3
