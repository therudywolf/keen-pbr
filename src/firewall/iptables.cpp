#include "iptables.hpp"
#include "ipset_restore_pipe.hpp"
#include "iptables_set_consolidation.hpp"
#include "port_spec_util.hpp"
#include "../log/logger.hpp"
#include "../util/format_compat.hpp"
#include "../util/ipv6_support.hpp"
#include "../util/safe_exec.hpp"

#include <algorithm>
#include <cstdint>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <sys/socket.h>

namespace keen_pbr3 {

namespace {

bool is_ipv6_addr(const std::string& addr) {
    return addr.find(':') != std::string::npos;
}

std::vector<std::string> filter_addrs_by_family(const std::vector<std::string>& addrs,
                                                bool ipv6) {
    std::vector<std::string> filtered;
    for (const auto& addr : addrs) {
        if (is_ipv6_addr(addr) == ipv6) {
            filtered.push_back(addr);
        }
    }
    return filtered;
}

std::vector<L4Proto> expand_l4_protos(L4Proto proto) {
    if (proto == L4Proto::TcpUdp) {
        return {L4Proto::Tcp, L4Proto::Udp};
    }
    return {proto};
}

std::vector<L4Proto> expand_l4_protos_for_iptables(const FirewallRuleCriteria& criteria) {
    if (criteria.proto == L4Proto::Any
        && (!criteria.src_port.empty() || !criteria.dst_port.empty())) {
        // iptables requires an explicit L4 protocol whenever port matchers are used.
        return {L4Proto::Tcp, L4Proto::Udp};
    }
    return expand_l4_protos(criteria.proto);
}

} // namespace

IptablesFirewall::IptablesFirewall() = default;

IptablesFirewall::~IptablesFirewall() {
    try {
        cleanup_impl();
    } catch (const std::exception& e) {
        Logger::instance().error("IptablesFirewall cleanup failed during destruction: {}",
                                 e.what());
    } catch (...) {
        Logger::instance().error(
            "IptablesFirewall cleanup failed during destruction: unknown error");
    }
}

void IptablesFirewall::create_ipset(const std::string& set_name, int family,
                                     uint32_t timeout) {
    PendingSet ps;
    ps.name = set_name;
    ps.family_str = (family == AF_INET6) ? "inet6" : "inet";
    ps.timeout = timeout;
    pending_sets_.push_back(std::move(ps));
    created_sets_[set_name] = family;
}

std::string IptablesFirewall::declare_negated_address_set(bool ipv6,
                                                          const std::vector<std::string>& addrs) {
    const std::string name = negated_address_set_name(ipv6, addrs);
    if (pending_negated_set_entries_.count(name) != 0) {
        return name;
    }

    PendingSet ps;
    ps.name = name;
    ps.family_str = ipv6 ? "inet6" : "inet";
    ps.timeout = 0;
    pending_sets_.push_back(std::move(ps));
    created_sets_[name] = ipv6 ? AF_INET6 : AF_INET;

    // The set is named after its content, so `add -exist` keeps it exact on
    // every apply mode; a 0.0.0.0/0 entry is split like in any list.
    IpsetRestoreVisitor loader(pending_elements_[name], name);
    for (const auto& addr : addrs) {
        loader.on_entry(addr.find('/') != std::string::npos ? EntryType::Cidr : EntryType::Ip,
                        addr);
    }
    pending_negated_set_entries_[name] = loader.count();
    return name;
}

void IptablesFirewall::append_rules_for_family(bool ipv6,
                                               PendingRule::Action action,
                                               uint32_t fwmark,
                                               const FirewallRuleCriteria& criteria) {
    const auto filtered_src_addrs = criteria.src_addr.empty()
        ? std::vector<std::string>{}
        : filter_addrs_by_family(criteria.src_addr, ipv6);
    const auto filtered_dst_addrs = criteria.dst_addr.empty()
        ? std::vector<std::string>{}
        : filter_addrs_by_family(criteria.dst_addr, ipv6);
    if ((!criteria.src_addr.empty() && filtered_src_addrs.empty())
        || (!criteria.dst_addr.empty() && filtered_dst_addrs.empty())) {
        return;
    }

    // The address alternatives of one side: none (any address), one rule per
    // address (a positive list ORs its rules), or, for a negated list of
    // several addresses, a single rule on the list's set: "not a" OR "not b"
    // would match every packet.
    const auto alternatives = [this, ipv6](const std::vector<std::string>& addrs,
                                           bool negated) {
        std::vector<std::vector<std::string>> out;
        if (addrs.empty()) {
            out.emplace_back();
        } else if (needs_negated_address_set(negated, addrs)) {
            out.push_back({declare_negated_address_set(ipv6, addrs)});
        } else {
            for (const auto& addr : addrs) {
                out.push_back({addr});
            }
        }
        return out;
    };
    const auto src_alternatives = alternatives(filtered_src_addrs, criteria.negate_src_addr);
    const auto dst_alternatives = alternatives(filtered_dst_addrs, criteria.negate_dst_addr);

    for (const auto proto : expand_l4_protos_for_iptables(criteria)) {
        for (const auto& src : src_alternatives) {
            for (const auto& dst : dst_alternatives) {
                PendingRule pr;
                pr.ipv6     = ipv6;
                pr.action   = action;
                pr.fwmark   = fwmark;
                pr.fwmark_mask = fwmark_mask();
                pr.criteria = criteria;
                pr.criteria.proto = proto;
                pr.criteria.src_addr = src;
                pr.criteria.dst_addr = dst;
                pending_rules_.push_back(std::move(pr));
            }
        }
    }
}

void IptablesFirewall::create_mark_rule(uint32_t fwmark,
                                        const FirewallRuleCriteria& criteria) {
    if (criteria.dst_set_name.has_value()) {
        auto it = created_sets_.find(*criteria.dst_set_name);
        bool ipv6 = (it != created_sets_.end() && it->second == AF_INET6);
        append_rules_for_family(ipv6, PendingRule::Mark, fwmark, criteria);
        return;
    }
    append_rules_for_family(false, PendingRule::Mark, fwmark, criteria);
    append_rules_for_family(true, PendingRule::Mark, fwmark, criteria);
}

void IptablesFirewall::create_drop_rule(const FirewallRuleCriteria& criteria) {
    if (criteria.dst_set_name.has_value()) {
        auto it = created_sets_.find(*criteria.dst_set_name);
        bool ipv6 = (it != created_sets_.end() && it->second == AF_INET6);
        append_rules_for_family(ipv6, PendingRule::Drop, 0, criteria);
        return;
    }
    append_rules_for_family(false, PendingRule::Drop, 0, criteria);
    append_rules_for_family(true, PendingRule::Drop, 0, criteria);
}

void IptablesFirewall::create_pass_rule(const FirewallRuleCriteria& criteria) {
    if (criteria.dst_set_name.has_value()) {
        auto it = created_sets_.find(*criteria.dst_set_name);
        bool ipv6 = (it != created_sets_.end() && it->second == AF_INET6);
        append_rules_for_family(ipv6, PendingRule::Pass, 0, criteria);
        return;
    }
    append_rules_for_family(false, PendingRule::Pass, 0, criteria);
    append_rules_for_family(true, PendingRule::Pass, 0, criteria);
}

std::unique_ptr<ListEntryVisitor> IptablesFirewall::create_batch_loader(
    const std::string& set_name) {
    auto& buf = pending_elements_[set_name];
    return std::make_unique<IpsetRestoreVisitor>(buf, set_name);
}

static void pipe_to_cmd(const std::vector<std::string>& args, const std::string& input) {
    Logger::instance().verbose("{} script:\n{}", args[0], input);
    int status = safe_exec_pipe_stdin(args, input);
    if (status != 0) {
        throw FirewallError(keen_pbr3::format("{} exited with status {}", args[0], status));
    }
}

std::string IptablesFirewall::build_ipset_create_line(const PendingSet& ps) {
    if (ps.timeout > 0) {
        return keen_pbr3::format("create {} hash:net family {} timeout {} -exist\n",
                                 ps.name, ps.family_str, ps.timeout);
    } else {
        return keen_pbr3::format("create {} hash:net family {} -exist\n",
                                 ps.name, ps.family_str);
    }
}

bool IptablesFirewall::ipv6_backend_available() const {
    return iptables_ipv6_supported();
}

std::string IptablesFirewall::build_list_set_lines(const PendingListSet& pls) {
    // list:set has a small default capacity (8); size it to the member count
    // with generous headroom so a growing config does not overflow it. The
    // kernel caps list:set at 65536 members.
    uint64_t size = static_cast<uint64_t>(pls.members.size());
    size += size / 2 + 8;
    if (size > 65536) {
        size = 65536;
    }

    std::string lines = keen_pbr3::format("create {} list:set size {} -exist\n",
                                          pls.name, size);
    // Flush before repopulating: under PreserveSets the set may already exist
    // with a stale member composition from a previous config.
    lines += keen_pbr3::format("flush {}\n", pls.name);
    for (const auto& member : pls.members) {
        lines += keen_pbr3::format("add {} {} -exist\n", pls.name, member);
    }
    return lines;
}

std::vector<IptablesFirewall::PendingRule> IptablesFirewall::consolidate_rules(
    const std::vector<PendingRule>& rules,
    std::vector<PendingListSet>* out_list_sets) {
    auto to_action = [](PendingRule::Action a) {
        switch (a) {
            case PendingRule::Mark: return ConsolidatableRule::Action::Mark;
            case PendingRule::Drop: return ConsolidatableRule::Action::Drop;
            case PendingRule::Pass: return ConsolidatableRule::Action::Pass;
        }
        return ConsolidatableRule::Action::Mark;
    };
    auto from_action = [](ConsolidatableRule::Action a) {
        switch (a) {
            case ConsolidatableRule::Action::Mark: return PendingRule::Mark;
            case ConsolidatableRule::Action::Drop: return PendingRule::Drop;
            case ConsolidatableRule::Action::Pass: return PendingRule::Pass;
        }
        return PendingRule::Mark;
    };

    // The fwmark mask is firewall-instance-wide (set once via set_fwmark_mask),
    // so every Mark rule carries the same value; the per-rule mask below is
    // captured to re-stamp the consolidated rules.
    std::vector<ConsolidatableRule> input;
    input.reserve(rules.size());
    uint32_t fwmark_mask = 0xFFFFFFFFu;
    for (const auto& pr : rules) {
        ConsolidatableRule cr;
        cr.ipv6 = pr.ipv6;
        cr.action = to_action(pr.action);
        cr.fwmark = pr.fwmark;
        cr.criteria = pr.criteria;
        input.push_back(std::move(cr));
        if (pr.action == PendingRule::Mark) {
            fwmark_mask = pr.fwmark_mask;
        }
    }

    const auto consolidated = consolidate_iptables_rules(input);

    std::vector<PendingRule> out;
    out.reserve(consolidated.size());
    for (const auto& cons : consolidated) {
        PendingRule pr;
        pr.ipv6 = cons.ipv6;
        pr.action = from_action(cons.action);
        pr.fwmark = cons.fwmark;
        pr.fwmark_mask = fwmark_mask;
        pr.criteria = cons.criteria;
        out.push_back(std::move(pr));

        if (cons.is_combined && out_list_sets != nullptr
            && cons.criteria.dst_set_name.has_value()) {
            // Each combined set surfaces once even though the same group can
            // appear in both the v4 and v6 rule lists (it never does here,
            // since family is part of the group key, but guard anyway).
            const std::string& name = *cons.criteria.dst_set_name;
            const bool seen = std::any_of(
                out_list_sets->begin(), out_list_sets->end(),
                [&](const PendingListSet& pls) { return pls.name == name; });
            if (!seen) {
                PendingListSet pls;
                pls.name = name;
                pls.members = cons.member_sets;
                out_list_sets->push_back(std::move(pls));
            }
        }
    }
    return out;
}

std::string IptablesFirewall::build_proto_port_fragment(L4Proto proto,
                                                         const PortSpec& src_port,
                                                         const PortSpec& dst_port,
                                                         bool negate_src_port,
                                                         bool negate_dst_port) {
    if (proto == L4Proto::Any && src_port.empty() && dst_port.empty()) {
        return "";
    }

    std::string frag;

    // -p flag (required if we have any port matching)
    if (proto != L4Proto::Any) {
        frag += " -p ";
        frag += l4_proto_name(proto);
    }

    bool has_src = !src_port.empty();
    bool has_dst = !dst_port.empty();
    bool src_list = has_src && classify_port_spec(src_port) == PortSpecKind::List;
    bool dst_list = has_dst && classify_port_spec(dst_port) == PortSpecKind::List;
    std::string normalized_src = has_src ? src_port.to_iptables_string() : "";
    std::string normalized_dst = has_dst ? dst_port.to_iptables_string() : "";

    // Use -m multiport only for comma-separated port lists. Single ports and
    // ranges are natively supported by the protocol matcher.
    if (has_src || has_dst) {
        if (src_list || dst_list) {
            if (src_list) {
                frag += " -m multiport" + std::string(negate_src_port ? " !" : "") + " --sports " + normalized_src;
            } else if (has_src) {
                frag += std::string(negate_src_port ? " !" : "") + " --sport " + normalized_src;
            }

            if (dst_list) {
                frag += " -m multiport" + std::string(negate_dst_port ? " !" : "") + " --dports " + normalized_dst;
            } else if (has_dst) {
                frag += std::string(negate_dst_port ? " !" : "") + " --dport " + normalized_dst;
            }
        } else {
            if (has_src) frag += std::string(negate_src_port ? " !" : "") + " --sport " + normalized_src;
            if (has_dst) frag += std::string(negate_dst_port ? " !" : "") + " --dport " + normalized_dst;
        }
    }

    return frag;
}

std::string IptablesFirewall::build_prefilter_lines(
    const FirewallGlobalPrefilter& prefilter) {
    std::string lines;
    if (prefilter.skip_established_or_dnat) {
        lines += keen_pbr3::format(
            "-A {} -m conntrack --ctstate DNAT -j RETURN\n",
            CHAIN_NAME);
    }

    if (prefilter.skip_marked_packets) {
        lines += keen_pbr3::format(
            "-A {} -m mark ! --mark 0x0/0xffffffff -j ACCEPT\n",
            CHAIN_NAME);
    }

    if (prefilter.has_inbound_interfaces()
        && prefilter.inbound_interfaces.has_value()
        && prefilter.inbound_interfaces->size() == 1) {
        lines += keen_pbr3::format(
            "-A {} ! -i {} -j RETURN\n",
            CHAIN_NAME,
            prefilter.inbound_interfaces->front());
    }

    return lines;
}

std::vector<std::string> IptablesFirewall::build_rule_lines(
    const PendingRule& pr,
    const FirewallGlobalPrefilter& prefilter) {
    // iptables cannot express a multi-value negated -i guard in one rule, so
    // multi-interface allowlists are expanded into one positive -i match per rule.
    std::vector<std::string> iface_frags;
    if (prefilter.has_inbound_interfaces()
        && prefilter.inbound_interfaces.has_value()
        && prefilter.inbound_interfaces->size() > 1) {
        iface_frags.reserve(prefilter.inbound_interfaces->size());
        for (const auto& iface : *prefilter.inbound_interfaces) {
            iface_frags.push_back(" -i " + iface);
        }
    } else {
        iface_frags.push_back("");
    }

    // A negated address list is carried as its set's name (see
    // append_rules_for_family) and matched with a negated set match.
    const auto addr_match = [](const char* flag,
                               const char* direction,
                               const std::vector<std::string>& addrs,
                               bool negated) -> std::string {
        if (addrs.empty()) {
            return "";
        }
        if (is_negated_address_set_name(addrs[0])) {
            return keen_pbr3::format(" -m set ! --match-set {} {}", addrs[0], direction);
        }
        return std::string(negated ? " !" : "") + " " + flag + " " + addrs[0];
    };
    std::string addr_frag;
    addr_frag += addr_match("-s", "src", pr.criteria.src_addr, pr.criteria.negate_src_addr);
    addr_frag += addr_match("-d", "dst", pr.criteria.dst_addr, pr.criteria.negate_dst_addr);
    std::vector<std::string> lines;
    lines.reserve(iface_frags.size() * 2);
    for (const auto proto : expand_l4_protos_for_iptables(pr.criteria)) {
        std::string pp = build_proto_port_fragment(proto,
                                                   pr.criteria.src_port,
                                                   pr.criteria.dst_port,
                                                   pr.criteria.negate_src_port,
                                                   pr.criteria.negate_dst_port);

        for (const auto& iface_frag : iface_frags) {
            if (!pr.criteria.dst_set_name.has_value()) {
                if (pr.action == PendingRule::Mark) {
                    const std::string mark_target = keen_pbr3::format(
                        "-j MARK --set-xmark {:#x}/{:#x}",
                        pr.fwmark,
                        pr.fwmark_mask);
                    lines.push_back(keen_pbr3::format(
                        "[0:0] -A {}{}{}{} {}\n",
                        CHAIN_NAME,
                        iface_frag,
                        addr_frag,
                        pp,
                        mark_target));
                    lines.push_back(keen_pbr3::format(
                        "-A {}{}{}{} -j RETURN\n",
                        CHAIN_NAME,
                        iface_frag,
                        addr_frag,
                        pp));
                } else if (pr.action == PendingRule::Drop) {
                    lines.push_back(keen_pbr3::format(
                        "-A {}{}{}{} -j DROP\n",
                        CHAIN_NAME,
                        iface_frag,
                        addr_frag,
                        pp));
                } else {
                    lines.push_back(keen_pbr3::format(
                        "-A {}{}{}{} -j RETURN\n",
                        CHAIN_NAME,
                        iface_frag,
                        addr_frag,
                        pp));
                }
            } else {
                if (pr.action == PendingRule::Mark) {
                    const std::string mark_target = keen_pbr3::format(
                        "-j MARK --set-xmark {:#x}/{:#x}",
                        pr.fwmark,
                        pr.fwmark_mask);
                    lines.push_back(keen_pbr3::format(
                        "[0:0] -A {} -m set --match-set {} dst{}{}{} {}\n",
                        CHAIN_NAME,
                        *pr.criteria.dst_set_name,
                        iface_frag,
                        addr_frag,
                        pp,
                        mark_target));
                    lines.push_back(keen_pbr3::format(
                        "-A {} -m set --match-set {} dst{}{}{} -j RETURN\n",
                        CHAIN_NAME,
                        *pr.criteria.dst_set_name,
                        iface_frag,
                        addr_frag,
                        pp));
                } else if (pr.action == PendingRule::Drop) {
                    lines.push_back(keen_pbr3::format(
                        "-A {} -m set --match-set {} dst{}{}{} -j DROP\n",
                        CHAIN_NAME,
                        *pr.criteria.dst_set_name,
                        iface_frag,
                        addr_frag,
                        pp));
                } else {
                    lines.push_back(keen_pbr3::format(
                        "-A {} -m set --match-set {} dst{}{}{} -j RETURN\n",
                        CHAIN_NAME,
                        *pr.criteria.dst_set_name,
                        iface_frag,
                        addr_frag,
                        pp));
                }
            }
        }
    }

    return lines;
}

std::string IptablesFirewall::build_ipt_script(bool ipv6,
                                                const std::vector<PendingRule>& rules,
                                                const FirewallGlobalPrefilter& prefilter,
                                                bool add_prerouting_jump) {
    // Collapse per-list match rules into list:set-backed rules. The list:set
    // ipsets themselves are created in apply(); here only the chain rules
    // (which reference the sets by name) are emitted.
    const std::vector<PendingRule> consolidated = consolidate_rules(rules, nullptr);

    // With --noflush, declaring the chain flushes it if it exists (creates it
    // otherwise), and the whole table is committed at once.
    std::string s;
    s += keen_pbr3::format("*mangle\n:{} - [0:0]\n", CHAIN_NAME);
    if (add_prerouting_jump) {
        s += keen_pbr3::format("-A PREROUTING -j {}\n", CHAIN_NAME);
    }
    s += build_prefilter_lines(prefilter);
    for (const auto& pr : consolidated) {
        if (pr.ipv6 != ipv6) continue;
        for (const auto& line : build_rule_lines(pr, prefilter)) {
            s += line;
        }
    }
    s += "COMMIT\n";
    return s;
}

void IptablesFirewall::apply(FirewallApplyMode mode) {
    // The buffered sets, elements and rules belong to this apply only. Drop
    // them on every exit path: after a failed apply they would otherwise be
    // carried into the next one (duplicate rules, a stale config's rules).
    struct PendingBuffersReset {
        IptablesFirewall& firewall;
        ~PendingBuffersReset() {
            firewall.pending_sets_.clear();
            firewall.pending_elements_.clear();
            firewall.pending_rules_.clear();
            firewall.pending_negated_set_entries_.clear();
        }
    } pending_reset{*this};

    bool effective_ipv6 = ipv6_enabled();
    if (effective_ipv6 && !ipv6_backend_available()) {
        Logger::instance().error(
            "IPv6 iptables backend is unavailable; skipping IPv6 firewall state and continuing IPv4-only");
        effective_ipv6 = false;
    }

    // Consolidate per-list match rules into list:set-backed rules. The list:set
    // definitions are needed here (phase 1) to create the sets; the consolidated
    // rules themselves are rebuilt by build_ipt_script() in phase 2.
    std::vector<PendingListSet> pending_list_sets;
    consolidate_rules(pending_rules_, &pending_list_sets);

    if (mode == FirewallApplyMode::RulesOnly) {
        apply_rules_only(effective_ipv6, pending_list_sets);
        return;
    }

    if (mode == FirewallApplyMode::Destructive) {
        // A config save or list refresh used to destroy the dnsmasq-filled
        // sets too: domain traffic then left via the default route until
        // dnsmasq answered again or the list warmer ran (up to 10 minutes).
        // Keep the live ones whose layout still fits, unless configured not to.
        DynamicSetPlan dynamic_plan;
        if (!clear_dynamic_sets_on_apply()) {
            const auto listing =
                safe_exec_capture({"ipset", "list", "-t"}, /*suppress_stderr=*/true);
            if (listing.exit_code == 0 && !listing.truncated) {
                dynamic_plan = plan_dynamic_sets(parse_ipset_terse_listing(listing.stdout_output),
                                                 pending_sets_,
                                                 effective_ipv6);
            }
            // Without a listing nothing is known about the live sets: they
            // are all recreated, as before.
            for (const auto& name : dynamic_plan.destroy) {
                Logger::instance().info(
                    "Dynamic set {} changed family or timeout; recreating it empty", name);
            }
        }
        cleanup_live_impl(dynamic_plan.keep, dynamic_plan.destroy);
    } else {
        cleanup_rules_impl();
    }

    created_list_sets_.clear();

    // Phase 1: ipsets via 'ipset restore -exist'
    {
        std::string ipset_script;
        // Per-list hash:net sets first — a list:set may only reference sets
        // that already exist.
        std::set<std::string> disabled_ipv6_sets;
        for (const auto& ps : pending_sets_) {
            if (ps.family_str == "inet6" && !effective_ipv6) {
                disabled_ipv6_sets.insert(ps.name);
                continue;
            }
            ipset_script += build_ipset_create_line(ps);
        }
        // Consolidated list:set sets, created after their member sets.
        for (const auto& pls : pending_list_sets) {
            ipset_script += build_list_set_lines(pls);
            created_list_sets_.push_back(pls.name);
        }
        for (auto& [set_name, buf] : pending_elements_) {
            if (disabled_ipv6_sets.find(set_name) != disabled_ipv6_sets.end()) {
                continue;
            }
            std::string elements = buf.str();
            if (!elements.empty()) {
                ipset_script += elements;
            }
        }
        // A failed restore can leave a list:set half refilled: record the
        // members only once the batch went through.
        applied_list_set_members_.clear();
        if (!ipset_script.empty()) {
            pipe_to_cmd({"ipset", "restore", "-exist"}, ipset_script);
        }
        for (const auto& pls : pending_list_sets) {
            applied_list_set_members_[pls.name] = pls.members;
        }
    }

    // Phase 2: iptables rules via iptables-restore / ip6tables-restore.
    // Always materialize the KeenPbrTable scaffold for both protocols so
    // diagnostics can verify chain/jump presence even when no rules are needed.
    //
    // The restore is always executed -- including on a PreserveSets refresh.
    // That refresh is triggered by the netfilter.d hook precisely because the
    // mangle table changed under us (NDM rebuilds it on network events and
    // does not keep keen-pbr's rules), so re-asserting the rules is the whole
    // point. The iptables-restore script flushes and rebuilds the KeenPbrTable
    // chain, so it is idempotent and safe to run unconditionally. When ipv6
    // support is disabled (or unavailable), skip the v6 restore so we do not
    // assert chains in an unused table.
    pipe_to_cmd({"iptables-restore", "--noflush", "--counters"},
                build_ipt_script(false, pending_rules_, global_prefilter_));
    chain_v4_created_ = true;
    if (effective_ipv6) {
        pipe_to_cmd({"ip6tables-restore", "--noflush", "--counters"},
                    build_ipt_script(true, pending_rules_, global_prefilter_));
        chain_v6_created_ = true;
    }
}

std::map<std::string, IptablesFirewall::LiveSetInfo>
IptablesFirewall::parse_ipset_terse_listing(const std::string& output) {
    // Records look like:
    //   Name: kpbr4d_youtube
    //   Type: hash:net
    //   Header: family inet hashsize 1024 maxelem 65536 timeout 600
    //   Number of entries: 3
    std::map<std::string, LiveSetInfo> sets;
    LiveSetInfo* current = nullptr;
    std::istringstream stream(output);
    std::string line;
    const auto value_of = [&line](const std::string& prefix) -> std::optional<std::string> {
        if (line.rfind(prefix, 0) != 0) {
            return std::nullopt;
        }
        std::string value = line.substr(prefix.size());
        while (!value.empty() && (value.back() == '\r' || value.back() == ' ')) {
            value.pop_back();
        }
        return value;
    };
    while (std::getline(stream, line)) {
        if (const auto name = value_of("Name: ")) {
            current = &sets[*name];
            continue;
        }
        if (current == nullptr) {
            continue;
        }
        if (const auto type = value_of("Type: ")) {
            current->type = *type;
        } else if (const auto header = value_of("Header: ")) {
            std::istringstream tokens(*header);
            std::string key;
            std::string value;
            while (tokens >> key) {
                if (key == "family" && tokens >> value) {
                    current->family = value;
                } else if (key == "timeout" && tokens >> value) {
                    try {
                        current->timeout = static_cast<uint32_t>(std::stoul(value));
                    } catch (...) {
                        current->timeout.reset();
                    }
                }
            }
        } else if (const auto entries = value_of("Number of entries: ")) {
            try {
                current->entries = static_cast<size_t>(std::stoul(*entries));
            } catch (...) {
                current->entries.reset();
            }
        }
    }
    return sets;
}

std::optional<std::string> IptablesFirewall::live_hash_set_mismatch(
    const std::map<std::string, LiveSetInfo>& live,
    const PendingSet& expected) {
    const auto it = live.find(expected.name);
    if (it == live.end()) {
        return "set " + expected.name + " is missing";
    }
    const LiveSetInfo& info = it->second;
    if (info.type != "hash:net") {
        return "set " + expected.name + " has type " + info.type;
    }
    if (info.family != expected.family_str) {
        return "set " + expected.name + " has family " + info.family;
    }
    const bool timeout_ok = expected.timeout > 0
        ? info.timeout.has_value() && *info.timeout == expected.timeout
        : !info.timeout.has_value() || *info.timeout == 0;
    if (!timeout_ok) {
        return "set " + expected.name + " has a different timeout";
    }
    return std::nullopt;
}

bool IptablesFirewall::is_dynamic_set_name(const std::string& set_name) {
    return set_name.rfind("kpbr4d_", 0) == 0 || set_name.rfind("kpbr6d_", 0) == 0;
}

IptablesFirewall::DynamicSetPlan IptablesFirewall::plan_dynamic_sets(
    const std::map<std::string, LiveSetInfo>& live,
    const std::vector<PendingSet>& pending,
    bool effective_ipv6) {
    DynamicSetPlan plan;
    for (const auto& ps : pending) {
        if (!is_dynamic_set_name(ps.name) || live.count(ps.name) == 0) {
            continue;
        }
        if (ps.family_str == "inet6" && !effective_ipv6) {
            continue;
        }
        if (live_hash_set_mismatch(live, ps).has_value()) {
            plan.destroy.insert(ps.name);
        } else {
            plan.keep.insert(ps.name);
        }
    }
    return plan;
}

void IptablesFirewall::apply_rules_only(bool effective_ipv6,
                                        const std::vector<PendingListSet>& list_sets) {
    // Preflight, before anything is touched: every set the new rules use must
    // already exist with the expected layout. One terse listing covers all.
    const auto listing = safe_exec_capture({"ipset", "list", "-t"}, /*suppress_stderr=*/true);
    if (listing.exit_code != 0 || listing.truncated) {
        throw FirewallRulesOnlyError("cannot list the live ipsets");
    }
    const auto live = parse_ipset_terse_listing(listing.stdout_output);

    for (const auto& ps : pending_sets_) {
        if (ps.family_str == "inet6" && !effective_ipv6) {
            continue;
        }
        if (const auto mismatch = live_hash_set_mismatch(live, ps)) {
            throw FirewallRulesOnlyError(*mismatch);
        }
    }
    for (const auto& pls : list_sets) {
        const auto applied = applied_list_set_members_.find(pls.name);
        if (applied == applied_list_set_members_.end() || applied->second != pls.members) {
            throw FirewallRulesOnlyError("list:set " + pls.name + " needs other members");
        }
        const auto it = live.find(pls.name);
        if (it == live.end() || it->second.type != "list:set" ||
            (it->second.entries.has_value() && *it->second.entries != pls.members.size())) {
            throw FirewallRulesOnlyError("list:set " + pls.name + " is missing or changed");
        }
    }
    for (const auto& [name, buffer] : pending_elements_) {
        (void)buffer;
        // A negated address set is named after its content: when it exists
        // with all its entries, its elements need not be loaded again.
        const auto expected = pending_negated_set_entries_.find(name);
        const auto it = live.find(name);
        if (expected == pending_negated_set_entries_.end()) {
            throw FirewallRulesOnlyError("set elements were queued; refusing to change sets");
        }
        if (it == live.end() ||
            (it->second.entries.has_value() && *it->second.entries != expected->second)) {
            throw FirewallRulesOnlyError("negated address set " + name + " is missing or changed");
        }
    }

    // Rebuild each family's chain in one iptables-restore transaction: the
    // chain is flushed and refilled atomically, so there is no moment without
    // rules (the full path deletes the jump and the chain first). The jump
    // is added only when NDM's rebuild removed it, never duplicated.
    const auto restore_family = [this](bool ipv6) {
        const std::string iptables = ipv6 ? "ip6tables" : "iptables";
        const bool jump_present =
            safe_exec({iptables, "-t", "mangle", "-C", "PREROUTING", "-j", CHAIN_NAME},
                      /*suppress_output=*/true) == 0;
        pipe_to_cmd({iptables + "-restore", "--noflush", "--counters"},
                    build_ipt_script(ipv6, pending_rules_, global_prefilter_, !jump_present));
    };
    restore_family(false);
    chain_v4_created_ = true;
    if (effective_ipv6) {
        restore_family(true);
        chain_v6_created_ = true;
    }
}

void IptablesFirewall::cleanup_rules_impl() {
    auto& log = Logger::instance();

    // Remove jump rules, flush and delete custom chain for IPv4
    if (chain_v4_created_) {
        log.verbose("iptables cleanup: removing IPv4 chain {}", CHAIN_NAME);
        safe_exec({"iptables", "-t", "mangle", "-D", "PREROUTING", "-j", CHAIN_NAME}, /*suppress_output=*/true);
        safe_exec({"iptables", "-t", "mangle", "-F", CHAIN_NAME}, /*suppress_output=*/true);
        safe_exec({"iptables", "-t", "mangle", "-X", CHAIN_NAME}, /*suppress_output=*/true);
        chain_v4_created_ = false;
    }

    // Same for IPv6
    if (chain_v6_created_) {
        log.verbose("iptables cleanup: removing IPv6 chain {}", CHAIN_NAME);
        safe_exec({"ip6tables", "-t", "mangle", "-D", "PREROUTING", "-j", CHAIN_NAME}, /*suppress_output=*/true);
        safe_exec({"ip6tables", "-t", "mangle", "-F", CHAIN_NAME}, /*suppress_output=*/true);
        safe_exec({"ip6tables", "-t", "mangle", "-X", CHAIN_NAME}, /*suppress_output=*/true);
        chain_v6_created_ = false;
    }
}

void IptablesFirewall::cleanup_live_impl(const std::set<std::string>& keep,
                                         const std::set<std::string>& also_destroy) {
    auto& log = Logger::instance();

    cleanup_rules_impl();

    // Destroy synthesized list:set sets first: ipset refuses to destroy a
    // hash:net set while a list:set still references it as a member.
    for (const auto& name : created_list_sets_) {
        log.verbose("iptables cleanup: destroying list:set ipset {}", name);
        safe_exec({"ipset", "flush", name}, /*suppress_output=*/true);
        safe_exec({"ipset", "destroy", name}, /*suppress_output=*/true);
    }
    created_list_sets_.clear();
    applied_list_set_members_.clear();

    // Destroy all created per-list ipsets
    for (const auto& [name, _] : created_sets_) {
        if (keep.count(name) != 0) {
            log.verbose("iptables cleanup: keeping ipset {}", name);
            continue;
        }
        log.verbose("iptables cleanup: destroying ipset {}", name);
        safe_exec({"ipset", "flush", name}, /*suppress_output=*/true);
        safe_exec({"ipset", "destroy", name}, /*suppress_output=*/true);
    }
    // Live sets this instance did not create (left by an instance that did
    // not shut down cleanly) but that cannot be reused as they are.
    for (const auto& name : also_destroy) {
        if (created_sets_.count(name) != 0) {
            continue;
        }
        log.verbose("iptables cleanup: destroying stale ipset {}", name);
        safe_exec({"ipset", "flush", name}, /*suppress_output=*/true);
        safe_exec({"ipset", "destroy", name}, /*suppress_output=*/true);
    }
}

void IptablesFirewall::cleanup_impl() {
    cleanup_live_impl();

    created_sets_.clear();

    pending_sets_.clear();
    pending_elements_.clear();
    pending_rules_.clear();
    pending_negated_set_entries_.clear();
}

void IptablesFirewall::cleanup() {
    cleanup_impl();
}

FirewallBackend IptablesFirewall::backend() const {
    return FirewallBackend::iptables;
}

std::unique_ptr<Firewall> create_iptables_firewall() {
    return std::make_unique<IptablesFirewall>();
}

} // namespace keen_pbr3
