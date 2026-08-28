#include "conntrack_flush.hpp"

#include "../lists/ipset.hpp"
#include "../log/logger.hpp"
#include "../util/blocking_executor.hpp"
#include "../util/format_compat.hpp"
#include "../util/safe_exec.hpp"

#include <algorithm>
#include <arpa/inet.h>
#include <atomic>
#include <cerrno>
#include <cstring>
#include <memory>
#include <netinet/in.h>
#include <sstream>
#include <string>
#include <sys/socket.h>
#include <utility>
#include <vector>

extern "C" {
#include <netlink/attr.h>
#include <netlink/errno.h>
#include <netlink/msg.h>
#include <netlink/netlink.h>
#include <netlink/socket.h>
}

// Kernel UAPI for nfnetlink + conntrack. Pulled directly from linux-libc-dev
// (a transitive dep of build-essential and the Entware cross toolchain), so no
// new opkg/apt package is required.
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_conntrack.h>

namespace keen_pbr3 {

namespace {

// Compose the 16-bit nfnetlink type from a subsystem + message-type pair.
// Mirrors the macro the kernel header uses internally but expressed inline
// so the conntrack flush logic doesn't depend on any libnl-nf helper.
constexpr uint16_t make_nfnl_type(uint8_t subsys, uint8_t msg_type) {
    return static_cast<uint16_t>((static_cast<uint16_t>(subsys) << 8) | msg_type);
}

// True if the set name is one we manage (and therefore safe to flush conntrack
// destinations for). Matches the four prefixes the daemon emits:
//   - "kpbr4_" / "kpbr6_"  — static IP/CIDR sets
//   - "kpbr4d_" / "kpbr6d_" — dnsmasq-populated dynamic sets
bool is_kpbr_set_name(const std::string& name) {
    return name.rfind("kpbr4_", 0) == 0 ||
           name.rfind("kpbr6_", 0) == 0 ||
           name.rfind("kpbr4d_", 0) == 0 ||
           name.rfind("kpbr6d_", 0) == 0;
}

// Pull every "add <set> <ip-or-cidr> ..." record out of an `ipset save`
// stdout dump for a single set, feeding each entry into the given sink.
void parse_ipset_save_members(const std::string& dump,
                              const std::function<void(const std::string&)>& sink) {
    size_t pos = 0;
    while (pos < dump.size()) {
        const size_t newline = dump.find('\n', pos);
        const size_t line_end =
            (newline == std::string::npos) ? dump.size() : newline;
        const std::string line = dump.substr(pos, line_end - pos);
        pos = (newline == std::string::npos) ? dump.size() : newline + 1;

        // We only care about `add <set> <member> ...` lines. `create`,
        // `flush`, blank lines, and comments are ignored.
        if (line.rfind("add ", 0) != 0) {
            continue;
        }
        std::istringstream iss(line);
        std::string verb, set_name, member;
        if (!(iss >> verb >> set_name >> member)) {
            continue;
        }
        if (member.empty()) {
            continue;
        }
        sink(member);
    }
}

// Best-effort: insert one member entry into the IpSet. ipset hash:net entries
// come as CIDR; hash:ip entries come as bare IPs. The IpSet helper accepts
// both via add_address / add_cidr.
void insert_ipset_member(IpSet& set, const std::string& member) {
    try {
        if (member.find('/') != std::string::npos) {
            set.add_cidr(member);
        } else {
            set.add_address(member);
        }
    } catch (const std::exception& e) {
        // Members that ipset emits in forms we don't parse (rare; ipset
        // sometimes adds protocol/port suffixes for non-net types we don't
        // own) are skipped silently — they can't be ours anyway, but log
        // at trace so any future surprise is diagnosable.
        Logger::instance().trace("conntrack_flush_member_skip",
                                 "member={} error={}",
                                 member,
                                 e.what());
    }
}

// RAII for an owned nl_msg* (the message has to be released with nlmsg_free,
// not delete).
struct NlMsgDeleter {
    void operator()(struct nl_msg* m) const noexcept {
        if (m) nlmsg_free(m);
    }
};
using NlMsgPtr = std::unique_ptr<struct nl_msg, NlMsgDeleter>;

// RAII for the netlink socket.
struct NlSockDeleter {
    void operator()(struct nl_sock* s) const noexcept {
        if (s) {
            // nl_socket_free closes the underlying fd and frees the socket.
            nl_socket_free(s);
        }
    }
};
using NlSockPtr = std::unique_ptr<struct nl_sock, NlSockDeleter>;

// Open a NETLINK_NETFILTER socket connected to the kernel. Returns nullptr
// on failure, logging at warn level.
NlSockPtr open_nfnl_socket() {
    NlSockPtr sock(nl_socket_alloc());
    if (!sock) {
        Logger::instance().warn(
            "conntrack_flush: nl_socket_alloc failed");
        return nullptr;
    }
    // Make all kernel responses synchronous (we want to process the dump as
    // we read it, not via libnl's callback queue).
    nl_socket_disable_seq_check(sock.get());
    const int err = nl_connect(sock.get(), NETLINK_NETFILTER);
    if (err < 0) {
        Logger::instance().warn(
            "conntrack_flush: nl_connect(NETLINK_NETFILTER) failed: {}",
            nl_geterror(err));
        return nullptr;
    }
    return sock;
}

// Build an IPCTNL_MSG_CT_GET dump request. The kernel responds with one
// nlmsg per conntrack entry, terminated by NLMSG_DONE.
NlMsgPtr build_ct_dump_request() {
    NlMsgPtr msg(nlmsg_alloc());
    if (!msg) {
        return nullptr;
    }
    struct nfgenmsg hdr{};
    hdr.nfgen_family = AF_UNSPEC;  // dump v4 + v6 in one pass
    hdr.version = NFNETLINK_V0;
    hdr.res_id = 0;

    const uint16_t nfnl_type =
        make_nfnl_type(NFNL_SUBSYS_CTNETLINK, IPCTNL_MSG_CT_GET);
    // Construct the netlink message header (nlmsg_put returns the
    // nlmsghdr*, which we ignore — nlmsg_append writes the payload).
    struct nlmsghdr* nlh = nlmsg_put(msg.get(),
                                     /*pid=*/NL_AUTO_PORT,
                                     /*seq=*/NL_AUTO_SEQ,
                                     nfnl_type,
                                     /*payload=*/0,
                                     NLM_F_REQUEST | NLM_F_DUMP);
    if (!nlh) {
        return nullptr;
    }
    if (nlmsg_append(msg.get(), &hdr, sizeof(hdr), NLMSG_ALIGNTO) < 0) {
        return nullptr;
    }
    return msg;
}

// Extract a single IPv4 address attribute (CTA_IP_V4_SRC/_DST) into dotted
// form. Returns empty string if the attribute is missing or malformed.
std::string parse_v4_attr(struct nlattr* attr) {
    if (!attr || nla_len(attr) < static_cast<int>(sizeof(uint32_t))) {
        return {};
    }
    char buf[INET_ADDRSTRLEN];
    const void* data = nla_data(attr);
    if (!inet_ntop(AF_INET, data, buf, sizeof(buf))) {
        return {};
    }
    return buf;
}

// Extract a single IPv6 address attribute (CTA_IP_V6_SRC/_DST) into colon
// form. Returns empty string if the attribute is missing or malformed.
std::string parse_v6_attr(struct nlattr* attr) {
    if (!attr || nla_len(attr) < 16) {
        return {};
    }
    char buf[INET6_ADDRSTRLEN];
    const void* data = nla_data(attr);
    if (!inet_ntop(AF_INET6, data, buf, sizeof(buf))) {
        return {};
    }
    return buf;
}

// Walk a CTA_TUPLE_ORIG / CTA_TUPLE_REPLY nested attribute and return the
// destination IP for the family carried by the tuple. Empty string on
// failure (caller skips the entry).
std::string parse_tuple_dst(struct nlattr* tuple_attr, uint8_t expected_family) {
    if (!tuple_attr) return {};

    struct nlattr* tuple_attrs[CTA_TUPLE_MAX + 1] = {nullptr};
    if (nla_parse_nested(tuple_attrs, CTA_TUPLE_MAX, tuple_attr, nullptr) < 0) {
        return {};
    }
    struct nlattr* ip_attr = tuple_attrs[CTA_TUPLE_IP];
    if (!ip_attr) return {};

    struct nlattr* ip_attrs[CTA_IP_MAX + 1] = {nullptr};
    if (nla_parse_nested(ip_attrs, CTA_IP_MAX, ip_attr, nullptr) < 0) {
        return {};
    }

    if (expected_family == AF_INET) {
        return parse_v4_attr(ip_attrs[CTA_IP_V4_DST]);
    }
    if (expected_family == AF_INET6) {
        return parse_v6_attr(ip_attrs[CTA_IP_V6_DST]);
    }
    // Tuple without a known family — skip.
    return {};
}

// Send the dump request and walk the response stream, calling on_entry for
// each parsed conntrack entry. Returns true if the dump completed, false on
// netlink error. on_entry may return false to stop early; we still drain the
// kernel response so the socket doesn't get stuck.
bool walk_conntrack_dump(struct nl_sock* sock,
                         const std::function<bool(const ConntrackFlusher::ConntrackEntry&)>& on_entry) {
    NlMsgPtr request = build_ct_dump_request();
    if (!request) {
        Logger::instance().warn(
            "conntrack_flush: failed to build conntrack dump request");
        return false;
    }

    int err = nl_send_auto(sock, request.get());
    if (err < 0) {
        Logger::instance().warn(
            "conntrack_flush: nl_send_auto failed: {}", nl_geterror(err));
        return false;
    }

    bool keep_calling = true;
    while (true) {
        unsigned char* buf = nullptr;
        struct sockaddr_nl peer{};
        const int recv_n = nl_recv(sock, &peer, &buf, nullptr);
        if (recv_n < 0) {
            // EAGAIN can happen on a non-blocking socket; we use the default
            // blocking socket, but log the error and return cleanly so the
            // caller doesn't hang.
            Logger::instance().warn(
                "conntrack_flush: nl_recv failed: {}", nl_geterror(recv_n));
            if (buf) free(buf);
            return false;
        }
        // Take ownership of buf; free even on early continue/return.
        struct BufDeleter {
            void operator()(unsigned char* p) const noexcept { if (p) free(p); }
        };
        std::unique_ptr<unsigned char, BufDeleter> buf_owner(buf);
        if (recv_n == 0) {
            // Peer closed the socket — treat as end-of-dump.
            break;
        }

        // Walk every netlink message in the buffer (libnl's nlmsg_for_each_msg
        // is convenient but does it manually with NLMSG_OK so we don't pull
        // any extra libnl headers). NLMSG_NEXT mutates the length counter, so
        // iterate over a mutable copy rather than the const recv_n.
        int remaining = recv_n;
        for (struct nlmsghdr* nlh = reinterpret_cast<struct nlmsghdr*>(buf_owner.get());
             NLMSG_OK(nlh, remaining);
             nlh = NLMSG_NEXT(nlh, remaining)) {
            if (nlh->nlmsg_type == NLMSG_DONE) {
                return true;
            }
            if (nlh->nlmsg_type == NLMSG_ERROR) {
                auto* nle = static_cast<struct nlmsgerr*>(NLMSG_DATA(nlh));
                if (nle->error != 0) {
                    Logger::instance().warn(
                        "conntrack_flush: kernel error during dump: {}",
                        std::strerror(-nle->error));
                    return false;
                }
                // error==0 is an ACK; nothing to process.
                continue;
            }
            if (nlh->nlmsg_type == NLMSG_NOOP) {
                continue;
            }

            // Validate this is a CTNETLINK NEW message (the kernel responds
            // to CT_GET dumps with CT_NEW packets, one per entry).
            const uint16_t subsys = NFNL_SUBSYS_ID(nlh->nlmsg_type);
            if (subsys != NFNL_SUBSYS_CTNETLINK) {
                continue;
            }

            // Skip past the nfgenmsg header to reach the netlink attrs.
            if (nlh->nlmsg_len < NLMSG_LENGTH(sizeof(struct nfgenmsg))) {
                continue;
            }
            auto* nfh = static_cast<struct nfgenmsg*>(NLMSG_DATA(nlh));
            const uint8_t family = nfh->nfgen_family;
            const int attr_len =
                nlh->nlmsg_len - NLMSG_LENGTH(sizeof(struct nfgenmsg));
            auto* attr_head =
                reinterpret_cast<struct nlattr*>(
                    reinterpret_cast<unsigned char*>(NLMSG_DATA(nlh)) +
                    NLMSG_ALIGN(sizeof(struct nfgenmsg)));

            struct nlattr* ct_attrs[CTA_MAX + 1] = {nullptr};
            if (nla_parse(ct_attrs, CTA_MAX, attr_head, attr_len, nullptr) < 0) {
                continue;
            }
            struct nlattr* orig = ct_attrs[CTA_TUPLE_ORIG];
            const std::string dst = parse_tuple_dst(orig, family);
            if (dst.empty()) {
                continue;
            }

            ConntrackFlusher::ConntrackEntry entry;
            entry.family = family;
            entry.original_dst_ip = dst;
            if (orig) {
                // Copy the original-tuple NLA bytes verbatim so the deleter
                // can re-emit them. Tuple len includes the NLA header
                // (nla_total_size accounts for alignment padding too).
                const int total = nla_total_size(nla_len(orig));
                entry.original_tuple_blob.resize(static_cast<size_t>(total));
                std::memcpy(entry.original_tuple_blob.data(), orig,
                            static_cast<size_t>(total));
            }

            if (keep_calling) {
                keep_calling = on_entry(entry);
            }
        }
    }
    return true;
}

} // namespace

ConntrackFlusher::ConntrackFlusher(BlockingExecutor* executor)
    : ConntrackFlusher(executor,
                       [](const auto& on_entry) {
                           default_conntrack_walker(on_entry);
                       },
                       [](const ConntrackEntry& e) {
                           return default_conntrack_delete(e);
                       },
                       [](const std::vector<std::string>& only_sets) {
                           return default_kpbr_ipset_snapshot(only_sets);
                       }) {}

ConntrackFlusher::ConntrackFlusher(BlockingExecutor* executor,
                                   ConntrackWalker walker,
                                   ConntrackDeleter deleter,
                                   KpbrIpsetSnapshotProvider snapshot_provider)
    : executor_(executor),
      walker_(std::move(walker)),
      deleter_(std::move(deleter)),
      snapshot_provider_(std::move(snapshot_provider)) {}

int ConntrackFlusher::flush_async(std::vector<std::string> only_sets) {
    if (!executor_) {
        // Defensive: a daemon-less direct caller (tests use flush_sync) won't
        // hit this; production callers always supply the daemon's executor.
        Logger::instance().warn(
            "conntrack_flush: no executor configured, skipping flush");
        return 0;
    }
    const bool posted = executor_->try_post(
        "conntrack-flush",
        [this, only_sets = std::move(only_sets)]() {
            try {
                const int deleted = flush_sync(only_sets);
                if (deleted < 0) {
                    Logger::instance().verbose(
                        "conntrack_flush: pass aborted (netlink unavailable)");
                } else if (deleted > 0) {
                    Logger::instance().info(
                        "conntrack_flush: deleted {} stale entries", deleted);
                } else {
                    Logger::instance().trace("conntrack_flush_done",
                                             "deleted=0");
                }
            } catch (const std::exception& e) {
                Logger::instance().warn(
                    "conntrack_flush: pass failed: {}", e.what());
            } catch (...) {
                Logger::instance().warn(
                    "conntrack_flush: pass failed: unknown error");
            }
        });
    if (!posted) {
        Logger::instance().trace("conntrack_flush_skip", "reason=queue_full");
        return 0;
    }
    return 1;
}

int ConntrackFlusher::flush_sync(const std::vector<std::string>& only_sets) {
    if (!walker_ || !deleter_ || !snapshot_provider_) {
        return -1;
    }

    auto kpbr_members = snapshot_provider_(only_sets);
    if (!kpbr_members) {
        // No usable snapshot — refuse to delete anything. Better to leave
        // stale conntrack entries than to flush the wrong flows.
        return -1;
    }

    std::atomic<int> deleted{0};
    walker_([&](const ConntrackEntry& entry) {
        if (entry.original_dst_ip.empty()) {
            return true;
        }
        bool match = false;
        try {
            match = kpbr_members->contains(entry.original_dst_ip);
        } catch (const std::exception&) {
            // contains() throws on parser errors; treat as a non-match.
            match = false;
        }
        if (!match) {
            return true;
        }
        try {
            if (deleter_(entry)) {
                deleted.fetch_add(1, std::memory_order_relaxed);
            }
        } catch (const std::exception& e) {
            Logger::instance().trace("conntrack_flush_delete_error",
                                     "dst={} error={}",
                                     entry.original_dst_ip,
                                     e.what());
        }
        return true;
    });
    return deleted.load(std::memory_order_relaxed);
}

std::unique_ptr<IpSet> default_kpbr_ipset_snapshot(
    const std::vector<std::string>& only_sets) {
    // Scoped flush: skip enumeration entirely and read just the named sets.
    // `ipset save` per set is the expensive half of building the snapshot, so
    // narrowing here is what actually saves the work.
    if (!only_sets.empty()) {
        auto snapshot = std::make_unique<IpSet>();
        int sets_loaded = 0;
        for (const auto& name : only_sets) {
            if (!is_kpbr_set_name(name)) {
                continue;  // never read sets we don't own
            }
            auto save_result = safe_exec_capture({"ipset", "save", name},
                                                 /*suppress_stderr=*/true);
            if (save_result.exit_code != 0) {
                // A named set may legitimately not exist yet (freshly added
                // list, IPv6 set with IPv6 disabled). Skip it.
                Logger::instance().trace("conntrack_flush_save_skip",
                                         "set={} exit={}",
                                         name,
                                         save_result.exit_code);
                continue;
            }
            parse_ipset_save_members(save_result.stdout_output,
                                     [&snapshot](const std::string& member) {
                                         insert_ipset_member(*snapshot, member);
                                     });
            ++sets_loaded;
        }
        Logger::instance().trace("conntrack_flush_snapshot",
                                 "scoped=true requested={} sets_loaded={}",
                                 only_sets.size(), sets_loaded);
        return snapshot;
    }

    // One `ipset list -n` to learn every set name on the box. Cheap (kernel
    // dumps the names with no member contents).
    auto names_result = safe_exec_capture({"ipset", "list", "-n"},
                                          /*suppress_stderr=*/true);
    if (names_result.exit_code != 0) {
        Logger::instance().verbose(
            "conntrack_flush: `ipset list -n` failed (exit={}), skipping flush",
            names_result.exit_code);
        return nullptr;
    }

    auto snapshot = std::make_unique<IpSet>();
    size_t pos = 0;
    int sets_loaded = 0;
    while (pos < names_result.stdout_output.size()) {
        const size_t newline = names_result.stdout_output.find('\n', pos);
        const size_t end =
            (newline == std::string::npos) ? names_result.stdout_output.size() : newline;
        std::string name = names_result.stdout_output.substr(pos, end - pos);
        pos = (newline == std::string::npos)
                  ? names_result.stdout_output.size()
                  : newline + 1;
        // Trim trailing CR (in case the binary emits \r\n on weird builds).
        while (!name.empty() && (name.back() == '\r' || name.back() == ' ')) {
            name.pop_back();
        }
        if (name.empty() || !is_kpbr_set_name(name)) {
            continue;
        }

        auto save_result = safe_exec_capture({"ipset", "save", name},
                                             /*suppress_stderr=*/true);
        if (save_result.exit_code != 0) {
            Logger::instance().trace("conntrack_flush_save_skip",
                                     "set={} exit={}",
                                     name,
                                     save_result.exit_code);
            continue;
        }
        parse_ipset_save_members(save_result.stdout_output,
                                 [&snapshot](const std::string& member) {
                                     insert_ipset_member(*snapshot, member);
                                 });
        ++sets_loaded;
    }
    Logger::instance().trace("conntrack_flush_snapshot",
                             "sets_loaded={}", sets_loaded);
    return snapshot;
}

void default_conntrack_walker(
    const std::function<bool(const ConntrackFlusher::ConntrackEntry&)>& on_entry) {
    NlSockPtr sock = open_nfnl_socket();
    if (!sock) {
        return; // already logged
    }
    if (!walk_conntrack_dump(sock.get(), on_entry)) {
        // Errors already logged in walk_conntrack_dump.
        return;
    }
}

bool default_conntrack_delete(const ConntrackFlusher::ConntrackEntry& entry) {
    if (entry.original_tuple_blob.empty()) {
        return false;
    }
    NlSockPtr sock = open_nfnl_socket();
    if (!sock) {
        return false;
    }
    NlMsgPtr msg(nlmsg_alloc());
    if (!msg) {
        return false;
    }
    struct nfgenmsg hdr{};
    hdr.nfgen_family = entry.family;
    hdr.version = NFNETLINK_V0;
    hdr.res_id = 0;

    const uint16_t nfnl_type =
        make_nfnl_type(NFNL_SUBSYS_CTNETLINK, IPCTNL_MSG_CT_DELETE);
    struct nlmsghdr* nlh = nlmsg_put(msg.get(),
                                     NL_AUTO_PORT,
                                     NL_AUTO_SEQ,
                                     nfnl_type,
                                     0,
                                     NLM_F_REQUEST | NLM_F_ACK);
    if (!nlh) {
        return false;
    }
    if (nlmsg_append(msg.get(), &hdr, sizeof(hdr), NLMSG_ALIGNTO) < 0) {
        return false;
    }
    // Re-emit the saved CTA_TUPLE_ORIG attribute verbatim. The kernel matches
    // the conntrack entry by tuple, so this uniquely identifies the flow.
    // nlmsg_append takes a non-const void*; it only reads the buffer, so the
    // const_cast is safe.
    if (nlmsg_append(msg.get(),
                     const_cast<void*>(static_cast<const void*>(entry.original_tuple_blob.data())),
                     entry.original_tuple_blob.size(),
                     NLMSG_ALIGNTO) < 0) {
        return false;
    }

    int err = nl_send_auto(sock.get(), msg.get());
    if (err < 0) {
        Logger::instance().trace("conntrack_flush_delete_send",
                                 "error={}", nl_geterror(err));
        return false;
    }
    // Drain the ACK so the next request on this socket (none here, but for
    // protocol cleanliness) starts fresh.
    err = nl_wait_for_ack(sock.get());
    if (err < 0) {
        // ENOENT: the entry was already gone (timed out, or some peer racing
        // with us). Treat as success — desired state is achieved.
        if (err == -NLE_OBJ_NOTFOUND) {
            return true;
        }
        Logger::instance().trace("conntrack_flush_delete_ack",
                                 "dst={} error={}",
                                 entry.original_dst_ip,
                                 nl_geterror(err));
        return false;
    }
    return true;
}

} // namespace keen_pbr3
