# SNI-based split routing — implementation plan

> **Status:** design only. Not implemented. This document lays out what would
> need to be built to support per-domain routing of shared-CDN destinations
> (e.g. drive.google.com via WAN while youtube.com via VPN), because pure
> IP-level routing cannot do this — Google's CDN edges serve all their
> properties from the same address pool.

## Problem statement

Forest-PBR routes by destination IP via `match-set kpbrm_X dst`. When two
domains belonging to different routing rules resolve to the same CDN edge:

```
drive.google.com   → 216.58.198.206  (user wants → Rostelecom / WAN)
www.youtube.com    → 216.58.198.206  (user wants → VPN)
```

iptables only sees the destination IP. It can't tell whether the connection
is "for Drive" or "for YouTube." Whichever rule fires first wins for both,
breaking the split.

This is a fundamental limitation of IP-level routing for shared infrastructure.
Google, Microsoft, Apple, Cloudflare, AWS — they all share edges. The
workaround in the current code is to merge "Drive must NOT go VPN" with
"YouTube must go VPN" into one decision (both via VPN, or both best-effort)
and accept the trade-off.

A real per-domain split requires looking *inside* the TCP/TLS connection at
the SNI (Server Name Indication) field in the TLS ClientHello — the only
place the client tells the server which hostname it wants. SNI is in plaintext
for TLS 1.2 and TLS 1.3 without ECH (Encrypted Client Hello, still rare in
practice).

## High-level approach

Add a userspace TLS-aware demarcator that:
1. **Intercepts** outgoing TLS handshakes from LAN.
2. **Reads** the first record (TCP segment) of the connection, parses the
   TLS ClientHello, extracts the SNI value.
3. **Re-marks** the conntrack entry of that flow based on which routing
   rule the SNI matches.
4. **Lets** the packet continue — subsequent packets of the same flow inherit
   the new mark via `CONNMARK --restore-mark`.

Two reasonable kernel-level designs:

### Option 1 — NFQUEUE userspace daemon

- iptables rule: tee the first TCP packet of every NEW LAN→WAN port 443
  connection into NFQUEUE.
- A small userspace daemon (Python or C) reads from the queue, parses TLS
  ClientHello, decides the routing class, sets `--mark`, returns the verdict.
- Use `conntrack --update --mark X` (or `CONNMARK --save-mark`) so all
  subsequent packets of the flow inherit the mark.

**Pros**: standard kernel feature, well-trodden path (used by sslh, sniproxy,
ipt-netflow plugins).
**Cons**: NFQUEUE has per-packet overhead, but only the first segment is
queued so it's bounded.
**Effort**: ~600 lines of C++ + a few iptables rules. 1-2 days work.

### Option 2 — eBPF / XDP TC classifier

- Attach a TC classifier on br0 ingress that sniffs the first segment of port
  443 flows.
- Parse ClientHello in-kernel (limited but doable for SNI).
- Set skb mark inline — no userspace round-trip.

**Pros**: very fast, no NFQUEUE overhead.
**Cons**: Keenetic kernel may not have BPF TC support; kernel BPF on a 4.9
MIPS kernel is sketchy; in-kernel TLS parsing is fragile.
**Effort**: harder, requires kernel feature audit first.

For KN-1011 (MIPS 4.9 kernel), **Option 1 is the right call.**

## Concrete iptables shape

```sh
# Tee the first 1 KB of every NEW LAN→443 TCP flow into NFQUEUE 17.
# `connbytes 0:1024` matches only while the connection has < 1 KB of bytes —
# i.e. the first segment with the ClientHello.
iptables -t mangle -A PREROUTING -i br0 -p tcp --dport 443 \
    -m conntrack --ctstate NEW \
    -m connbytes --connbytes 0:1024 --connbytes-mode bytes --connbytes-dir original \
    -j NFQUEUE --queue-num 17 --queue-bypass

# Save the mark set by the userspace daemon into conntrack
iptables -t mangle -A PREROUTING -i br0 -p tcp --dport 443 \
    -m mark --mark 0x50000/0xff0000 \
    -j CONNMARK --save-mark --nfmask 0xff0000 --ctmask 0xff0000

# Restore the conntrack mark to subsequent packets of the flow
iptables -t mangle -A PREROUTING -i br0 -p tcp --dport 443 \
    -m mark --mark 0/0xff0000 \
    -j CONNMARK --restore-mark --nfmask 0xff0000 --ctmask 0xff0000
```

`--queue-bypass` is important: if the daemon dies, packets are ACCEPTed by
default instead of dropped — the system degrades gracefully to current
IP-based routing rather than killing all HTTPS.

## SNI parser sketch (Python / C++)

The TLS ClientHello structure is fixed-prefix:

```
byte  0       = 0x16 (handshake)
bytes 1-2     = TLS version (0x0301/0x0302/0x0303)
bytes 3-4     = record length
byte  5       = 0x01 (handshake type: ClientHello)
bytes 6-8     = handshake length (3 bytes)
bytes 9-10    = client version
bytes 11-42   = client random (32 bytes)
byte  43      = session ID length
... session ID
... cipher suites length + cipher suites
... compression methods length + compression methods
... extensions length
... extensions:
    each extension: type(2) length(2) data
    extension type 0x0000 == server_name extension
      list length (2)
      type (1) = 0x00 (host_name)
      hostname length (2)
      hostname (ASCII)
```

About 80 lines of straightforward parsing. Handle:
- Fragmented ClientHello (first packet may not contain the whole hello — rare
  but real).
- Encrypted Client Hello (ECH) — when present, the outer SNI is `inner-relay`
  or similar. No domain visible. Fall back to default IP-based routing.
- Non-TLS port 443 traffic (QUIC, HTTP/3) — see below.

## QUIC / HTTP/3 caveat

Browsers and apps prefer QUIC (UDP/443) over TCP/443 these days. QUIC's
ClientHello is encrypted inside QUIC initial packet, but it can be decrypted
deterministically (the key derivation uses public values from the packet).

For SNI inspection of QUIC:
- The complexity is real: need QUIC packet number unprotection + key
  derivation per RFC 9001 + ClientHello extraction.
- Existing libraries: `quictls`, fragments of `nghttp3`, `lsquic`.
- Alternative: **disable QUIC for LAN clients** by `iptables -A FORWARD -i br0
  -p udp --dport 443 -j REJECT`. Browsers fall back to TCP/443. Forest-PBR's
  SNI inspection then catches everything. Trade-off: HTTP/3 perf loss on LAN,
  but it's a router for a home, not a CDN — fine.

I recommend **blocking QUIC** as the pragmatic v1.

## Routing decision logic

The userspace daemon needs a way to match SNI → rule. Reuse forest-pbr's
existing list/rule structure:

```cpp
struct SniRouter {
    // Pre-built at start-up by walking config.lists[*].domains and the
    // route.rules referencing them. Each domain → rule index.
    std::map<std::string, int> exact_to_rule;     // "drive.google.com" → rule 0
    std::vector<std::pair<std::string, int>> suffix_to_rule;  // ".youtube.com" → rule 1

    int classify(const std::string& sni) const {
        auto it = exact_to_rule.find(sni);
        if (it != exact_to_rule.end()) return it->second;
        for (auto& [suffix, rule] : suffix_to_rule)
            if (ends_with(sni, suffix)) return rule;
        return -1;  // no rule — let IP-based fallback decide
    }
};
```

The mark to set is `rule_index << 16 | 0x?0000` — same scheme forest-pbr's
firewall layer already uses.

## Performance on KN-1011

- MT7621 MIPS at 880 MHz, 512 MB RAM.
- NFQUEUE per-packet cost: ~20-50 µs on this CPU for a small daemon.
- TLS ClientHello parsing: ~10 µs.
- Connections per second peak: ~50 cps (typical home use).
- Total CPU: well under 1 %.
- Memory: the daemon process, ~5 MB resident.

Verdict: feasible. Not free, but cheap enough that the KN-1011 won't notice.

## Failure modes & graceful degradation

1. **Daemon crashes.** `--queue-bypass` lets packets through unmodified.
   IP-based routing takes over. Whichever rule wins for the destination IP
   wins. Worst case: same behaviour as today.
2. **SNI not present** (ECH, non-TLS). Daemon returns ACCEPT without setting
   mark. IP-based fallback.
3. **NFQUEUE backlog.** With `--queue-bypass` + sane queue depth (1024),
   packets are ACCEPTed rather than dropped.

## Test plan

Same approach as the firewall integration tests already in
`tests/firewall_it/`: spin up a netns + a docker container, send TLS
handshakes to a mock server with controlled SNI values, verify the conntrack
mark is set correctly.

## Why this is "later, not now"

The current state — drop google_disk/phonelink from the rostelecom rule and
accept that shared CDN IPs route via VPN — covers the user's hot path
(YouTube/Gemini works on the phone) with **zero new code**. SNI inspection
would add a moving part to a router that has been running stable for weeks.

Implement only when:
- A specific user-visible need to keep Drive on Rostelecom (e.g. bandwidth
  cap on the VPN, or a censorship case where Drive must look like a Russian
  request).
- Or when adding similar split-routing for another shared-CDN target.

## Estimated effort

- C++ daemon + NFQUEUE + SNI parser: 600 LOC, 1-2 days
- iptables wiring + tests: 200 LOC, 0.5 days
- Integration into existing forest-pbr daemon lifecycle: 0.5 days
- **Total: 2-3 days of focused work**

If/when needed, file an issue and link this doc.
