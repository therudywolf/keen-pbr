# Router-side tuning for forest-pbr on a weak Keenetic

> Targets **KN-1011** class hardware: MT7621 dual-core MIPS @ 880 MHz, 512 MB
> RAM, NDMS firmware. Other Keenetic models are similar order of magnitude.
> This doc lists the kernel/dnsmasq knobs that materially help once the daemon
> itself is healthy. None of these are auto-applied — review and apply by hand.

## What the daemon already does for you

- Disables Keenetic's HW NAT (`net.netfilter.nf_conntrack_fastnat`) on **every**
  netfilter event so marked packets always reach the `mangle` table. Without
  this, PBR silently breaks after any ACL rebuild. (Hook:
  `/opt/etc/ndm/netfilter.d/50-forest-pbr-routing.sh`.)
- Throttles the dnsmasq config-hash TXT probe to once per 30s (was 5s upstream),
  saving DNS chatter on slow MIPS CPUs.
- Coalesces bursts of NDM netfilter events into a single firewall refresh.

What's left below is environmental — kernel limits and dnsmasq cache shape — and
fixing the symptoms most users on a Keenetic actually hit.

## Conntrack

Default Keenetic `nf_conntrack_max` is usually 8192–16384, which one busy
workstation can exhaust by itself (each TCP/UDP/ICMP flow eats an entry). Once
the table is full, **new connections silently fail** until something expires.

```sh
# Inspect current values
sysctl net.nf_conntrack_max
sysctl net.netfilter.nf_conntrack_count
cat /proc/sys/net/netfilter/nf_conntrack_buckets

# Raise the table to 65k entries (≈ 22 MB RAM for the table + buckets)
echo 65536 > /proc/sys/net/nf_conntrack_max
echo 16384 > /proc/sys/net/netfilter/nf_conntrack_buckets   # max/4 is the rule of thumb
```

Persistence on Keenetic: drop these in
`/opt/etc/init.d/S99-localtune` (create if missing, chmod +x):

```sh
#!/bin/sh
echo 65536 > /proc/sys/net/nf_conntrack_max 2>/dev/null
echo 16384 > /proc/sys/net/netfilter/nf_conntrack_buckets 2>/dev/null
```

### TCP timeout tuning

The default `nf_conntrack_tcp_timeout_established` is **5 days**. On a router
this means a stale flow holds an entry for almost a week even after the client
shuts down. On a small table this matters; on a tuned 65k table it doesn't —
but if you don't want to bump the table, shrink the timeout instead:

```sh
echo 7200 > /proc/sys/net/netfilter/nf_conntrack_tcp_timeout_established  # 2h
```

Don't go below 1800 (30 min) or you'll start cutting legitimate idle SSH and
WebSocket connections.

## dnsmasq

Defaults on the Forest-PBR-shipped `dnsmasq.conf`:

```
cache-size=1000
max-cache-ttl=300
clear-on-reload
```

This is fine for a small house. Two tweaks worth knowing about:

### `cache-size`

- Up: more memory in dnsmasq, fewer upstream queries, faster repeat lookups.
- Down to `0`: pass-through mode, every lookup hits the upstream (NextDNS/DoT
  proxy). Worth doing **only** if you want every DNS answer to also re-populate
  the forest-pbr ipsets (since dnsmasq does NOT refresh ipset entries when it
  serves from cache — see `ListWarmer` in the daemon for the workaround).

For most users, leaving cache-size at 1000 + relying on `ListWarmer` is the
better trade-off: low DNS chatter + warm ipsets.

### `max-cache-ttl`

Caps how long dnsmasq will hold any cached answer regardless of upstream TTL.
At the default 300s, dnsmasq forgets a lookup after 5 minutes even if the
upstream said "cache for 1 hour".

Lowering this to e.g. 60s makes ipset populations refresh more often (because a
re-query forces a fresh resolve that hits the ipset write path). The cost is
more upstream DNS load. With local DoT proxies this is essentially free.

## Routing tables

The daemon manages ip rules at priorities **150–154** for the wan/rostelecom/
local/wg_server/forestserver_ru outbounds. Keenetic's NDM owns priorities
< 32766 too, but uses 102–107 in practice. Don't touch the 150–154 block by
hand — let the daemon own it.

## Memory shape

A healthy KN-1011 with forest-pbr looks like:

| Component | RAM | Notes |
|---|---|---|
| forest-pbr daemon | ~100 MB | grows with config size; 84-list config sat at 98 MB |
| 239 ipsets | ~4 MB | most are sparse hash:net with 1024 hashsize |
| dnsmasq | ~3 MB | tied to `cache-size` |
| conntrack table (65k) | ~22 MB | at max fill |
| Keenetic NDM core | ~150 MB | not yours to tune |
| Free for buffers/cache | ~200 MB | what's left |

If `free` shows < 50 MB available consistently, the first place to look is the
forest-pbr config — bloated lists (deleted in this fork's audit pass, where
`epic` alone was eating 1.6 MB of disk/RAM) make the daemon's hash tables
oversized.

## Useful diagnostic one-liners

Watch conntrack saturation:
```sh
watch -n2 'awk "{print \$1}" /proc/sys/net/netfilter/nf_conntrack_count; \
           awk "{print \$1}" /proc/sys/net/nf_conntrack_max'
```

See which client is opening the most flows:
```sh
grep -oE 'src=10\.77\.77\.[0-9]+' /proc/net/nf_conntrack | sort | uniq -c | sort -rn | head
```

Check that the fastnat watchdog is holding (must read `0`):
```sh
sysctl net.netfilter.nf_conntrack_fastnat
```

Verify the netfilter.d hook md5 matches the shipping version (the hash
guarantees the universal-table watchdog is in place):
```sh
md5sum /opt/etc/ndm/netfilter.d/50-forest-pbr-routing.sh
# Expected: 30f38cdf45b06d5c160ce1584f263edd
```

Show what dnsmasq actually loaded for forest-pbr:
```sh
/opt/usr/lib/forest-pbr/dnsmasq.sh dnsmasq-config-entry | head -30
```

## When you've tuned everything and it's still slow

Two real culprits left:

1. **Bloated lists.** Run `du` on `/opt/etc/forest-pbr/config.json` — anything
   over ~200 KB is suspicious. The Forest-PBR audit pass in May 2026 cut a real
   user's config from 1.8 MB to 36 KB without losing any working routes.
2. **The VPN itself is the bottleneck.** Test directly:
   ```sh
   curl -s -o /dev/null --interface nwg2 -w 'rtt=%{time_total}s\n' \
        --max-time 8 https://1.1.1.1
   ```
   If that's > 500 ms or times out, no amount of router tuning helps — the
   tunnel needs work upstream (peer reachability, MTU, key rotation).
