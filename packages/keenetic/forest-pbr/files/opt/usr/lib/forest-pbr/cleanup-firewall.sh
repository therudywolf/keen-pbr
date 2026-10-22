#!/bin/sh
# Removes the firewall objects forest-pbr owns: its mangle chains KeenPbr* in
# iptables and ip6tables (with the rules that jump to them), the nftables table
# inet KeenPbrTable, and its ipsets kpbr*. A clean stop already removes all of
# this; the script covers a daemon that crashed, was killed or never finished
# starting, whose marking rules would otherwise keep steering traffic with no
# daemon behind them. It uses only iptables, ip6tables, nft and ipset, never
# forest-pbr itself. Idempotent; always exits 0.
#
#   cleanup-firewall.sh [--reason stop|uninstall]
#
# S80forest-pbr runs it after a stop, once no daemon is left, and prerm on
# package removal. Finding anything means forest-pbr did not stop cleanly, so
# that is logged as a warning naming the reason, next to one line per object.
#
# forest-pbr's policy routing rules only match its fwmarks: once nothing marks
# packets they are inert, so they are left alone.

IPTABLES="${IPTABLES:-iptables}"
IP6TABLES="${IP6TABLES:-ip6tables}"
NFT="${NFT:-nft}"
IPSET="${IPSET:-ipset}"
NFT_TABLE="KeenPbrTable"
REASON="uninstall"
[ "${1:-}" = --reason ] && [ -n "${2:-}" ] && REASON="$2"
# Set to 1 once anything was removed.
found=0

log() {
    found=1
    logger -t forest-pbr "cleanup-firewall: $1" >/dev/null 2>&1 || true
}

# cleanup_mangle <iptables command>
cleanup_mangle() {
    rules="$("$1" -t mangle -S 2>/dev/null)" || return 0
    owned="$(printf '%s\n' "$rules" | sed -n 's/^-N \(KeenPbr[^ ]*\)$/\1/p')"
    [ -n "$owned" ] || return 0
    # Every chain that is not ours: built-in (-P) and user chains (-N).
    others="$(printf '%s\n' "$rules" | sed -n 's/^-[PN] \([^ ]*\).*$/\1/p' | grep -v '^KeenPbr')"
    # Jumps into our chains are deleted by number, highest first, so the
    # remaining numbers stay valid. -L prints "num target ..." per rule.
    for chain in $others; do
        nums="$("$1" -t mangle -L "$chain" -n --line-numbers 2>/dev/null |
            awk '$1 ~ /^[0-9]+$/ && $2 ~ /^KeenPbr/ { print $1 }' | sort -rn)"
        for num in $nums; do
            "$1" -t mangle -D "$chain" "$num" 2>/dev/null &&
                log "$1 -t mangle: removed rule $num of $chain"
        done
    done
    # Flush all first: our chains may jump to each other.
    for chain in $owned; do
        "$1" -t mangle -F "$chain" 2>/dev/null
    done
    for chain in $owned; do
        "$1" -t mangle -X "$chain" 2>/dev/null && log "$1 -t mangle: removed chain $chain"
    done
}

for cmd in "$IPTABLES" "$IP6TABLES"; do
    command -v "$cmd" >/dev/null 2>&1 && cleanup_mangle "$cmd"
done

if command -v "$NFT" >/dev/null 2>&1 &&
   "$NFT" list table inet "$NFT_TABLE" >/dev/null 2>&1; then
    "$NFT" delete table inet "$NFT_TABLE" >/dev/null 2>&1 &&
        log "removed nftables table inet $NFT_TABLE"
fi

# After the rules: a set that a rule still references cannot be destroyed, and
# neither can a member of a list:set, so the kpbrm_* list:sets go first.
if command -v "$IPSET" >/dev/null 2>&1; then
    sets="$("$IPSET" list -n 2>/dev/null | grep '^kpbr')"
    for set in $(printf '%s\n' "$sets" | grep '^kpbrm_') $(printf '%s\n' "$sets" | grep -v '^kpbrm_'); do
        "$IPSET" destroy "$set" >/dev/null 2>&1 && log "removed ipset $set"
    done
fi

if [ "$found" = 1 ]; then
    logger -s -t forest-pbr -p user.warning \
        "WARNING: forest-pbr firewall rules were left behind (on $REASON: forest-pbr did not stop cleanly); removed them" \
        2>&1 || true
fi

exit 0
