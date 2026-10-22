#!/opt/bin/sh

# Re-assert HW NAT (fastnat) is disabled on ANY netfilter change, regardless of
# which table was touched. NDM silently flips fastnat back on across a range of
# events (firmware reconfigure, VPN reconnects, ACL changes that only touch the
# filter table). When fastnat is on, marked packets bypass mangle entirely, so
# forest-pbr's PBR marks never fire and LAN clients get routed via default WAN
# (i.e. RKN-blocked for sites that need the VPN outbound). Keep this BEFORE the
# table guard below so the watchdog fires for every netfilter event, not just
# mangle ones.
#
# Hot-path cost: two sysctl reads; sysctl -w is skipped when already zero.
for _key in net.ipv4.netfilter.ip_conntrack_fastnat net.netfilter.nf_conntrack_fastnat; do
    _val="$(sysctl -n "$_key" 2>/dev/null)"
    [ -z "$_val" ] && continue
    if [ "$_val" != "0" ]; then
        sysctl -w "$_key=0" 2>/dev/null || true
        logger -t "forest-pbr" "Re-disabled HW NAT fastnat ($_key was $_val, table=$table)"
    fi
done
unset _key _val

# NDM calls this hook after it rebuilt one table: $type is iptables or
# ip6tables, $table the table. forest-pbr only writes the mangle table (its
# KeenPbrTable chain and the PREROUTING jump, IPv4 and IPv6), so only a mangle
# rebuild can have dropped its rules. Rebuilds of nat (UPnP, about once a
# minute) and filter leave them alone and no longer cost a full refresh.
if [ "$table" = "mangle" ]; then
    logger -t "forest-pbr" "Refreshing routing state after netfilter change (type=$type table=$table)"
    /opt/etc/init.d/S80forest-pbr reapply-firewall >/dev/null 2>&1 || true
fi

if [ -f /opt/etc/forest-pbr/hook.sh ]; then
    keen_pbr_hook="netfilter"
    . /opt/etc/forest-pbr/hook.sh
fi

exit 0
