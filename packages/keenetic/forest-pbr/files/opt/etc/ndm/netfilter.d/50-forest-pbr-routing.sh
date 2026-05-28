#!/opt/bin/sh

# Re-assert HW NAT (fastnat) is disabled on ANY netfilter change, regardless of
# which table was touched. NDM silently flips fastnat back on across a range of
# events (firmware reconfigure, VPN reconnects, ACL changes that only touch the
# filter table). When fastnat is on, marked packets bypass mangle entirely, so
# forest-pbr's PBR marks never fire and LAN clients get routed via default WAN
# (i.e. RKN-blocked for sites that need the VPN outbound). Keep this BEFORE the
# table guard below so the watchdog fires for every netfilter event, not just
# mangle/nat ones.
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

# Firewall reapply is only relevant when NDM touched mangle/nat — those are the
# tables forest-pbr writes to. A filter-table rebuild doesn't disturb our marks
# or NAT rules, so skip the SIGUSR1 in that case to avoid pointless work.
if [ "$table" = "mangle" ] || [ "$table" = "nat" ]; then
    logger -t "forest-pbr" "Refreshing routing state after netfilter change (table=$table)"
    /opt/etc/init.d/S80forest-pbr reapply-firewall >/dev/null 2>&1 || true
fi

if [ -f /opt/etc/forest-pbr/hook.sh ]; then
    keen_pbr_hook="netfilter"
    . /opt/etc/forest-pbr/hook.sh
fi

exit 0
