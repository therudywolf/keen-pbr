#!/bin/sh
# fastnat at start in S80forest-pbr: switched off for all traffic unless the
# user created fastnat.enabled and the kernel has the PPE target; then it is
# switched back on only while NDM's software accelerator (net.core.swnat) is.

set -u
. "$(dirname -- "$0")/lib.sh"

make_root
helpers="$T/helpers.sh"

# Only the fastnat helpers; /opt, /proc listings, sysctl and logging are
# replaced below, so nothing touches the real system.
awk '/^(enable_hwnat|disable_hwnat|fastnat_allowed|apply_fastnat_policy)\(\)/ { keep = 1 }
     keep { print }
     keep && /^}/ { keep = 0 }' "$pkg_files/opt/etc/init.d/S80forest-pbr" |
    sed -e "s#/proc/net/#$T/proc/#g" -e "s#/opt/#$T/opt/#g" > "$helpers"
grep -q '^apply_fastnat_policy()' "$helpers" || fail "apply_fastnat_policy not found"
. "$helpers"

mkdir -p "$T/proc"
LOGGED=""
log() { LOGGED="$LOGGED|$1"; }
sysctl() {
    case "$1" in
        -n) cat "$T/fake/$2" 2>/dev/null ;;
        -w) printf '%s\n' "$2" >> "$T/calls/sysctl" ;;
    esac
}

start() {
    rm -f "$T/calls/sysctl"
    LOGGED=""
    apply_fastnat_policy || fail "apply_fastnat_policy failed"
}

off="net.ipv4.netfilter.ip_conntrack_fastnat=0
net.netfilter.nf_conntrack_fastnat=0"
on="net.ipv4.netfilter.ip_conntrack_fastnat=1
net.netfilter.nf_conntrack_fastnat=1"
echo 1 > "$T/fake/net.core.swnat"

# No flag: off, whatever the kernel has.
printf 'MARK\nPPE\n' > "$T/proc/ip_tables_targets"
start
[ "$(calls sysctl)" = "$off" ] || fail "no flag: $(calls sysctl)"

# Flag without the PPE target: off.
: > "$T/opt/etc/forest-pbr/fastnat.enabled"
printf 'MARK\nCONNMARK\n' > "$T/proc/ip_tables_targets"
start
[ "$(calls sysctl)" = "$off" ] || fail "flag without PPE: $(calls sysctl)"

# Flag and target: on again, since NDM's software accelerator is on.
printf 'MARK\nPPE\n' > "$T/proc/ip_tables_targets"
start
[ "$(calls sysctl)" = "$on" ] || fail "flag and PPE: $(calls sysctl)"
case "$LOGGED" in
    *"stays on"*) ;;
    *) fail "the kept accelerator is not logged: [$LOGGED]" ;;
esac

# ... but left alone while NDM keeps its software accelerator off.
echo 0 > "$T/fake/net.core.swnat"
start
[ -z "$(calls sysctl)" ] || fail "swnat off: fastnat touched: $(calls sysctl)"

pass
