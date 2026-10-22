#!/bin/sh
# Kernel module loading in S80forest-pbr: one helper; a module that is present
# is silent, a missing required one is an error, a missing optional one
# (xt_multiport, absent on the KN-1011) only a warning.

set -u
. "$(dirname -- "$0")/lib.sh"

make_root
helpers="$T/helpers.sh"

# Only the module helpers; sysfs, /proc listings, insmod and logging are
# replaced below, so nothing touches the real system.
awk '/^(kernel_module_present|load_kernel_module|report_module_failure|ensure_ipset_modules_loaded|ensure_ipv6_modules_loaded|ensure_routing_modules_loaded)\(\)/ { keep = 1 }
     keep { print }
     keep && /^}/ { keep = 0 }' "$pkg_files/opt/etc/init.d/S80forest-pbr" |
    sed "s#/proc/net/#$T/proc/#g" > "$helpers"
. "$helpers"

KERNEL_MODULE_SYSFS="$T/sys/module"
IPSET_PROBE_SET=kpbr_probe_hash_net
IPSET_COMPONENTS_MESSAGE="ipset kernel modules are not available."
mkdir -p "$T/proc" "$T/lib"
LOGGED=""
module_path_for() { printf '%s/lib/%s.ko\n' "$T" "$1"; }
insmod() {
    case "$1" in
        */xt_tcpudp.ko) echo "Unknown symbol in module" >&2; return 1 ;;
    esac
    # Runs in a command substitution: record the call in a file.
    printf ' %s' "$(basename "$1" .ko)" >> "$T/inserted"
}
ipset_hash_net_available() { [ -f "$T/ipset-works" ]; }
log() { LOGGED="$LOGGED|info:$1"; }
log_warn() { LOGGED="$LOGGED|warn:$1"; }
log_error() { LOGGED="$LOGGED|error:$1"; }
inserted() { cat "$T/inserted" 2>/dev/null; }

# xt_mark is loaded (sysfs), xt_conntrack is built in (listed in the matches
# file), xt_tcpudp fails to load, xt_multiport has no .ko at all.
mkdir -p "$KERNEL_MODULE_SYSFS/xt_mark"
printf 'conntrack\nset\n' > "$T/proc/ip_tables_matches"
: > "$T/lib/xt_tcpudp.ko"
ensure_routing_modules_loaded
[ -z "$(inserted)" ] || fail "unexpected insmod calls:$(inserted)"
expected="|error:failed to load kernel module $T/lib/xt_tcpudp.ko (Unknown symbol in module): the firewall rules cannot be applied|warn:kernel module xt_multiport is not loaded and $T/lib/xt_multiport.ko does not exist: rules with port lists cannot be applied"
[ "$LOGGED" = "$expected" ] || fail "routing modules: [$LOGGED]"

# A module that loads is logged once.
LOGGED=""
rm -f "$T/inserted"
mv "$T/lib/xt_tcpudp.ko" "$T/lib/xt_multiport.ko"
load_kernel_module optional xt_multiport "$T/proc/ip_tables_matches:multiport" "x"
[ $? = 0 ] || fail "a module that loads must return 0"
[ "$(inserted)" = " xt_multiport" ] || fail "insmod calls:$(inserted)"
[ "$LOGGED" = "|info:Loaded kernel module $T/lib/xt_multiport.ko" ] || fail "load message: [$LOGGED]"

# Return codes, and probe failures stay silent.
LOGGED=""
load_kernel_module probe nf_conntrack_ipv6 "" ""
[ $? = 1 ] || fail "a missing module must return 1"
: > "$T/lib/xt_tcpudp.ko"
load_kernel_module probe xt_tcpudp "" ""
[ $? = 2 ] || fail "an insmod failure must return 2"
[ -z "$LOGGED" ] || fail "probe failures must be silent: [$LOGGED]"

# ipset works: no ipset module is touched, xt_set (built in) is silent.
LOGGED=""
rm -f "$T/inserted"
: > "$T/ipset-works"
ensure_ipset_modules_loaded
[ -z "$(inserted)" ] && [ -z "$LOGGED" ] || fail "working ipset: [$LOGGED]$(inserted)"

# ipset does not work: the ipset modules are tried quietly and one error
# names the failed probe; a missing xt_set is an error of its own.
rm -f "$T/ipset-works" "$T/inserted"
: > "$T/lib/ip_set.ko"
: > "$T/proc/ip_tables_matches"
ensure_ipset_modules_loaded
[ "$(inserted)" = " ip_set" ] || fail "ipset fallback insmod calls:$(inserted)"
case "$LOGGED" in
    "|info:Loaded kernel module $T/lib/ip_set.ko|error:ipset kernel modules are not available. Required probe failed: ipset create kpbr_probe_hash_net hash:net family inet -exist|error:kernel module xt_set is not loaded and $T/lib/xt_set.ko does not exist: routing rules cannot match ipset lists") ;;
    *) fail "ipset fallback: [$LOGGED]" ;;
esac

# The IPv6 preload stays best effort and quiet.
LOGGED=""
ensure_ipv6_modules_loaded
[ -z "$LOGGED" ] || fail "IPv6 preload must be quiet: [$LOGGED]"

pass
