#!/bin/sh
# RCI calls in S80forest-pbr are bounded by curl -m: the start waits for
# /rci/show/version at most 5 times, 1 s apart, and skips the wait without
# curl (busybox wget has no usable timeout); the component check falls back
# to plain wget only without curl.

set -u
. "$(dirname -- "$0")/lib.sh"

make_root
helpers="$T/helpers.sh"
awk '/^(fetch_rci|check_netfilter_addons_component|wait_for_keenetic_rci)\(\)/ { keep = 1 }
     keep { print }
     keep && /^}/ { keep = 0 }' "$pkg_files/opt/etc/init.d/S80forest-pbr" > "$helpers"
. "$helpers"

KEENETIC_RCI_STARTUP_ATTEMPTS=$(sed -n 's/^KEENETIC_RCI_STARTUP_ATTEMPTS=//p' "$pkg_files/opt/etc/init.d/S80forest-pbr")
[ "$KEENETIC_RCI_STARTUP_ATTEMPTS" = 5 ] || fail "KEENETIC_RCI_STARTUP_ATTEMPTS=$KEENETIC_RCI_STARTUP_ATTEMPTS"

# The fetch runs in a command substitution, so calls and the failure counter
# live in files.
LOGGED=""
fake_components='"base,opkg-kmod-netfilter,opkg-kmod-netfilter-addons,ppe"'
curl() {
    printf '|curl %s' "$*" >> "$T/calls/rci"
    if [ "$(cat "$T/fake/failures")" -gt 0 ]; then
        echo $(($(cat "$T/fake/failures") - 1)) > "$T/fake/failures"
        return 7
    fi
    case "$*" in *ndw/components*) printf '%s' "$fake_components" ;; esac
}
wget() { printf '|wget %s' "$*" >> "$T/calls/rci"; printf '%s' "$fake_components"; }
sleep() { printf '|sleep %s' "$*" >> "$T/calls/rci"; }
log() { LOGGED="$LOGGED|info:$1"; }
log_error() { LOGGED="$LOGGED|error:$1"; }
failures() { echo "$1" > "$T/fake/failures"; }
reset() { LOGGED=""; rm -f "$T/calls/rci"; }

probe="curl -s -m 2 -o /dev/null http://127.0.0.1:79/rci/show/version"

# RCI answers on the third attempt.
reset
failures 2
wait_for_keenetic_rci || fail "wait must not fail"
[ "$(calls rci)" = "|$probe|sleep 1|$probe|sleep 1|$probe" ] || fail "calls: $(calls rci)"
case "$LOGGED" in
    *"|info:Keenetic RCI became available after 3 attempts") ;;
    *) fail "log: $LOGGED" ;;
esac

# RCI never answers: 5 attempts, then the start goes on.
reset
failures 99
wait_for_keenetic_rci || fail "wait must not fail"
[ "$(printf '%s' "$(calls rci)" | grep -o 'curl ' | wc -l)" -eq 5 ] || fail "attempts: $(calls rci)"
[ "$(printf '%s' "$(calls rci)" | grep -o 'sleep ' | wc -l)" -eq 4 ] || fail "sleeps: $(calls rci)"
case "$LOGGED" in
    *"|error:Keenetic RCI is still unavailable after 5 attempts; continuing startup") ;;
    *) fail "log: $LOGGED" ;;
esac

# The component check, with curl.
reset
failures 0
check_netfilter_addons_component
[ "$(calls rci)" = "|curl -fs -m 5 http://127.0.0.1:79/rci/show/version/ndw/components" ] || fail "calls: $(calls rci)"
[ -z "$LOGGED" ] || fail "component present, yet: $LOGGED"
fake_components='"base,opkg-kmod-netfilter,ppe"'
check_netfilter_addons_component
[ "$LOGGED" = "|error:Missing Keenetic component opkg-kmod-netfilter-addons" ] || fail "log: $LOGGED"
reset
failures 1
check_netfilter_addons_component
[ "$LOGGED" = "|error:Failed to fetch installed Keenetic components" ] || fail "log: $LOGGED"

# Without curl: no RCI wait at all, and plain wget for the components.
unset -f curl
mkdir -p "$T/empty"
reset
saved_path=$PATH
PATH="$T/empty"
wait_for_keenetic_rci
rc=$?
PATH=$saved_path
[ "$rc" = 0 ] || fail "wait must not fail"
[ -z "$(calls rci)" ] || fail "calls without curl: $(calls rci)"
[ "$LOGGED" = "|info:curl is not installed; not waiting for Keenetic RCI" ] || fail "log: $LOGGED"
PATH="$T/empty"
check_netfilter_addons_component
PATH=$saved_path
[ "$(calls rci)" = "|wget -O - localhost:79/rci/show/version/ndw/components" ] || fail "calls: $(calls rci)"

pass
