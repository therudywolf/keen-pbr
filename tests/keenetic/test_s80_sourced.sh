#!/bin/sh
# S80forest-pbr sourced by an rc.unslung-like caller.
#
# Entware's rc.unslung forks the init scripts (see test_s80_boot.sh), but the
# script also detaches when a caller named rc.unslung sources it. Such a caller
# must get control back and go on with the rest of its scripts: the init
# script may not end it with `exit`.

set -u
. "$(dirname -- "$0")/lib.sh"

make_root
install_init_script
cat > "$T/opt/etc/init.d/rc.unslung-sim" <<'SIM'
. "$FAKE_ROOT/opt/etc/init.d/S80forest-pbr" "$1"
: > "$FAKE_ROOT/calls/caller-continued"
SIM

sh "$T/opt/etc/init.d/rc.unslung-sim" start > /dev/null 2>&1
[ -e "$T/calls/caller-continued" ] || fail "the sourcing caller did not get control back"
calls start-stop-daemon | grep -q '^detached=1 ' ||
    fail "the sourced start did not detach: $(calls start-stop-daemon)"

wait_for 15 daemon_running || fail "detached start did not launch the daemon"
wait_for 15 grep -q 'reapply_dnsmasq_config end rc=0' "$T/opt/var/log/forest-pbr-boot.log" ||
    fail "detached start did not finish: $(cat "$T/opt/var/log/forest-pbr-boot.log")"

pid=$(daemon_pid)
init_script stop > /dev/null 2>&1
wait_for 5 process_gone "$pid" || fail "daemon still running after stop"

pass
