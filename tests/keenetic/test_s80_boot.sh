#!/bin/sh
# S80forest-pbr started by rc.unslung at boot and by hand.
#
# rc.unslung (a replica of Entware's) runs the init script as its child. The
# script must detach its start sequence and return at once, and the detached
# sequence must hold the dnsmasq reapply (whose RCI dns-proxy call hangs while
# NDM holds its OPTWARE lock for rc.unslung) until that rc.unslung has exited.
# A start by hand does not detach.

set -u
. "$(dirname -- "$0")/lib.sh"

make_root
install_init_script
install_rc_unslung
echo 3 > "$T/fake/rc-unslung-tail"
: > "$T/fake/rci-blocked"

# --- boot: rc.unslung forks the script ------------------------------------
started=$(date +%s)
sh "$T/opt/etc/init.d/rc.unslung" start > /dev/null 2>&1 &
rc_unslung_pid=$!
wait "$rc_unslung_pid"
elapsed=$(( $(date +%s) - started ))

# The tail alone takes 3 s. Without the detach the start sequence would run
# inside rc.unslung and its dnsmasq reapply would wait for rc.unslung itself.
[ "$elapsed" -le 5 ] || fail "rc.unslung took ${elapsed}s: the start did not detach"
calls start-stop-daemon | grep -q "^detached=1 parent=$rc_unslung_pid args=-S -b " ||
    fail "start-stop-daemon was not asked to detach with rc.unslung's PID: $(calls start-stop-daemon)"

wait_for 15 daemon_running || fail "detached start did not launch the daemon"
wait_for 15 grep -q 'reapply_dnsmasq_config end rc=0' "$T/opt/var/log/forest-pbr-boot.log" ||
    fail "detached start did not finish: $(cat "$T/opt/var/log/forest-pbr-boot.log")"

[ "$(calls dnsmasq.sh)" = "activate after-rc-unslung" ] ||
    fail "dnsmasq config reapplied while rc.unslung was still running: $(calls dnsmasq.sh)"
boot_log=$(cat "$T/opt/var/log/forest-pbr-boot.log")
case "$boot_log" in
    *"from rc.unslung (pid $rc_unslung_pid), detaching"*"detached start: launching daemon"*"rc.unslung (pid $rc_unslung_pid) has exited"*"rci probe show/dns-proxy"*"reapply_dnsmasq_config begin"*) ;;
    *) fail "unexpected boot log: $boot_log" ;;
esac
calls curl | grep -q 'rci/show/version' || fail "the detached start did not wait for RCI"

pid=$(daemon_pid)
init_script stop > /dev/null 2>&1
wait_for 5 process_gone "$pid" || fail "daemon still running after stop"

# --- by hand: no detach -----------------------------------------------------
rm -f "$T/fake/rci-blocked" "$T/calls/start-stop-daemon" "$T/calls/dnsmasq.sh"
boot_log_before=$(cat "$T/opt/var/log/forest-pbr-boot.log")
init_script start > /dev/null 2>&1 || fail "start by hand failed"
daemon_running || fail "start by hand did not launch the daemon"
[ -z "$(calls start-stop-daemon)" ] || fail "start by hand detached"
[ "$(calls dnsmasq.sh)" = "activate" ] || fail "start by hand did not reapply the dnsmasq config: $(calls dnsmasq.sh)"
[ "$(cat "$T/opt/var/log/forest-pbr-boot.log")" = "$boot_log_before" ] ||
    fail "start by hand wrote to the boot log"

init_script stop > /dev/null 2>&1
[ "$(calls dnsmasq.sh)" = "activate
deactivate" ] || fail "stop did not deactivate the dnsmasq config: $(calls dnsmasq.sh)"

pass
