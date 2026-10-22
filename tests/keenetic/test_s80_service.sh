#!/bin/sh
# S80forest-pbr start/stop/check through rc.func: "running" means the PID file
# names a live forest-pbr process, not that some forest-pbr process exists.

set -u
. "$(dirname -- "$0")/lib.sh"

make_root
install_init_script
echo 2 > "$T/fake/rc-func-limit"
# Wait 2 s, not 15, for a daemon that does not stop.
sed -i 's/^STOP_WAIT_SECONDS=15$/STOP_WAIT_SECONDS=2/' "$T/opt/etc/init.d/S80forest-pbr"
grep -qx 'STOP_WAIT_SECONDS=2' "$T/opt/etc/init.d/S80forest-pbr" || fail "STOP_WAIT_SECONDS not found"
printf '#!/bin/sh\necho "$*" >> "$FAKE_ROOT/calls/cleanup-firewall"\n' \
    > "$T/opt/usr/lib/forest-pbr/cleanup-firewall.sh"
chmod +x "$T/opt/usr/lib/forest-pbr/cleanup-firewall.sh"

# Background processes are started from a subshell, so this shell reports
# nothing when they are killed; the EXIT trap kills what is left.
in_background() {
    ( "$@" > /dev/null 2>&1 & echo $! )
}

# A forest-pbr CLI that hangs (in RCI, say) is not the daemon.
echo 30 > "$T/fake/cli-sleep"
cli_pid=$(in_background "$T/opt/usr/bin/forest-pbr" --config "$T/opt/etc/forest-pbr/config.json" \
    generate-resolver-config dnsmasq-ipset)
wait_for 5 "$T/opt/bin/pidof" forest-pbr > /dev/null || fail "the hanging CLI did not start"
rm -f "$T/fake/cli-sleep"
out=$(init_script start 2>&1)
case "$out" in
    *"already running"*) fail "a hanging CLI was taken for the daemon" ;;
esac
daemon_running || fail "start did not launch the daemon next to a hanging CLI"
[ "$(init_script check)" = alive ] || fail "check does not see the daemon"
kill -9 "$cli_pid" 2>/dev/null

# A daemon killed with -9 leaves its PID file: dead, and start launches a new one.
old_pid=$(daemon_pid)
kill -9 "$old_pid"
wait_for 5 process_gone "$old_pid" || fail "daemon survived kill -9"
[ "$(init_script check)" = dead ] || fail "check trusts a PID file without a process"

# ... also when that PID now belongs to another program.
printf '#!/bin/sh\nsleep 30\n' > "$T/other-program"
chmod +x "$T/other-program"
other_pid=$(in_background "$T/other-program")
wait_for 5 grep -qs other-program "/proc/$other_pid/comm" || fail "other-program did not start"
echo "$other_pid" > "$T/opt/var/run/forest-pbr.pid"
[ "$(init_script check)" = dead ] || fail "check trusts a PID file naming another program"
init_script start > /dev/null 2>&1
daemon_running && [ "$(daemon_pid)" != "$other_pid" ] ||
    fail "start did not replace a PID file naming another program"
kill "$other_pid" 2>/dev/null

# --- stop, then cleanup-firewall.sh once no daemon is left -----------------
pid=$(daemon_pid)
init_script stop > /dev/null 2>&1 || fail "stop failed"
process_gone "$pid" || fail "stop left the daemon running"
[ "$(calls cleanup-firewall)" = "--reason stop" ] ||
    fail "cleanup after a clean stop: $(calls cleanup-firewall)"

# A daemon killed with -9 cannot clean up: stop still runs the cleanup.
rm -f "$T/calls/cleanup-firewall"
init_script start > /dev/null 2>&1
pid=$(daemon_pid)
kill -9 "$pid"
wait_for 5 process_gone "$pid" || fail "daemon survived kill -9"
init_script stop > /dev/null 2>&1
[ "$(calls cleanup-firewall)" = "--reason stop" ] ||
    fail "cleanup after kill -9: $(calls cleanup-firewall)"

# A daemon that does not stop keeps its rules, with a warning.
rm -f "$T/calls/cleanup-firewall"
: > "$T/fake/daemon-ignores-term"
init_script start > /dev/null 2>&1
pid=$(daemon_pid)
init_script stop > /dev/null 2>&1
kill -0 "$pid" 2>/dev/null || fail "the stubborn daemon stopped after all"
[ -z "$(calls cleanup-firewall)" ] || fail "cleanup ran next to a live daemon"
grep -q 'WARNING: forest-pbr is still running after stop; its firewall rules are left in place' "$T/calls/logger" ||
    fail "no warning about the live daemon"
kill -9 "$pid"
wait_for 5 process_gone "$pid" || fail "daemon survived kill -9"
rm -f "$T/fake/daemon-ignores-term" "$T/opt/var/run/forest-pbr.pid"

# Nor does a daemon whose PID file is gone lose its rules.
init_script start > /dev/null 2>&1
pid=$(daemon_pid)
rm -f "$T/opt/var/run/forest-pbr.pid"
init_script stop > /dev/null 2>&1
[ -z "$(calls cleanup-firewall)" ] || fail "cleanup ran next to a daemon without PID file"
kill "$pid"

pass
