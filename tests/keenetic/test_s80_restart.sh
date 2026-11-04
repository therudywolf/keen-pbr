#!/bin/sh
# S80forest-pbr restart must leave a daemon running. rc.func's restart is its
# stop (killall, then a wait of LIMIT seconds) followed at once by its start,
# and start only asks whether a daemon still runs: a daemon that needed
# longer than LIMIT to exit was "already running", nothing was started, and
# once it exited none was left (2026-11-04). The init script now waits for the
# old daemon to exit, killing it after STOP_TIMEOUT_SECONDS, before rc.func
# gets to start.

set -u
. "$(dirname -- "$0")/lib.sh"

make_root
install_init_script
echo 2 > "$T/fake/rc-func-limit"
# SIGKILL after 6 s instead of 120.
sed -i 's/^STOP_TIMEOUT_SECONDS=120$/STOP_TIMEOUT_SECONDS=6/' "$T/opt/etc/init.d/S80forest-pbr"
grep -qx 'STOP_TIMEOUT_SECONDS=6' "$T/opt/etc/init.d/S80forest-pbr" || fail "STOP_TIMEOUT_SECONDS not found"

# A daemon that takes 4 s to exit: longer than rc.func waits, shorter than
# the init script does.
init_script start > /dev/null 2>&1
daemon_running || fail "start did not launch the daemon"
old_pid=$(daemon_pid)
echo 4 > "$T/fake/daemon-exit-delay"
init_script restart > /dev/null 2>&1
process_gone "$old_pid" || fail "restart returned while the old daemon still ran"
daemon_running || fail "restart left no daemon behind a slow exit"
[ "$(daemon_pid)" != "$old_pid" ] || fail "restart kept the old daemon"
! grep -qs SIGKILL "$T/calls/logger" || fail "a slow but finite exit got SIGKILL"
rm -f "$T/fake/daemon-exit-delay"

# A daemon that ignores SIGTERM gets SIGKILL after STOP_TIMEOUT_SECONDS and
# is replaced.
pid=$(daemon_pid)
kill -9 "$pid"
wait_for 5 process_gone "$pid" || fail "daemon survived kill -9"
: > "$T/fake/daemon-ignores-term"
init_script start > /dev/null 2>&1
stubborn_pid=$(daemon_pid)
[ -n "$stubborn_pid" ] || fail "the stubborn daemon did not start"
rm -f "$T/fake/daemon-ignores-term"
init_script restart > /dev/null 2>&1
process_gone "$stubborn_pid" || fail "restart left a daemon that ignores SIGTERM running"
daemon_running || fail "restart left no daemon after killing a stubborn one"
[ "$(daemon_pid)" != "$stubborn_pid" ] || fail "restart kept the stubborn daemon"
grep -q "did not exit within 6s of SIGTERM; sending SIGKILL" "$T/calls/logger" ||
    fail "no warning before SIGKILL"

pass
