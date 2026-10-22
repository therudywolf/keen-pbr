# Shared helpers for the Keenetic shell tests; sourced by the test_*.sh files.
#
# The package scripts hard-code their install locations (/opt/..., and
# /tmp/forest-pbr for dnsmasq.sh). install_script copies one into a temporary
# root with those paths moved below it, so a test runs the real script against
# stub commands and scratch files, without root and without touching the
# system. The PATH line of the init script then starts with the stub
# directories ($T/opt/sbin, $T/opt/bin, $T/opt/usr/bin) and still ends with
# the system ones, so tr, grep, sed and the like are the real tools.
#
# Stubs append what they were asked to "$T/calls/<name>" and read their
# behaviour from files in "$T/fake/".

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
pkg_files="$repo_root/packages/keenetic/forest-pbr/files"
test_name=$(basename -- "$0" .sh)

fail() {
    printf '%s: FAIL: %s\n' "$test_name" "$*" >&2
    exit 1
}

pass() {
    printf '%s: PASS\n' "$test_name"
}

# Processes started under the fake root (a daemon stand-in, a detached start)
# must not outlive the test.
kill_root_processes() {
    local pid

    [ -n "${T:-}" ] || return 0
    for pid in $(root_pids); do
        kill -9 "$pid" 2>/dev/null || true
    done
}

# PIDs of processes whose command line mentions the fake root.
root_pids() {
    grep -lsF "$T/" /proc/[0-9]*/cmdline | sed -n 's#^/proc/\([0-9]*\)/cmdline$#\1#p' |
        grep -vx "$$"
}

make_root() {
    T=$(mktemp -d "${TMPDIR:-/tmp}/kpbr-shtest.XXXXXX") || exit 1
    trap 'kill_root_processes; rm -rf "$T"' EXIT
    trap 'exit 1' HUP INT TERM
    export FAKE_ROOT="$T"
    mkdir -p "$T/opt/bin" "$T/opt/sbin" "$T/opt/usr/bin" "$T/opt/usr/lib/forest-pbr" \
        "$T/opt/etc/init.d" "$T/opt/etc/forest-pbr" "$T/opt/var/run" "$T/opt/var/log" \
        "$T/tmp" "$T/calls" "$T/fake" "$T/sys/module"
    ln -s "$(command -v sh)" "$T/opt/bin/sh"
}

# install_script SRC DEST: copy SRC to DEST inside the fake root.
install_script() {
    sed -e "s#/opt/#$T/opt/#g" -e "s#/tmp/forest-pbr\([/\"]\)#$T/tmp/forest-pbr\1#g" "$1" > "$2" &&
        chmod +x "$2" || fail "cannot install $1"
}

# stub NAME: write the stub body from stdin to the first PATH directory.
stub() {
    {
        echo '#!/bin/sh'
        cat
    } > "$T/opt/bin/$1"
    chmod +x "$T/opt/bin/$1"
}

calls() {
    cat "$T/calls/$1" 2>/dev/null
}

# wait_for TIMEOUT_SECONDS COMMAND...: poll COMMAND every 0.2 s.
wait_for() {
    local limit=$(($1 * 5))
    local n=0

    shift
    while ! "$@"; do
        n=$((n + 1))
        [ "$n" -le "$limit" ] || return 1
        sleep 0.2
    done
}

# Stubs shared by the init script tests. Process lookups only see processes
# of this fake root, so nothing else on the host can disturb a test.
install_common_stubs() {
    stub logger <<'EOF'
printf '%s\n' "$*" >> "$FAKE_ROOT/calls/logger"
EOF
    stub uname <<'EOF'
echo test-kernel
EOF
    stub sysctl <<'EOF'
printf '%s\n' "$*" >> "$FAKE_ROOT/calls/sysctl"
EOF
    stub insmod <<'EOF'
printf '%s\n' "$*" >> "$FAKE_ROOT/calls/insmod"
EOF
    stub ipset <<'EOF'
printf '%s\n' "$*" >> "$FAKE_ROOT/calls/ipset"
EOF
    stub wget <<'EOF'
printf '%s\n' "$*" >> "$FAKE_ROOT/calls/wget"
exit 1
EOF
    # curl: "$T/fake/curl-failures" holds how many calls still fail.
    stub curl <<'EOF'
printf '%s\n' "$*" >> "$FAKE_ROOT/calls/curl"
left=$(cat "$FAKE_ROOT/fake/curl-failures" 2>/dev/null || echo 0)
if [ "$left" -gt 0 ]; then
    echo $((left - 1)) > "$FAKE_ROOT/fake/curl-failures"
    exit 7
fi
case "$*" in
    *ndw/components*) printf '"base,opkg-kmod-netfilter,opkg-kmod-netfilter-addons,ppe"' ;;
    *http_code*) printf 200 ;;
esac
exit 0
EOF
    stub pidof <<'EOF'
pids=""
for name in "$@"; do
    for dir in /proc/[0-9]*; do
        read -r comm 2>/dev/null < "$dir/comm" || continue
        [ "$comm" = "$name" ] || continue
        grep -qsF "$FAKE_ROOT/" "$dir/cmdline" || continue
        pids="$pids${pids:+ }${dir#/proc/}"
    done
done
[ -n "$pids" ] || exit 1
echo "$pids"
EOF
    stub killall <<'EOF'
sig=-TERM
case "$1" in -*) sig="$1"; shift ;; esac
for pid in $(pidof "$1"); do
    kill "$sig" "$pid"
done
EOF
    # start-stop-daemon -S -b ... -x EXEC -- ARGS: run EXEC ARGS in a new
    # session, in the background, like busybox does with -b.
    stub start-stop-daemon <<'EOF'
printf 'detached=%s parent=%s args=%s\n' "${FOREST_PBR_DETACHED:-}" \
    "${FOREST_PBR_BOOT_PARENT:-}" "$*" >> "$FAKE_ROOT/calls/start-stop-daemon"
exec_path=""
while [ $# -gt 0 ]; do
    case "$1" in
        -x) exec_path="$2"; shift ;;
        --) shift; break ;;
    esac
    shift
done
( setsid "$exec_path" "$@" > /dev/null 2>&1 < /dev/null & )
EOF
}

# forest-pbr stand-in: `service` writes its PID file and runs until SIGTERM
# (or ignores it when "$T/fake/daemon-ignores-term" exists); other commands
# only succeed. "$T/fake/cli-sleep" makes them hang that many seconds, like
# a CLI stuck in RCI.
install_fake_daemon() {
    cat > "$T/opt/usr/bin/forest-pbr" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "$FAKE_ROOT/calls/forest-pbr"
pidfile=""
command=""
while [ $# -gt 0 ]; do
    case "$1" in
        --pid-file) pidfile="$2"; shift ;;
        --config) shift ;;
        -*) ;;
        *) [ -n "$command" ] || command="$1" ;;
    esac
    shift
done
if [ "$command" != service ]; then
    [ -f "$FAKE_ROOT/fake/cli-sleep" ] && sleep "$(cat "$FAKE_ROOT/fake/cli-sleep")"
    exit 0
fi
if [ -f "$FAKE_ROOT/fake/daemon-ignores-term" ]; then
    trap '' TERM
else
    trap 'rm -f "$pidfile"; exit 0' TERM
fi
echo $$ > "$pidfile"
while :; do
    sleep 1 &
    wait $!
done
EOF
    chmod +x "$T/opt/usr/bin/forest-pbr"
}

# Entware's rc.func, reduced to what the init script relies on: `pidof $PROC`
# decides whether the service runs, start launches "$PREARGS $PROC $ARGS" in
# the background, waits for pidof and then runs $POSTCMD as a plain command
# with its output thrown away; stop is killall plus a wait.
# "$T/fake/rc-func-limit" shortens the waits (10 s on Entware).
install_rc_func() {
    cat > "$T/opt/etc/init.d/rc.func" <<'EOF'
ACTION=$1
LIMIT=$(cat "$FAKE_ROOT/fake/rc-func-limit" 2>/dev/null || echo 10)

start() {
    [ "$ENABLED" != "yes" ] && return 8
    if [ -n "`pidof $PROC`" ]; then
        echo "already running"
        return 0
    fi
    $PREARGS $PROC $ARGS > /dev/null 2>&1 &
    COUNTER=0
    while [ -z "`pidof $PROC`" -a "$COUNTER" -le "$LIMIT" ]; do
        sleep 1
        COUNTER=`expr $COUNTER + 1`
    done
    $POSTCMD > /dev/null 2>&1
    if [ -z "`pidof $PROC`" ]; then
        echo "failed"
        return 255
    fi
    echo "done"
    return 0
}

stop() {
    case "$ACTION" in
        stop|restart)
            killall $PROC 2>/dev/null
            COUNTER=0
            while [ -n "`pidof $PROC`" -a "$COUNTER" -le "$LIMIT" ]; do
                sleep 1
                COUNTER=`expr $COUNTER + 1`
            done
            ;;
        kill)
            killall -9 $PROC 2>/dev/null
            ;;
    esac
    [ -z "`pidof $PROC`" ] || return 255
}

check() {
    if [ -n "`pidof $PROC`" ]; then
        echo "alive"
        return 0
    fi
    echo "dead"
    return 1
}

for PROC in $PROCS; do
    case $ACTION in
        start) start ;;
        stop|kill) check && stop ;;
        restart) check > /dev/null && stop; start ;;
        check) check ;;
        *) echo "Usage: $0 (start|stop|restart|check|kill)"; exit 1 ;;
    esac
done
EOF
}

# Entware's rc.unslung: it runs every executable S* script with the full path
# find prints, so its "source S* and *.sh" branch never matches and the
# scripts run as its child processes. After the scripts it sleeps
# "$T/fake/rc-unslung-tail" seconds (the scripts after ours, and NDM keeping
# its OPTWARE lock meanwhile), then leaves the marker "$T/calls/rc-unslung-exited".
install_rc_unslung() {
    cat > "$T/opt/etc/init.d/rc.unslung" <<'EOF'
ACTION=$1
CALLER=$2
for i in $(find "$FAKE_ROOT/opt/etc/init.d/" -perm '-u+x' -name 'S*' | sort); do
    case "$i" in
        S* | *.sh)
            . $i $ACTION $CALLER
            ;;
        *)
            $i $ACTION $CALLER
            ;;
    esac
done
sleep "$(cat "$FAKE_ROOT/fake/rc-unslung-tail" 2>/dev/null || echo 0)"
: > "$FAKE_ROOT/calls/rc-unslung-exited"
EOF
}

# The init script with its defaults file, stubs, rc.func and a dnsmasq.sh
# stand-in that records activate/deactivate. While "$T/fake/rci-blocked"
# exists, activate stands in for the RCI dns-proxy call that hangs while NDM
# holds the OPTWARE lock: it records whether rc.unslung had already exited,
# then waits (at most 8 s) for it to exit.
install_init_script() {
    install_script "$pkg_files/opt/etc/forest-pbr/defaults" "$T/opt/etc/forest-pbr/defaults"
    install_script "$pkg_files/opt/etc/init.d/S80forest-pbr" "$T/opt/etc/init.d/S80forest-pbr"
    install_common_stubs
    install_fake_daemon
    install_rc_func
    cat > "$T/opt/usr/lib/forest-pbr/dnsmasq.sh" <<'EOF'
#!/bin/sh
if [ "$1" = activate ] && [ -f "$FAKE_ROOT/fake/rci-blocked" ]; then
    if [ -f "$FAKE_ROOT/calls/rc-unslung-exited" ]; then
        echo "activate after-rc-unslung" >> "$FAKE_ROOT/calls/dnsmasq.sh"
    else
        echo "activate during-rc-unslung" >> "$FAKE_ROOT/calls/dnsmasq.sh"
    fi
    n=0
    while [ ! -f "$FAKE_ROOT/calls/rc-unslung-exited" ] && [ "$n" -lt 40 ]; do
        sleep 0.2
        n=$((n + 1))
    done
    exit 0
fi
echo "$1" >> "$FAKE_ROOT/calls/dnsmasq.sh"
EOF
    chmod +x "$T/opt/usr/lib/forest-pbr/dnsmasq.sh"
}

init_script() {
    "$T/opt/etc/init.d/S80forest-pbr" "$@"
}

daemon_pid() {
    cat "$T/opt/var/run/forest-pbr.pid" 2>/dev/null
}

process_gone() {
    [ -n "$1" ] && ! kill -0 "$1" 2>/dev/null
}

daemon_running() {
    local pid

    pid=$(daemon_pid) && [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null
}
