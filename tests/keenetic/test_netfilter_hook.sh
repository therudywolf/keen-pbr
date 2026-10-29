#!/bin/sh
# ndm/netfilter.d hook: fastnat is switched off again on every event, unless
# the user asked to keep it with fastnat.enabled and the kernel has the PPE
# target; the firewall is refreshed only when NDM rebuilt mangle (IPv4 or
# IPv6), and the user hook.sh runs on every event.

set -u
. "$(dirname -- "$0")/lib.sh"

make_root
hook="$T/opt/etc/ndm/netfilter.d/50-forest-pbr-routing.sh"
mkdir -p "$(dirname "$hook")" "$T/proc"
install_script "$pkg_files/opt/etc/ndm/netfilter.d/50-forest-pbr-routing.sh" "$hook"
sed -i "s#/proc/net/#$T/proc/#g" "$hook"
grep -qF "$T/proc/ip_tables_targets" "$hook" || fail "targets listing not redirected"
PATH="$T/opt/bin:$PATH"
export PATH

stub logger <<'EOF'
printf '%s\n' "$*" >> "$FAKE_ROOT/calls/logger"
EOF
# Each fastnat key is on until switched off.
stub sysctl <<'EOF'
case "$1" in
    -n) cat "$FAKE_ROOT/fake/$2" ;;
    -w) printf '%s\n' "$2" >> "$FAKE_ROOT/calls/sysctl"; echo 0 > "$FAKE_ROOT/fake/${2%=*}" ;;
esac
EOF
cat > "$T/opt/etc/init.d/S80forest-pbr" <<'EOF'
#!/bin/sh
echo "$1" >> "$FAKE_ROOT/calls/S80"
EOF
chmod +x "$T/opt/etc/init.d/S80forest-pbr"
echo 'echo "$keen_pbr_hook $type $table" >> "$FAKE_ROOT/calls/hook.sh"' > "$T/opt/etc/forest-pbr/hook.sh"

event() {
    echo 1 > "$T/fake/net.ipv4.netfilter.ip_conntrack_fastnat"
    echo 1 > "$T/fake/net.netfilter.nf_conntrack_fastnat"
    rm -f "$T/calls/S80" "$T/calls/sysctl"
    type="$1" table="$2" sh "$hook" || fail "hook failed for $1/$2"
    [ "$(calls sysctl)" = "net.ipv4.netfilter.ip_conntrack_fastnat=0
net.netfilter.nf_conntrack_fastnat=0" ] || fail "$1/$2: fastnat not switched off: $(calls sysctl)"
}

for t in nat filter raw; do
    for family in iptables ip6tables; do
        event "$family" "$t"
        [ -z "$(calls S80)" ] || fail "$family/$t triggered a firewall refresh"
    done
done
for family in iptables ip6tables; do
    event "$family" mangle
    [ "$(calls S80)" = reapply-firewall ] || fail "$family/mangle did not refresh the firewall"
done

[ "$(calls hook.sh | wc -l)" = 8 ] || fail "hook.sh did not run on every event: $(calls hook.sh)"
grep -q 'Refreshing routing state after netfilter change (type=ip6tables table=mangle)' "$T/calls/logger" ||
    fail "refresh not logged: $(calls logger)"

# The kernel has the PPE target, but the user did not ask: still switched off.
printf 'MARK\nPPE\nCONNMARK\n' > "$T/proc/ip_tables_targets"
event iptables nat

# Asked for, but no PPE target to keep the routed flows off fastnat: off.
: > "$T/opt/etc/forest-pbr/fastnat.enabled"
printf 'MARK\nCONNMARK\n' > "$T/proc/ip_tables_targets"
event iptables filter

# Asked for and guarded: fastnat stays as NDM set it, mangle still refreshes.
printf 'MARK\nPPE\nCONNMARK\n' > "$T/proc/ip_tables_targets"
for t in nat filter mangle; do
    echo 1 > "$T/fake/net.netfilter.nf_conntrack_fastnat"
    rm -f "$T/calls/S80" "$T/calls/sysctl"
    type=iptables table="$t" sh "$hook" || fail "hook failed for guarded $t"
    [ -z "$(calls sysctl)" ] || fail "guarded $t: fastnat touched: $(calls sysctl)"
    [ "$(cat "$T/fake/net.netfilter.nf_conntrack_fastnat")" = 1 ] || fail "guarded $t: fastnat changed"
done
[ "$(calls S80)" = reapply-firewall ] || fail "guarded mangle did not refresh the firewall"

pass
