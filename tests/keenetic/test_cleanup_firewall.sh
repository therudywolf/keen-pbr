#!/bin/sh
# cleanup-firewall.sh against fake iptables, ip6tables and ipset: it removes
# forest-pbr's mangle chains with the jumps to them and its ipsets (list:sets
# before their members), leaves everything else alone, and is idempotent.

set -u
. "$(dirname -- "$0")/lib.sh"

make_root
script="$pkg_files/opt/usr/lib/forest-pbr/cleanup-firewall.sh"
db="$T/fake"

# Fake iptables/ip6tables: table T is "$db/<command>.<T>" in `iptables -S`
# form. Supports -S, -L <chain> -n --line-numbers, -D <chain> <num>, -F and -X.
cat > "$T/opt/bin/fake-xt" <<'EOF'
#!/bin/sh
[ "$1" = -t ] || exit 2
file="$FAKE_ROOT/fake/$(basename "$0").$2"
shift 2
[ -f "$file" ] || { echo "table does not exist" >&2; exit 1; }
case "$1" in
    -S) cat "$file" ;;
    -L)
        echo "Chain $2"
        echo "num  target  prot opt source  destination"
        awk -v c="$2" '$1 == "-A" && $2 == c {
            n++; t = ""
            for (i = 3; i < NF; i++) if ($i == "-j" || $i == "-g") t = $(i + 1)
            print n "    " t "  all  --  0.0.0.0/0  0.0.0.0/0"
        }' "$file"
        ;;
    -D)
        awk -v c="$2" -v k="$3" '$1 == "-A" && $2 == c && ++n == k { next } { print }' "$file" > "$file.new"
        mv "$file.new" "$file"
        ;;
    -F)
        awk -v c="$2" '!($1 == "-A" && $2 == c)' "$file" > "$file.new"
        mv "$file.new" "$file"
        ;;
    -X)
        grep -q -- "-[jg] $2\( \|$\)" "$file" && { echo "chain in use" >&2; exit 1; }
        grep -vxF -- "-N $2" "$file" > "$file.new"
        mv "$file.new" "$file"
        ;;
    *) exit 2 ;;
esac
EOF
chmod +x "$T/opt/bin/fake-xt"
ln -s fake-xt "$T/opt/bin/iptables"
ln -s fake-xt "$T/opt/bin/ip6tables"

# Fake ipset: "$db/ipsets" lists the sets, "$db/ipset-members" holds
# "<list:set> <member>" pairs; like the kernel it refuses to destroy a set that
# is still a member of a list:set.
stub ipset <<'EOF'
echo "$*" >> "$FAKE_ROOT/calls/ipset"
sets="$FAKE_ROOT/fake/ipsets"
members="$FAKE_ROOT/fake/ipset-members"
case "$1" in
    list) cat "$sets" ;;
    destroy)
        grep -qx "$2" "$sets" || exit 1
        awk -v s="$2" '$2 == s { exit 1 }' "$members" || { echo "in use" >&2; exit 1; }
        grep -vx "$2" "$sets" > "$sets.new"; mv "$sets.new" "$sets"
        awk -v s="$2" '$1 != s' "$members" > "$members.new"; mv "$members.new" "$members"
        ;;
    *) exit 1 ;;
esac
EOF
stub logger <<'EOF'
echo "logger $*" >> "$FAKE_ROOT/calls/logger"
EOF

cat > "$db/iptables.mangle" <<'EOF'
-P PREROUTING ACCEPT
-P OUTPUT ACCEPT
-N KeenPbrTable
-N _NDM_HOTSPOT_PRERT
-A PREROUTING -j _NDM_HOTSPOT_PRERT
-A PREROUTING -j KeenPbrTable
-A PREROUTING -p tcp -j ACCEPT
-A KeenPbrTable -m conntrack --ctstate DNAT -j RETURN
-A KeenPbrTable -m mark ! --mark 0x0/0xffffffff -j ACCEPT
-A KeenPbrTable -m set --match-set kpbrm_0 dst -i br0 -j MARK --set-xmark 0x10000/0xff0000
-A KeenPbrTable -m set --match-set kpbrm_0 dst -i br0 -j RETURN
-A _NDM_HOTSPOT_PRERT -j RETURN
EOF
cat > "$db/ip6tables.mangle" <<'EOF'
-P PREROUTING ACCEPT
-N KeenPbrTable
-A PREROUTING -j KeenPbrTable
-A KeenPbrTable -m set --match-set kpbrm_1 dst -i br0 -j MARK --set-xmark 0x10000/0xff0000
EOF
# NDM's nat (UPnP and the like) is no business of forest-pbr's.
cat > "$db/iptables.nat" <<'EOF'
-P POSTROUTING ACCEPT
-N _NDM_MASQ
-A POSTROUTING -j _NDM_MASQ
-A _NDM_MASQ -s 192.168.1.0/24 -j MASQUERADE
EOF
cp "$db/iptables.nat" "$T/nat.before"
printf 'kpbr4_lists\nkpbr4d_lists\nkpbr6_lists\nkpbr6d_lists\nuser_set\nkpbrm_0\nkpbrm_1\n' > "$db/ipsets"
printf 'kpbrm_0 kpbr4_lists\nkpbrm_0 kpbr4d_lists\nkpbrm_1 kpbr6_lists\nkpbrm_1 kpbr6d_lists\n' > "$db/ipset-members"

PATH="$T/opt/bin:$PATH" sh "$script" --reason stop > /dev/null || fail "script failed"

[ "$(cat "$db/iptables.mangle")" = "-P PREROUTING ACCEPT
-P OUTPUT ACCEPT
-N _NDM_HOTSPOT_PRERT
-A PREROUTING -j _NDM_HOTSPOT_PRERT
-A PREROUTING -p tcp -j ACCEPT
-A _NDM_HOTSPOT_PRERT -j RETURN" ] || fail "iptables mangle not cleaned: $(cat "$db/iptables.mangle")"
[ "$(cat "$db/ip6tables.mangle")" = "-P PREROUTING ACCEPT" ] ||
    fail "ip6tables mangle not cleaned: $(cat "$db/ip6tables.mangle")"
cmp -s "$db/iptables.nat" "$T/nat.before" || fail "nat was changed"
[ "$(cat "$db/ipsets")" = user_set ] || fail "ipsets left: $(cat "$db/ipsets")"
grep -q 'logger -t forest-pbr cleanup-firewall: iptables -t mangle: removed chain KeenPbrTable' "$T/calls/logger" ||
    fail "removed chain not logged: $(calls logger)"
grep -q 'logger -t forest-pbr cleanup-firewall: removed ipset kpbrm_0' "$T/calls/logger" ||
    fail "removed ipset not logged"
grep -q 'logger -s -t forest-pbr -p user.warning .*left behind (on stop:' "$T/calls/logger" ||
    fail "leftovers not reported as a warning naming the reason"

# Nothing left: no change, no warning, still exit 0.
cp "$db/iptables.mangle" "$T/mangle.before"
: > "$T/calls/logger"
PATH="$T/opt/bin:$PATH" sh "$script" --reason stop > /dev/null || fail "second run failed"
cmp -s "$db/iptables.mangle" "$T/mangle.before" || fail "second run changed iptables"
[ -z "$(calls logger)" ] || fail "second run logged: $(calls logger)"

# No firewall tools at all.
mkdir -p "$T/empty"
PATH="$T/empty" IPTABLES=none IP6TABLES=none NFT=none IPSET=none \
    "$(command -v sh)" "$script" || fail "run without tools failed"

pass
