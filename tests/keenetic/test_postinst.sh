#!/bin/sh
# postinst / postinst-headless: no dnsmasq.conf question when the managed
# block is already there, an explicit answer still counts, and the service is
# restarted rather than started.

set -u
. "$(dirname -- "$0")/lib.sh"

make_root
unset FOREST_PBR_REPLACE_DNSMASQ_DEFAULTS KEEN_PBR_REPLACE_DNSMASQ_DEFAULTS
conf="$T/opt/etc/dnsmasq.conf"
template="$T/opt/usr/lib/forest-pbr/dnsmasq.conf.template"
install_script "$pkg_files/opt/usr/lib/forest-pbr/dnsmasq.conf.template" "$template"
cat > "$T/opt/etc/init.d/S80forest-pbr" <<'EOF'
#!/bin/sh
echo "$1" >> "$FAKE_ROOT/calls/S80"
EOF
chmod +x "$T/opt/etc/init.d/S80forest-pbr"

block_template=$(sed -n '/^# BEGIN forest-pbr managed block$/,/^# END forest-pbr managed block$/p' "$template")
[ -n "$block_template" ] || fail "no managed block in the dnsmasq.conf template"
# Inside the fake root the helper, like every /opt path, lives below $T.
conf_script="conf-script=$T/opt/usr/lib/forest-pbr/dnsmasq.sh dnsmasq-config-entry"
printf '%s\n' "$block_template" | grep -qxF "$conf_script" || fail "template block: $block_template"

for variant in postinst postinst-headless; do
    script="$T/$variant"
    install_script "$pkg_files/$variant" "$script"

    run() {
        rm -f "$T/calls/S80"
        out=$(env "$@" sh "$script" < /dev/null 2>&1) || fail "$variant failed: $out"
        [ "$(calls S80)" = restart ] || fail "$variant: service not restarted: $(calls S80)"
    }

    # The block as the template ships it, and as a keen-pbr migration leaves
    # it (keen-pbr's notice line): kept, nothing asked.
    for notice in "$(printf '%s\n' "$block_template" | sed -n 2p)" \
                  "# Do not remove the following line, it is required for keen-pbr to function properly."; do
        printf 'port=53\n# BEGIN forest-pbr managed block\n%s\n%s\n# END forest-pbr managed block\n' \
            "$notice" "$conf_script" > "$conf"
        cp "$conf" "$T/conf.before"
        run
        case "$out" in
            *"already loads forest-pbr; keeping it."*) ;;
            *) fail "$variant: managed block not recognised: $out" ;;
        esac
        case "$out" in *Tip:*) fail "$variant: offered to replace dnsmasq.conf: $out" ;; esac
        cmp -s "$conf" "$T/conf.before" || fail "$variant: dnsmasq.conf changed"
    done

    # No block, or the conf-script line outside it: the tip as before.
    for body in 'port=53' "$conf_script"; do
        printf '%s\n' "$body" > "$conf"
        run
        case "$out" in
            *"Tip: set FOREST_PBR_REPLACE_DNSMASQ_DEFAULTS"*) ;;
            *) fail "$variant: no tip without the managed block: $out" ;;
        esac
    done

    # An explicit answer wins over the block check.
    printf 'port=53\n%s\n' "$block_template" > "$conf"
    run FOREST_PBR_REPLACE_DNSMASQ_DEFAULTS=Y
    cmp -s "$conf" "$template" || fail "$variant: explicit Y did not install the template"
    [ -f "$T/opt/etc/dnsmasq.conf.backup-pre-forest-pbr" ] || fail "$variant: no backup"
    rm -f "$T/opt/etc/dnsmasq.conf.backup-pre-forest-pbr"
done

pass
