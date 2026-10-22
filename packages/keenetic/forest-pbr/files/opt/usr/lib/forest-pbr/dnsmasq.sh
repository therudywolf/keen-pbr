#!/bin/sh

set -e

KEEN_PBR_BIN="/opt/usr/bin/forest-pbr"
CONFIG_PATH="/opt/etc/forest-pbr/config.json"
DNSMASQ_FALLBACK_FILE="/opt/etc/forest-pbr/dnsmasq-fallback.conf"
STATE_DIR="/tmp/forest-pbr"
ACTIVE_FILE="${STATE_DIR}/active"

# The last line of every generated config (src/dns/dnsmasq_gen.cpp), as a
# regular expression:
#   txt-record=config-hash.keen.pbr,<unix time>|<config hash>
# The daemon reads the record back to see which config dnsmasq has loaded.
CONFIG_HASH_RECORD='txt-record=config-hash\.keen\.pbr,'

log_message() {
    local level="$1"
    local message="$2"

    logger -s -t "forest-pbr" -p "user.${level}" "$message"
}

log_info() {
    log_message info "$1"
}

log_warn() {
    log_message warn "$1"
}

resolver_type() {
    if command -v nft >/dev/null 2>&1; then
        echo "dnsmasq-nftset"
    else
        echo "dnsmasq-ipset"
    fi
}

fallback_conf_line() {
    printf 'conf-file=%s\n' "$DNSMASQ_FALLBACK_FILE"
}

active_conf_line() {
    "$KEEN_PBR_BIN" --config "$CONFIG_PATH" generate-resolver-config "$(resolver_type)"
}

# Print forest-pbr's generated config, or nothing and fail when generation
# fails (RCI not answering for a keenetic DNS server, a broken config). The
# output is collected first, so a run that fails half-way never hands dnsmasq
# a partial config; a complete one ends with the config-hash record.
generated_config() {
    local config

    config="$(active_conf_line)" || return 1
    printf '%s\n' "$config" | grep -q "^$CONFIG_HASH_RECORD" || return 1
    printf '%s\n' "$config"
}

is_active() {
    [ -r "$ACTIVE_FILE" ] || return 1

    active_state="$(tr -d '[:space:]' < "$ACTIVE_FILE" 2>/dev/null || true)"
    [ "$active_state" = "Y" ]
}

set_active_state() {
    mkdir -p "$STATE_DIR"
    printf '%s\n' "$1" > "$ACTIVE_FILE"
}

# dnsmasq treats a conf-script that fails as a fatal error and does not start,
# which leaves the whole LAN without DNS. So when the config cannot be
# generated, dnsmasq gets the fallback config entry instead.
emit_dnsmasq_config_entry() {
    local config

    if ! is_active; then
        fallback_conf_line
        log_info "Produced dnsmasq fallback config entry"
        return 0
    fi
    if config="$(generated_config)"; then
        printf '%s\n' "$config"
        log_info "Produced dnsmasq forest-pbr managed config"
        return 0
    fi
    fallback_conf_line
    log_warn "forest-pbr could not generate the dnsmasq config; produced the fallback config entry instead"
}

activate_dnsmasq() {
    set_active_state "Y"
    log_info "Marked forest-pbr dnsmasq state as active"
    restart_dnsmasq
}

deactivate_dnsmasq() {
    set_active_state "N"
    log_info "Marked forest-pbr dnsmasq state as inactive"
    restart_dnsmasq
}

resolver_config_hash_file() {
    echo "${STATE_DIR}/resolver-config.hash"
}

# What dnsmasq-config-entry hands dnsmasq, without the logging.
effective_config_content() {
    is_active && generated_config && return 0
    fallback_conf_line
}

# The config-hash record carries the time of the run, so no two runs print the
# same text. Compare without that timestamp; the hash after it still changes
# whenever the config does.
stable_config_content() {
    effective_config_content | sed "s/^\($CONFIG_HASH_RECORD\)[0-9]*|/\1|/"
}

dnsmasq_is_running() {
    pidof dnsmasq >/dev/null 2>&1
}

restart_dnsmasq() {
    if [ -x /opt/etc/init.d/S56dnsmasq ]; then
        hash_file="$(resolver_config_hash_file)"
        new_hash="$(stable_config_content | md5sum | awk '{print $1}')"
        old_hash=""
        if [ -f "$hash_file" ]; then
            old_hash="$(cat "$hash_file")"
        fi
        if [ "$new_hash" = "$old_hash" ] && dnsmasq_is_running; then
            log_info "resolver config unchanged, skipping dnsmasq restart"
            return 0
        fi
        mkdir -p "$STATE_DIR"
        printf '%s\n' "$new_hash" > "$hash_file"
        /opt/etc/init.d/S56dnsmasq restart 2>/dev/null || true
        return 0
    fi

    return 1
}

print_help() {
    cat <<EOF
Usage: $0 <command>

Commands:
  dnsmasq-config-entry   Print the dnsmasq config entry for the current active state.
  activate               Mark forest-pbr dnsmasq state active and restart dnsmasq.
  deactivate             Mark forest-pbr dnsmasq state inactive and restart dnsmasq.
  restart-dnsmasq        Restart dnsmasq without changing helper-managed config.
  reload                 Alias for restart-dnsmasq; used by the system resolver hook.
  help                   Show this help text.
EOF
}

case "$1" in
    dnsmasq-config-entry)
        # Never fail, whatever goes wrong above (see emit_dnsmasq_config_entry).
        emit_dnsmasq_config_entry || true
        exit 0
        ;;
    activate)
        activate_dnsmasq
        ;;
    deactivate)
        deactivate_dnsmasq
        ;;
    restart-dnsmasq)
        restart_dnsmasq
        ;;
    reload)
        restart_dnsmasq
        ;;
    help|-h|--help)
        print_help
        ;;
    *)
        print_help >&2
        exit 1
        ;;
esac
