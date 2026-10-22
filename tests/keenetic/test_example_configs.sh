#!/bin/sh
# The shipped example configs start route.rules with local_networks ->
# direct_local (an ignore outbound), so a catch-all rule added later does not
# send LAN, link-local or multicast traffic into a tunnel.

set -u
. "$(dirname -- "$0")/lib.sh"

command -v python3 > /dev/null 2>&1 || { echo "$test_name: SKIP (no python3)"; exit 0; }

for config in \
    "$repo_root/packages/common/config.full.example.json" \
    "$repo_root/packages/common/config.headless.example.json" \
    "$pkg_files/opt/etc/forest-pbr/config.full.example.json" \
    "$pkg_files/opt/etc/forest-pbr/config.headless.example.json"; do
    python3 -I - "$config" <<'EOF' || fail "$config"
import json
import sys

config = json.load(open(sys.argv[1]))
first = config["route"]["rules"][0]
assert first["list"] == ["local_networks"] and first["outbound"] == "direct_local", first
assert first.get("enabled", True)
assert {"type": "ignore", "tag": "direct_local"} in config["outbounds"]
cidrs = config["lists"]["local_networks"]["ip_cidrs"]
for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
             "169.254.0.0/16", "224.0.0.0/4", "fe80::/10", "fc00::/7"):
    assert cidr in cidrs, cidr
EOF
done

pass
