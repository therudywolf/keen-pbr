#!/bin/sh
# Tests of the Keenetic package scripts (init script, dnsmasq.sh, netfilter
# hook, cleanup-firewall.sh, postinst, example configs). Plain POSIX sh with
# stub commands in a temporary root: no root rights, nothing on the system is
# touched.
#
#   sh tests/keenetic/run.sh

dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
failed=0

for test in "$dir"/test_*.sh; do
    sh "$test" || failed=$((failed + 1))
done

if [ "$failed" -ne 0 ]; then
    echo "Keenetic script tests: $failed failed" >&2
    exit 1
fi
echo "Keenetic script tests: all passed"
