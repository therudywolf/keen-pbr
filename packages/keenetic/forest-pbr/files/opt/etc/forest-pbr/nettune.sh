#!/bin/sh
# forest-pbr net perf tuning: spread NET_RX softirq off CPU0 (RPS), enable flow
# steering (RFS), enlarge backlog/XPS. Pure perf knobs — does NOT touch routing,
# firewall, marks or fastnat. Idempotent; safe to run repeatedly.
RPS_MASK=e            # CPU1,2,3 — leave CPU0 for the NIC hardware IRQ (IRQ18)
IFACES="ppp0 nwg1 nwg2 br0 eth2.1 eth2 eth3"
echo 32768 > /proc/sys/net/core/rps_sock_flow_entries 2>/dev/null
echo 4000  > /proc/sys/net/core/netdev_max_backlog     2>/dev/null
for i in $IFACES; do
  for q in /sys/class/net/$i/queues/rx-*; do
    [ -e "$q/rps_cpus" ] && echo "$RPS_MASK" > "$q/rps_cpus" 2>/dev/null
    [ -e "$q/rps_flow_cnt" ] && echo 4096 > "$q/rps_flow_cnt" 2>/dev/null
  done
  for q in /sys/class/net/$i/queues/tx-*; do
    [ -e "$q/xps_cpus" ] && echo "$RPS_MASK" > "$q/xps_cpus" 2>/dev/null
  done
done
exit 0
