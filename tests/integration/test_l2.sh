#!/usr/bin/env bash
# tests/test_l2.sh — L2 (9-module) functional tests
# Exits 0 on full pass, non-zero on any failure.
set -euo pipefail

SOCK_DIR=$(mktemp -d /tmp/vrouter_l2_XXXXXX)
ROOTDIR=${ROOTDIR:-$(cd "$(dirname "$0")/../.." && pwd)}
L2D=${L2D:-$ROOTDIR/build/bin/l2d}
PASS=0; FAIL=0

cleanup() {
    kill "$L2D_PID" 2>/dev/null || true
    wait "$L2D_PID" 2>/dev/null || true
    rm -rf "$SOCK_DIR"
}
trap cleanup EXIT

# ── helpers ──────────────────────────────────────────────────────
send() { echo "$2" | nc -U "$SOCK_DIR/$1" -w2 2>/dev/null; }

check() {
    local label="$1" sock="$2" cmd="$3" expect="$4"
    local result
    result=$(send "$sock" "$cmd")
    if echo "$result" | grep -qF "$expect"; then
        printf "  ✓ %s\n" "$label"
        PASS=$((PASS+1))
    else
        printf "  ✗ %s\n    expected: %s\n    got:      %s\n" \
               "$label" "$expect" "$result"
        FAIL=$((FAIL+1))
    fi
}

check_absent() {
    local label="$1" sock="$2" cmd="$3" absent="$4"
    local result
    result=$(send "$sock" "$cmd")
    if echo "$result" | grep -qF "$absent"; then
        printf "  ✗ %s (should be absent: %s)\n    got: %s\n" "$label" "$absent" "$result"
        FAIL=$((FAIL+1))
    else
        printf "  ✓ %s\n" "$label"
        PASS=$((PASS+1))
    fi
}

# ── start daemon ─────────────────────────────────────────────────
echo "=== L2 Tests (mode: rstp) ==="
echo "    socket dir: $SOCK_DIR"

"$L2D" -m rstp -S "$SOCK_DIR" &
L2D_PID=$!

# wait up to 5s for all 9 sockets
SOCKS="fdb.sock rib.sock stp.sock vlan.sock portsec.sock storm.sock igmp.sock arp.sock lacp.sock"
for i in $(seq 1 50); do
    all=1
    for s in $SOCKS; do
        [ -S "$SOCK_DIR/$s" ] || { all=0; break; }
    done
    [ "$all" -eq 1 ] && break
    sleep 0.1
done

for s in $SOCKS; do
    [ -S "$SOCK_DIR/$s" ] || { echo "FATAL: $s never appeared"; exit 1; }
done

# ── ping all 9 modules ───────────────────────────────────────────
echo ""
echo "--- Ping all modules ---"
for sock_name in fdb rib stp vlan portsec storm igmp arp lacp; do
    check "$sock_name ping" "${sock_name}.sock" '{"cmd":"ping"}' '"ok"'
done

# ── FDB: learn, lookup, miss, flush ──────────────────────────────
echo ""
echo "--- FDB ---"
check "learn dynamic" fdb.sock \
    '{"cmd":"learn","mac":"aa:bb:cc:dd:ee:01","vlan":"10","port":"eth0","flags":"dynamic"}' '"ok"'
check "lookup hit" fdb.sock \
    '{"cmd":"lookup","mac":"aa:bb:cc:dd:ee:01","vlan":"10"}' '"port":"eth0"'
check "lookup miss → flood" fdb.sock \
    '{"cmd":"lookup","mac":"ff:ff:ff:ff:ff:ff","vlan":"10"}' '"miss"'
check "flush vlan 10" fdb.sock \
    '{"cmd":"flush","vlan":"10"}' '"ok"'
check "miss after flush" fdb.sock \
    '{"cmd":"lookup","mac":"aa:bb:cc:dd:ee:01","vlan":"10"}' '"miss"'
check "stats" fdb.sock '{"cmd":"stats"}' '"lookups"'

# ── RIB: multi-source, best wins, failover ─────────────────────
echo ""
echo "--- RIB source selection ---"
check "add static port eth0" rib.sock \
    '{"cmd":"add","mac":"de:ad:be:ef:00:01","vlan":"10","port":"eth0","source":"static"}' '"ok"'
check "add dynamic port eth1 (lower prio)" rib.sock \
    '{"cmd":"add","mac":"de:ad:be:ef:00:01","vlan":"10","port":"eth1","source":"dynamic"}' '"ok"'
# static beats dynamic → FDB should have eth0
check "FDB has static winner eth0" fdb.sock \
    '{"cmd":"lookup","mac":"de:ad:be:ef:00:01","vlan":"10"}' '"port":"eth0"'
# delete static → dynamic takes over
check "del static" rib.sock \
    '{"cmd":"del","mac":"de:ad:be:ef:00:01","vlan":"10","source":"static"}' '"ok"'
check "FDB failover to dynamic eth1" fdb.sock \
    '{"cmd":"lookup","mac":"de:ad:be:ef:00:01","vlan":"10"}' '"port":"eth1"'

# ── VLAN: add, port modes, allow/deny ────────────────────────────
echo ""
echo "--- VLAN ---"
check "add vlan 100" vlan.sock '{"cmd":"add","vlan":"100","name":"prod"}' '"ok"'
check "add vlan 200" vlan.sock '{"cmd":"add","vlan":"200","name":"mgmt"}' '"ok"'
check "port eth0 access vlan 100" vlan.sock \
    '{"cmd":"port_set","port":"eth0","mode":"access","pvid":"100"}' '"access"'
check "port eth1 trunk" vlan.sock \
    '{"cmd":"port_set","port":"eth1","mode":"trunk","pvid":"1"}' '"trunk"'
check "deny vlan 200 on eth0" vlan.sock \
    '{"cmd":"port_deny","port":"eth0","vlan_lo":"200","vlan_hi":"200"}' '"ok"'
check "show lists both vlans" vlan.sock '{"cmd":"show"}' '"prod"'

# ── STP/RSTP ─────────────────────────────────────────────────────
echo ""
echo "--- STP/RSTP ---"
check "port eth0 up" stp.sock '{"cmd":"port_up","port":"eth0"}' '"ok"'
check "port eth1 up" stp.sock '{"cmd":"port_up","port":"eth1"}' '"ok"'
check "inject superior BPDU" stp.sock \
    '{"cmd":"bpdu","port":"eth0","root":"4000.aabbcc000099","bridge":"4000.aabbcc000099","cost":"4","flags":"60"}' '"ok"'
check "show has root_id" stp.sock '{"cmd":"show"}' '"root_id"'
check "set priority 4096" stp.sock \
    '{"cmd":"set","key":"STP_PRIORITY","value":"4096"}' '"ok"'
check "get priority 4096" stp.sock \
    '{"cmd":"get","key":"STP_PRIORITY"}' '"4096"'
check "tick 3 hellos" stp.sock '{"cmd":"tick","n":"3"}' '"ok"'

# ── MST mode ─────────────────────────────────────────────────────
echo ""
echo "--- MST ---"
check "switch to mst" stp.sock '{"cmd":"set_mode","mode":"mst"}' '"ok"'
check "set region CORE" stp.sock \
    '{"cmd":"set","key":"MST_REGION","value":"CORE"}' '"ok"'
check "map vlan 100 → instance 1" stp.sock \
    '{"cmd":"mst_map","vlan":"100","instance":"1"}' '"ok"'
check "map vlan 200 → instance 2" stp.sock \
    '{"cmd":"mst_map","vlan":"200","instance":"2"}' '"ok"'
check "mst_show has instances" stp.sock '{"cmd":"mst_show"}' '"instances"'
check "get MST_REGION=CORE" stp.sock '{"cmd":"get","key":"MST_REGION"}' '"CORE"'

# ── Port Security ────────────────────────────────────────────────
echo ""
echo "--- Port Security ---"
check "configure max=2 restrict" portsec.sock \
    '{"cmd":"configure","port":"eth0","max_macs":"2","violation":"restrict"}' '"ok"'
check "check mac1 permit" portsec.sock \
    '{"cmd":"check","port":"eth0","mac":"aa:bb:cc:00:00:01","vlan":"10"}' '"permit"'
check "check mac2 permit" portsec.sock \
    '{"cmd":"check","port":"eth0","mac":"aa:bb:cc:00:00:02","vlan":"10"}' '"permit"'
check "check mac3 deny (max=2)" portsec.sock \
    '{"cmd":"check","port":"eth0","mac":"aa:bb:cc:00:00:03","vlan":"10"}' '"deny"'
check "show lists port" portsec.sock '{"cmd":"show"}' '"eth0"'

# ── Storm Control ─────────────────────────────────────────────────
echo ""
echo "--- Storm Control ---"
check "set BC 1000pps" storm.sock \
    '{"cmd":"set_rate","port":"eth0","type":"broadcast","pps":"1000","burst":"500"}' '"ok"'
check "first frame passes" storm.sock \
    '{"cmd":"check","port":"eth0","type":"broadcast"}' '"pass"'
check "show has bucket" storm.sock '{"cmd":"show"}' '"rate_pps"'

# ── IGMP Snooping ─────────────────────────────────────────────────
echo ""
echo "--- IGMP Snooping ---"
check "report 239.1.1.1 vlan 100" igmp.sock \
    '{"cmd":"report","port":"eth0","group":"239.1.1.1","vlan":"100"}' '"ok"'
check "report 239.1.1.2 vlan 100" igmp.sock \
    '{"cmd":"report","port":"eth1","group":"239.1.1.2","vlan":"100"}' '"ok"'
check "show lists groups" igmp.sock '{"cmd":"show"}' '"group"'
check "stats has reports" igmp.sock '{"cmd":"stats"}' '"reports"'
check "leave 239.1.1.1" igmp.sock \
    '{"cmd":"leave","port":"eth0","group":"239.1.1.1","vlan":"100"}' '"ok"'

# ── ARP/ND Snooping ───────────────────────────────────────────────
echo ""
echo "--- ARP/ND Snooping ---"
check "learn 192.168.1.1" arp.sock \
    '{"cmd":"learn","mac":"aa:bb:cc:dd:ee:ff","ip":"192.168.1.1","port":"eth0","vlan":"100","type":"arp"}' '"ok"'
check "lookup 192.168.1.1" arp.sock \
    '{"cmd":"lookup","ip":"192.168.1.1","vlan":"100"}' '"mac"'
check "learn IPv6 ::1" arp.sock \
    '{"cmd":"learn","mac":"aa:bb:cc:dd:ee:ff","ip":"fe80::1","port":"eth0","vlan":"100","type":"nd","ipv6":"true"}' '"ok"'
check "stats has bindings" arp.sock '{"cmd":"stats"}' '"bindings"'

# detect ARP spoofing: same IP, different port
check "spoof attempt detected" arp.sock \
    '{"cmd":"learn","mac":"11:22:33:44:55:66","ip":"192.168.1.1","port":"eth1","vlan":"100","type":"arp"}' '"violation"'

# ── LACP ──────────────────────────────────────────────────────────
echo ""
echo "--- LACP ---"
check "create lag bond0" lacp.sock '{"cmd":"lag_add","lag":"bond0","key":"1"}' '"ok"'
check "add eth0 active" lacp.sock \
    '{"cmd":"member_add","lag":"bond0","port":"eth0","mode":"active"}' '"ok"'
check "add eth1 active" lacp.sock \
    '{"cmd":"member_add","lag":"bond0","port":"eth1","mode":"active"}' '"ok"'
check "inject LACPDU on eth0" lacp.sock \
    '{"cmd":"bpdu","lag":"bond0","port":"eth0","actor_sys":"8000.aabbcc000099","actor_key":"1","actor_state":"61"}' '"ok"'
check "TX hash eth0→eth1" lacp.sock \
    '{"cmd":"hash","lag":"bond0","src":"aa:bb:cc:00:00:01","dst":"dd:ee:ff:00:00:01"}' '"member"'
check "show bond0" lacp.sock '{"cmd":"show"}' '"bond0"'

# ── get/set config ────────────────────────────────────────────────
echo ""
echo "--- get/set config ---"
check "fdb get FDB_AGE_SEC"     fdb.sock '{"cmd":"get","key":"FDB_AGE_SEC"}' '"value"'
check "fdb set FDB_AGE_SEC=120" fdb.sock '{"cmd":"set","key":"FDB_AGE_SEC","value":"120"}' '"ok"'
check "fdb get FDB_AGE_SEC=120" fdb.sock '{"cmd":"get","key":"FDB_AGE_SEC"}' '"120"'
# change is visible on rib too (shared cfg pointer)
check "rib sees same FDB_AGE_SEC=120" rib.sock \
    '{"cmd":"get","key":"FDB_AGE_SEC"}' '"120"'

# ── project-cli tier-3 ────────────────────────────────────────────
echo ""
echo "--- project-cli tier-3 ---"
[ -f l2d_schema.json ] && { echo "  ✓ l2d_schema.json written"; PASS=$((PASS+1)); } \
                        || { echo "  ✗ l2d_schema.json missing"; FAIL=$((FAIL+1)); }

# ── summary ──────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════"
echo "  L2: $PASS passed, $FAIL failed"
echo "════════════════════════════════════"

[ "$FAIL" -eq 0 ] || exit 1
