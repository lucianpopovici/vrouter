#!/usr/bin/env bash
# tests/test_l2.sh — L2 (9-module) functional tests
# Exits 0 on full pass, non-zero on any failure.
set -euo pipefail

SOCK_DIR=$(mktemp -d /tmp/vrouter_l2_XXXXXX)
L2D=./l2/l2d
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
SOCKS="l2fdb.sock l2rib.sock l2stp.sock l2vlan.sock l2portsec.sock l2storm.sock l2igmp.sock l2arp.sock l2lacp.sock"
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
for sock_name in l2fdb l2rib l2stp l2vlan l2portsec l2storm l2igmp l2arp l2lacp; do
    check "$sock_name ping" "${sock_name}.sock" '{"cmd":"ping"}' '"ok"'
done

# ── FDB: learn, lookup, miss, flush ──────────────────────────────
echo ""
echo "--- FDB ---"
check "learn dynamic" l2fdb.sock \
    '{"cmd":"learn","mac":"aa:bb:cc:dd:ee:01","vlan":"10","port":"eth0","flags":"dynamic"}' '"ok"'
check "lookup hit" l2fdb.sock \
    '{"cmd":"lookup","mac":"aa:bb:cc:dd:ee:01","vlan":"10"}' '"port":"eth0"'
check "lookup miss → flood" l2fdb.sock \
    '{"cmd":"lookup","mac":"ff:ff:ff:ff:ff:ff","vlan":"10"}' '"miss"'
check "flush vlan 10" l2fdb.sock \
    '{"cmd":"flush","vlan":"10"}' '"ok"'
check "miss after flush" l2fdb.sock \
    '{"cmd":"lookup","mac":"aa:bb:cc:dd:ee:01","vlan":"10"}' '"miss"'
check "stats" l2fdb.sock '{"cmd":"stats"}' '"lookups"'

# ── L2RIB: multi-source, best wins, failover ─────────────────────
echo ""
echo "--- L2RIB source selection ---"
check "add static port eth0" l2rib.sock \
    '{"cmd":"add","mac":"de:ad:be:ef:00:01","vlan":"10","port":"eth0","source":"static"}' '"ok"'
check "add dynamic port eth1 (lower prio)" l2rib.sock \
    '{"cmd":"add","mac":"de:ad:be:ef:00:01","vlan":"10","port":"eth1","source":"dynamic"}' '"ok"'
# static beats dynamic → FDB should have eth0
check "FDB has static winner eth0" l2fdb.sock \
    '{"cmd":"lookup","mac":"de:ad:be:ef:00:01","vlan":"10"}' '"port":"eth0"'
# delete static → dynamic takes over
check "del static" l2rib.sock \
    '{"cmd":"del","mac":"de:ad:be:ef:00:01","vlan":"10","source":"static"}' '"ok"'
check "FDB failover to dynamic eth1" l2fdb.sock \
    '{"cmd":"lookup","mac":"de:ad:be:ef:00:01","vlan":"10"}' '"port":"eth1"'

# ── VLAN: add, port modes, allow/deny ────────────────────────────
echo ""
echo "--- VLAN ---"
check "add vlan 100" l2vlan.sock '{"cmd":"add","vlan":"100","name":"prod"}' '"ok"'
check "add vlan 200" l2vlan.sock '{"cmd":"add","vlan":"200","name":"mgmt"}' '"ok"'
check "port eth0 access vlan 100" l2vlan.sock \
    '{"cmd":"port_set","port":"eth0","mode":"access","pvid":"100"}' '"access"'
check "port eth1 trunk" l2vlan.sock \
    '{"cmd":"port_set","port":"eth1","mode":"trunk","pvid":"1"}' '"trunk"'
check "deny vlan 200 on eth0" l2vlan.sock \
    '{"cmd":"port_deny","port":"eth0","vlan_lo":"200","vlan_hi":"200"}' '"ok"'
check "show lists both vlans" l2vlan.sock '{"cmd":"show"}' '"prod"'

# ── STP/RSTP ─────────────────────────────────────────────────────
echo ""
echo "--- STP/RSTP ---"
check "port eth0 up" l2stp.sock '{"cmd":"port_up","port":"eth0"}' '"ok"'
check "port eth1 up" l2stp.sock '{"cmd":"port_up","port":"eth1"}' '"ok"'
check "inject superior BPDU" l2stp.sock \
    '{"cmd":"bpdu","port":"eth0","root":"4000.aabbcc000099","bridge":"4000.aabbcc000099","cost":"4","flags":"60"}' '"ok"'
check "show has root_id" l2stp.sock '{"cmd":"show"}' '"root_id"'
check "set priority 4096" l2stp.sock \
    '{"cmd":"set","key":"STP_PRIORITY","value":"4096"}' '"ok"'
check "get priority 4096" l2stp.sock \
    '{"cmd":"get","key":"STP_PRIORITY"}' '"4096"'
check "tick 3 hellos" l2stp.sock '{"cmd":"tick","n":"3"}' '"ok"'

# ── MST mode ─────────────────────────────────────────────────────
echo ""
echo "--- MST ---"
check "switch to mst" l2stp.sock '{"cmd":"set_mode","mode":"mst"}' '"ok"'
check "set region CORE" l2stp.sock \
    '{"cmd":"set","key":"MST_REGION","value":"CORE"}' '"ok"'
check "map vlan 100 → instance 1" l2stp.sock \
    '{"cmd":"mst_map","vlan":"100","instance":"1"}' '"ok"'
check "map vlan 200 → instance 2" l2stp.sock \
    '{"cmd":"mst_map","vlan":"200","instance":"2"}' '"ok"'
check "mst_show has instances" l2stp.sock '{"cmd":"mst_show"}' '"instances"'
check "get MST_REGION=CORE" l2stp.sock '{"cmd":"get","key":"MST_REGION"}' '"CORE"'

# ── Port Security ────────────────────────────────────────────────
echo ""
echo "--- Port Security ---"
check "configure max=2 restrict" l2portsec.sock \
    '{"cmd":"configure","port":"eth0","max_macs":"2","violation":"restrict"}' '"ok"'
check "check mac1 permit" l2portsec.sock \
    '{"cmd":"check","port":"eth0","mac":"aa:bb:cc:00:00:01","vlan":"10"}' '"permit"'
check "check mac2 permit" l2portsec.sock \
    '{"cmd":"check","port":"eth0","mac":"aa:bb:cc:00:00:02","vlan":"10"}' '"permit"'
check "check mac3 deny (max=2)" l2portsec.sock \
    '{"cmd":"check","port":"eth0","mac":"aa:bb:cc:00:00:03","vlan":"10"}' '"deny"'
check "show lists port" l2portsec.sock '{"cmd":"show"}' '"eth0"'

# ── Storm Control ─────────────────────────────────────────────────
echo ""
echo "--- Storm Control ---"
check "set BC 1000pps" l2storm.sock \
    '{"cmd":"set_rate","port":"eth0","type":"broadcast","pps":"1000","burst":"500"}' '"ok"'
check "first frame passes" l2storm.sock \
    '{"cmd":"check","port":"eth0","type":"broadcast"}' '"pass"'
check "show has bucket" l2storm.sock '{"cmd":"show"}' '"rate_pps"'

# ── IGMP Snooping ─────────────────────────────────────────────────
echo ""
echo "--- IGMP Snooping ---"
check "report 239.1.1.1 vlan 100" l2igmp.sock \
    '{"cmd":"report","port":"eth0","group":"239.1.1.1","vlan":"100"}' '"ok"'
check "report 239.1.1.2 vlan 100" l2igmp.sock \
    '{"cmd":"report","port":"eth1","group":"239.1.1.2","vlan":"100"}' '"ok"'
check "show lists groups" l2igmp.sock '{"cmd":"show"}' '"group"'
check "stats has reports" l2igmp.sock '{"cmd":"stats"}' '"reports"'
check "leave 239.1.1.1" l2igmp.sock \
    '{"cmd":"leave","port":"eth0","group":"239.1.1.1","vlan":"100"}' '"ok"'

# ── ARP/ND Snooping ───────────────────────────────────────────────
echo ""
echo "--- ARP/ND Snooping ---"
check "learn 192.168.1.1" l2arp.sock \
    '{"cmd":"learn","mac":"aa:bb:cc:dd:ee:ff","ip":"192.168.1.1","port":"eth0","vlan":"100","type":"arp"}' '"ok"'
check "lookup 192.168.1.1" l2arp.sock \
    '{"cmd":"lookup","ip":"192.168.1.1","vlan":"100"}' '"mac"'
check "learn IPv6 ::1" l2arp.sock \
    '{"cmd":"learn","mac":"aa:bb:cc:dd:ee:ff","ip":"fe80::1","port":"eth0","vlan":"100","type":"nd","ipv6":"true"}' '"ok"'
check "stats has bindings" l2arp.sock '{"cmd":"stats"}' '"bindings"'

# detect ARP spoofing: same IP, different port
check "spoof attempt detected" l2arp.sock \
    '{"cmd":"learn","mac":"11:22:33:44:55:66","ip":"192.168.1.1","port":"eth1","vlan":"100","type":"arp"}' '"violation"'

# ── LACP ──────────────────────────────────────────────────────────
echo ""
echo "--- LACP ---"
check "create lag bond0" l2lacp.sock '{"cmd":"lag_add","lag":"bond0","key":"1"}' '"ok"'
check "add eth0 active" l2lacp.sock \
    '{"cmd":"member_add","lag":"bond0","port":"eth0","mode":"active"}' '"ok"'
check "add eth1 active" l2lacp.sock \
    '{"cmd":"member_add","lag":"bond0","port":"eth1","mode":"active"}' '"ok"'
check "inject LACPDU on eth0" l2lacp.sock \
    '{"cmd":"bpdu","lag":"bond0","port":"eth0","actor_sys":"8000.aabbcc000099","actor_key":"1","actor_state":"61"}' '"ok"'
check "TX hash eth0→eth1" l2lacp.sock \
    '{"cmd":"hash","lag":"bond0","src":"aa:bb:cc:00:00:01","dst":"dd:ee:ff:00:00:01"}' '"member"'
check "show bond0" l2lacp.sock '{"cmd":"show"}' '"bond0"'

# ── get/set config ────────────────────────────────────────────────
echo ""
echo "--- get/set config ---"
check "fdb get FDB_AGE_SEC"     l2fdb.sock '{"cmd":"get","key":"FDB_AGE_SEC"}' '"value"'
check "fdb set FDB_AGE_SEC=120" l2fdb.sock '{"cmd":"set","key":"FDB_AGE_SEC","value":"120"}' '"ok"'
check "fdb get FDB_AGE_SEC=120" l2fdb.sock '{"cmd":"get","key":"FDB_AGE_SEC"}' '"120"'
# change is visible on l2rib too (shared cfg pointer)
check "l2rib sees same FDB_AGE_SEC=120" l2rib.sock \
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
