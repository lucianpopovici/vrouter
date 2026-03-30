#!/usr/bin/env bash
# tests/test_persist.sh — Persistence + SIGHUP tests for L3 + L2
set -euo pipefail

SOCK_DIR=$(mktemp -d /tmp/vrouter_persist_XXXXXX)
SOCK_DIR2=$(mktemp -d /tmp/vrouter_persist2_XXXXXX)
# Dump files land in CWD — use a dedicated dir
WORK_DIR=$(mktemp -d /tmp/vrouter_work_XXXXXX)
PASS=0; FAIL=0
L3_PID=""; L2_PID=""

cleanup() {
    [ -n "$L3_PID" ] && kill "$L3_PID" 2>/dev/null || true
    [ -n "$L2_PID" ] && kill "$L2_PID" 2>/dev/null || true
    wait 2>/dev/null || true
    cd /home/claude/package 2>/dev/null || true
    rm -rf "$SOCK_DIR" "$SOCK_DIR2" "$WORK_DIR"
}
trap cleanup EXIT

send() { echo "$2" | nc -U "$1" -w2 2>/dev/null; }

check() {
    local label="$1" sock="$2" cmd="$3" expect="$4"
    local result; result=$(send "$sock" "$cmd")
    if echo "$result" | grep -qF "$expect"; then
        printf "  ✓ %s\n" "$label"; PASS=$((PASS+1))
    else
        printf "  ✗ %s\n    expected: %s\n    got: %s\n" \
               "$label" "$expect" "$result"; FAIL=$((FAIL+1))
    fi
}

wait_sock() {
    for i in $(seq 1 50); do [ -S "$1" ] && return 0; sleep 0.1; done
    echo "FATAL: $1 never appeared"; exit 1
}

echo "════════════════════════════════════════════════"
echo "  Persistence + SIGHUP Tests"
echo "════════════════════════════════════════════════"

# Resolve binary paths before cd'ing away
FIBD="$(cd "$(dirname "$0")/.." && pwd)/l3/fibd"
L2D="$(cd "$(dirname "$0")/.." && pwd)/l2/l2d"

# Work from a temp dir so dump files land predictably
cd "$WORK_DIR"

# ── Phase 1: Start daemons, populate state ────────────────────
echo ""
echo "--- Phase 1: populate state ---"

"$FIBD" -S "$SOCK_DIR" &
L3_PID=$!
"$L2D" -m rstp -S "$SOCK_DIR" &
L2_PID=$!

wait_sock "$SOCK_DIR/fibd.sock"
wait_sock "$SOCK_DIR/ribd.sock"
wait_sock "$SOCK_DIR/fdb.sock"
wait_sock "$SOCK_DIR/stp.sock"
wait_sock "$SOCK_DIR/lacp.sock"
wait_sock "$SOCK_DIR/vlan.sock"

# L3: add routes from multiple sources
send "$SOCK_DIR/ribd.sock" '{"cmd":"add","prefix":"10.0.0.0/8","nexthop":"1.1.1.1","iface":"eth0","source":"ospf"}' >/dev/null
send "$SOCK_DIR/ribd.sock" '{"cmd":"add","prefix":"10.1.2.0/24","nexthop":"2.2.2.2","iface":"eth1","source":"ebgp"}' >/dev/null
send "$SOCK_DIR/ribd.sock" '{"cmd":"add","prefix":"172.16.0.0/12","nexthop":"3.3.3.3","iface":"eth0","source":"static"}' >/dev/null

check "L3 routes live before restart" \
    "$SOCK_DIR/fibd.sock" '{"cmd":"lookup","addr":"10.1.2.5"}' '2.2.2.2'

# L2: static FDB, VLAN, STP priority, LACP
send "$SOCK_DIR/fdb.sock"  '{"cmd":"learn","mac":"aa:bb:cc:dd:ee:01","vlan":"10","port":"eth0","flags":"static"}' >/dev/null
send "$SOCK_DIR/vlan.sock" '{"cmd":"add","vlan":"200","name":"persist-test"}' >/dev/null
send "$SOCK_DIR/stp.sock"  '{"cmd":"set","key":"STP_PRIORITY","value":"8192"}' >/dev/null
send "$SOCK_DIR/lacp.sock" '{"cmd":"lag_add","lag":"bond0","key":"5"}' >/dev/null
send "$SOCK_DIR/lacp.sock" '{"cmd":"member_add","lag":"bond0","port":"eth0","mode":"active"}' >/dev/null

sleep 0.1   # let writes settle

# ── Phase 2: SIGHUP checkpoint ────────────────────────────────
echo ""
echo "--- Phase 2: SIGHUP checkpoint ---"

kill -HUP "$L3_PID"
kill -HUP "$L2_PID"
sleep 0.8   # management loop runs every 100ms; wait for 2 ticks

[ -f "vrouter_routes.json" ] && \
    { echo "  ✓ L3 checkpoint written ($(wc -l < vrouter_routes.json) routes)"; PASS=$((PASS+1)); } || \
    { echo "  ✗ L3 checkpoint missing"; FAIL=$((FAIL+1)); }
[ -f "vrouter_l2.json" ] && \
    { echo "  ✓ L2 checkpoint written ($(wc -l < vrouter_l2.json) objects)"; PASS=$((PASS+1)); } || \
    { echo "  ✗ L2 checkpoint missing"; FAIL=$((FAIL+1)); }

# ── Phase 3: Clean shutdown ────────────────────────────────────
echo ""
echo "--- Phase 3: clean shutdown ---"

kill -TERM "$L3_PID"; kill -TERM "$L2_PID"
wait "$L3_PID" 2>/dev/null || true
wait "$L2_PID" 2>/dev/null || true
L3_PID=""; L2_PID=""
sleep 0.2

[ -f "vrouter_routes.json" ] && \
    { echo "  ✓ L3 dump present ($(wc -l < vrouter_routes.json) routes)"; } || \
    { echo "  ✗ L3 dump missing"; FAIL=$((FAIL+1)); }
[ -f "vrouter_l2.json" ] && \
    { echo "  ✓ L2 dump present ($(wc -l < vrouter_l2.json) objects)"; } || \
    { echo "  ✗ L2 dump missing"; FAIL=$((FAIL+1)); }

echo "  L3 dump contents:"
cat vrouter_routes.json 2>/dev/null | head -5 || echo "    (empty)"
echo "  L2 dump contents:"
cat vrouter_l2.json     2>/dev/null | head -5 || echo "    (empty)"

# ── Phase 4: Restart and verify restore ───────────────────────
echo ""
echo "--- Phase 4: restart and verify restore ---"

"$FIBD" -S "$SOCK_DIR2" &
L3_PID=$!
"$L2D" -m rstp -S "$SOCK_DIR2" &
L2_PID=$!

wait_sock "$SOCK_DIR2/fibd.sock"
wait_sock "$SOCK_DIR2/ribd.sock"
wait_sock "$SOCK_DIR2/fdb.sock"
wait_sock "$SOCK_DIR2/stp.sock"
wait_sock "$SOCK_DIR2/lacp.sock"
wait_sock "$SOCK_DIR2/vlan.sock"
sleep 0.3   # let restore settle

# L3 restore
check "L3 OSPF /8 restored"    "$SOCK_DIR2/fibd.sock" '{"cmd":"lookup","addr":"10.99.0.1"}'  '1.1.1.1'
check "L3 eBGP /24 restored"   "$SOCK_DIR2/fibd.sock" '{"cmd":"lookup","addr":"10.1.2.5"}'   '2.2.2.2'
check "L3 static /12 restored" "$SOCK_DIR2/fibd.sock" '{"cmd":"lookup","addr":"172.16.0.1"}' '3.3.3.3'

# L2 restore
check "L2 static FDB restored" \
    "$SOCK_DIR2/fdb.sock" '{"cmd":"lookup","mac":"aa:bb:cc:dd:ee:01","vlan":"10"}' 'eth0'
check "L2 VLAN 200 restored" \
    "$SOCK_DIR2/vlan.sock" '{"cmd":"show"}' 'persist-test'
check "L2 STP priority 8192 restored" \
    "$SOCK_DIR2/stp.sock" '{"cmd":"get","key":"STP_PRIORITY"}' '8192'
check "L2 LACP bond0 restored" \
    "$SOCK_DIR2/lacp.sock" '{"cmd":"show"}' 'bond0'

# ── Summary ───────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════"
echo "  Persistence: $PASS passed, $FAIL failed"
echo "════════════════════════════════════"

[ "$FAIL" -eq 0 ] || exit 1
