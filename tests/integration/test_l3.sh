#!/usr/bin/env bash
# tests/test_l3.sh — L3 (RIB + FIB) functional tests
# Exits 0 on full pass, non-zero on any failure.
set -euo pipefail

SOCK_DIR=$(mktemp -d /tmp/vrouter_l3_XXXXXX)
ROOTDIR=${ROOTDIR:-$(cd "$(dirname "$0")/../.." && pwd)}
FIBD=${FIBD:-$ROOTDIR/build/bin/fibd}
PASS=0; FAIL=0

cleanup() {
    kill "$FIBD_PID" 2>/dev/null || true
    wait "$FIBD_PID" 2>/dev/null || true
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

# ── start daemon ─────────────────────────────────────────────────
echo "=== L3 Tests ==="
echo "    socket dir: $SOCK_DIR"

# Remove any leftover persistence files from previous runs
rm -f vrouter_routes.json vrouter_l2.json

"$FIBD" -S "$SOCK_DIR" &
FIBD_PID=$!

# wait for sockets to appear (max 10s for slow CI runners)
for i in $(seq 1 100); do
    [ -S "$SOCK_DIR/fibd.sock" ] && [ -S "$SOCK_DIR/ribd.sock" ] && break
    sleep 0.1
done
[ -S "$SOCK_DIR/fibd.sock" ] || { echo "FATAL: fibd.sock never appeared"; exit 1; }
[ -S "$SOCK_DIR/ribd.sock" ] || { echo "FATAL: ribd.sock never appeared"; exit 1; }

# ── ping ─────────────────────────────────────────────────────────
echo ""
echo "--- Ping ---"
check "FIB ping"  fibd.sock '{"cmd":"ping"}' 'fib'
check "RIB ping"  ribd.sock '{"cmd":"ping"}' 'rib'

# ── Flush any state restored from disk ───────────────────────────
send ribd.sock '{"cmd":"flush"}' > /dev/null
send fibd.sock '{"cmd":"flush"}' > /dev/null

# ── RIB → FIB pipeline ───────────────────────────────────────────
echo ""
echo "--- RIB → FIB pipeline ---"
check "add OSPF /8"  ribd.sock \
    '{"cmd":"add","prefix":"10.0.0.0/8","nexthop":"1.1.1.1","iface":"eth0","source":"ospf"}' \
    '"ok"'
check "add eBGP /24" ribd.sock \
    '{"cmd":"add","prefix":"10.1.2.0/24","nexthop":"2.2.2.2","iface":"eth1","source":"ebgp"}' \
    '"ok"'
check "add static default" ribd.sock \
    '{"cmd":"add","prefix":"0.0.0.0/0","nexthop":"10.0.0.1","iface":"eth0","source":"static"}' \
    '"ok"'

# eBGP (AD=20) beats OSPF (AD=110) — /24 should go via 2.2.2.2
check "LPM: /24 hit → eBGP nexthop" fibd.sock \
    '{"cmd":"lookup","addr":"10.1.2.5"}' '2.2.2.2'

# /8 has only OSPF
check "LPM: /8 hit → OSPF nexthop"  fibd.sock \
    '{"cmd":"lookup","addr":"10.99.0.1"}' '1.1.1.1'

# default route for unknown prefix
check "LPM: default route fallback"  fibd.sock \
    '{"cmd":"lookup","addr":"8.8.8.8"}' '10.0.0.1'

# ── failover: withdraw eBGP, OSPF should take over ───────────────
echo ""
echo "--- eBGP failover ---"
check "del eBGP /24" ribd.sock \
    '{"cmd":"del","prefix":"10.1.2.0/24","nexthop":"2.2.2.2","source":"ebgp"}' '"ok"'
check "after failover: /24 → OSPF nexthop" fibd.sock \
    '{"cmd":"lookup","addr":"10.1.2.5"}' '1.1.1.1'

# ── get/set config ────────────────────────────────────────────────
echo ""
echo "--- get/set ---"
check "FIB get MAX_ROUTES default" fibd.sock '{"cmd":"get","key":"MAX_ROUTES"}' '"value"'
check "FIB set MAX_ROUTES"   fibd.sock '{"cmd":"set","key":"MAX_ROUTES","value":"2000"}' '"ok"'
check "FIB get MAX_ROUTES=2000" fibd.sock '{"cmd":"get","key":"MAX_ROUTES"}' '"2000"'

# ── stats ─────────────────────────────────────────────────────────
echo ""
echo "--- stats ---"
check "RIB stats has load_factor" ribd.sock '{"cmd":"stats"}' '"load_factor"'
check "FIB stats has lookups"     fibd.sock '{"cmd":"stats"}' '"total_lookups"'

# ── multi-protocol RIB: same prefix, three sources ───────────────
echo ""
echo "--- multi-source selection ---"
check "add iBGP /8 (AD=200)"  ribd.sock \
    '{"cmd":"add","prefix":"10.0.0.0/8","nexthop":"3.3.3.3","iface":"eth2","source":"ibgp"}' '"ok"'
check "add connected /8 (AD=0)" ribd.sock \
    '{"cmd":"add","prefix":"10.0.0.0/8","nexthop":"4.4.4.4","iface":"eth3","source":"connected"}' '"ok"'
# connected (AD=0) should now win
check "connected wins LPM"  fibd.sock \
    '{"cmd":"lookup","addr":"10.0.0.1"}' '4.4.4.4'

# ── flush ─────────────────────────────────────────────────────────
echo ""
echo "--- flush ---"
check "RIB flush" ribd.sock '{"cmd":"flush"}' '"ok"'
check "FIB miss after flush" fibd.sock \
    '{"cmd":"lookup","addr":"10.1.2.5"}' '"miss"'

# ── project-cli tier-3: schema written at startup ────────────────
echo ""
echo "--- project-cli tier-3 ---"
[ -f schema.json ] && { echo "  ✓ schema.json written"; PASS=$((PASS+1)); } \
                   || { echo "  ✗ schema.json missing"; FAIL=$((FAIL+1)); }

# ── summary ──────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════"
echo "  L3: $PASS passed, $FAIL failed"
echo "════════════════════════════════════"

[ "$FAIL" -eq 0 ] || exit 1
