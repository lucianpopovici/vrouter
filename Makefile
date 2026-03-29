# ================================================================
# Top-level Makefile — Network Stack (L2 + L3 + IP + VRF + EVPN + VXLAN)
# ================================================================
#
# Targets:
#   make            build everything
#   make l3         build L3 only  (fibd)
#   make l2         build L2 only  (l2d)
#   make ip         build IP daemon only
#   make vrf        build VRF daemon only
#   make evpn       build EVPN daemon only
#   make vxlan      build VXLAN daemon only
#   make clean      clean all
#   make install    install binaries to $(PREFIX)/bin
#   make run-l3     start the L3 daemon (background)
#   make run-l2     start the L2 daemon (background, RSTP mode)
#   make run-ip     start the IP daemon (background)
#   make run-vrf    start the VRF daemon (background)
#   make run-evpn   start the EVPN daemon (background)
#   make run-vxlan  start the VXLAN daemon (background)
#   make run        start all daemons
#   make stop       kill all daemons
#   make status     show daemon socket status
#
# Variables:
#   MODE=rstp         STP mode for l2d (stp | rstp | mst)
#   SOCK_DIR=/tmp     Directory for all Unix sockets
#   PREFIX=/usr/local install prefix

.PHONY: all l3 l2 ip vrf evpn vxlan clean install \
        run-l3 run-l2 run-ip run-vrf run-evpn run-vxlan run stop status \
        test-l3 test-l2 test

MODE     ?= rstp
SOCK_DIR ?= /tmp
PREFIX   ?= /usr/local

# ── sub-directories ──────────────────────────────────────────── #
L3_DIR   := l3
L2_DIR   := l2
IP_DIR   := ip
VRF_DIR  := vrf
EVPN_DIR := evpn
VXLAN_DIR := vxlan

L3_BIN   := $(L3_DIR)/fibd
L2_BIN   := $(L2_DIR)/l2d
IP_BIN   := $(IP_DIR)/ip_daemon
VRF_BIN  := $(VRF_DIR)/vrf_daemon
EVPN_BIN := $(EVPN_DIR)/evpn_daemon
VXLAN_BIN := $(VXLAN_DIR)/vxlan_daemon

# ================================================================
# Build targets
# ================================================================

all: l3 l2 ip vrf evpn vxlan
	@echo ""
	@echo "══════════════════════════════════════════"
	@echo "  Build complete"
	@echo "  L3    →  $(L3_BIN)"
	@echo "  L2    →  $(L2_BIN)"
	@echo "  IP    →  $(IP_BIN)"
	@echo "  VRF   →  $(VRF_BIN)"
	@echo "  EVPN  →  $(EVPN_BIN)"
	@echo "  VXLAN →  $(VXLAN_BIN)"
	@echo "══════════════════════════════════════════"
	@echo "  Run:   make run"
	@echo "  Stop:  make stop"
	@echo "  Status:make status"
	@echo "══════════════════════════════════════════"

l3:
	@echo "[l3] building..."
	$(MAKE) -C $(L3_DIR)
	@echo "[l3] done → $(L3_BIN)"

l2:
	@echo "[l2] building..."
	$(MAKE) -C $(L2_DIR)
	@echo "[l2] done → $(L2_BIN)"

ip:
	@echo "[ip] building..."
	$(MAKE) -C $(IP_DIR) daemon SOCK_DIR=$(SOCK_DIR)
	@echo "[ip] done → $(IP_BIN)"

vrf:
	@echo "[vrf] building..."
	$(MAKE) -C $(VRF_DIR) daemon SOCK_DIR=$(SOCK_DIR)
	@echo "[vrf] done → $(VRF_BIN)"

evpn:
	@echo "[evpn] building..."
	$(MAKE) -C $(EVPN_DIR) daemon
	@echo "[evpn] done → $(EVPN_BIN)"

vxlan:
	@echo "[vxlan] building..."
	$(MAKE) -C $(VXLAN_DIR) daemon
	@echo "[vxlan] done → $(VXLAN_BIN)"

# ================================================================
# Clean
# ================================================================

clean:
	@echo "[l3] cleaning..."
	$(MAKE) -C $(L3_DIR) clean
	@echo "[l2] cleaning..."
	$(MAKE) -C $(L2_DIR) clean
	@echo "[ip] cleaning..."
	$(MAKE) -C $(IP_DIR) clean
	@echo "[vrf] cleaning..."
	$(MAKE) -C $(VRF_DIR) clean
	@echo "[evpn] cleaning..."
	$(MAKE) -C $(EVPN_DIR) clean
	@echo "[vxlan] cleaning..."
	$(MAKE) -C $(VXLAN_DIR) clean
	@echo "clean done"

# ================================================================
# Install
# ================================================================

install: all
	install -d $(PREFIX)/bin
	install -m 755 $(L3_BIN)   $(PREFIX)/bin/fibd
	install -m 755 $(L2_BIN)   $(PREFIX)/bin/l2d
	install -m 755 $(IP_BIN)   $(PREFIX)/bin/ip_daemon
	install -m 755 $(VRF_BIN)  $(PREFIX)/bin/vrf_daemon
	install -m 755 $(EVPN_BIN) $(PREFIX)/bin/evpn_daemon
	install -m 755 $(VXLAN_BIN) $(PREFIX)/bin/vxlan_daemon
	@echo "installed all daemons to $(PREFIX)/bin"

# ================================================================
# Run / Stop / Status
# ================================================================

run-l3: l3
	@pkill -f '[/]fibd\b' 2>/dev/null; pkill -f 'fibd\b' 2>/dev/null; sleep 0.2; rm -f $(SOCK_DIR)/fibd.sock $(SOCK_DIR)/ribd.sock
	@echo "[l3] starting fibd (sock_dir=$(SOCK_DIR))..."
	@$(L3_BIN) -S $(SOCK_DIR) &
	@sleep 0.3
	@echo "[l3] fibd running ($(SOCK_DIR)/fibd.sock  $(SOCK_DIR)/ribd.sock)"

run-l2: l2
	@pkill -f '[/]l2d\b' 2>/dev/null; pkill -f 'l2d\b' 2>/dev/null; sleep 0.2
	@echo "[l2] starting l2d (mode=$(MODE) sock_dir=$(SOCK_DIR))..."
	@$(L2_BIN) -m $(MODE) -S $(SOCK_DIR) &
	@sleep 0.3
	@echo "[l2] l2d running (9 sockets under $(SOCK_DIR)/)"

run-ip: ip
	@pkill -f '[/]ip_daemon\b' 2>/dev/null; pkill -f 'ip_daemon\b' 2>/dev/null; sleep 0.2; rm -f $(SOCK_DIR)/ip.sock
	@echo "[ip] starting ip_daemon (sock=$(SOCK_DIR)/ip.sock)..."
	@$(IP_BIN) -s $(SOCK_DIR)/ip.sock &
	@sleep 0.3
	@echo "[ip] ip_daemon running ($(SOCK_DIR)/ip.sock)"

run-vrf: vrf
	@pkill -f '[/]vrf_daemon\b' 2>/dev/null; pkill -f 'vrf_daemon\b' 2>/dev/null; sleep 0.2; rm -f $(SOCK_DIR)/vrf.sock
	@echo "[vrf] starting vrf_daemon (sock=$(SOCK_DIR)/vrf.sock)..."
	@$(VRF_BIN) -s $(SOCK_DIR)/vrf.sock &
	@sleep 0.3
	@echo "[vrf] vrf_daemon running ($(SOCK_DIR)/vrf.sock)"

run-evpn: evpn
	@pkill -f '[/]evpn_daemon\b' 2>/dev/null; pkill -f 'evpn_daemon\b' 2>/dev/null; sleep 0.2; rm -f $(SOCK_DIR)/evpn.sock
	@echo "[evpn] starting evpn_daemon (sock=$(SOCK_DIR)/evpn.sock)..."
	@$(EVPN_BIN) -s $(SOCK_DIR)/evpn.sock &
	@sleep 0.3
	@echo "[evpn] evpn_daemon running ($(SOCK_DIR)/evpn.sock)"

run-vxlan: vxlan
	@pkill -f '[/]vxlan_daemon\b' 2>/dev/null; pkill -f 'vxlan_daemon\b' 2>/dev/null; sleep 0.2; rm -f $(SOCK_DIR)/vxlan.sock
	@echo "[vxlan] starting vxlan_daemon (sock=$(SOCK_DIR)/vxlan.sock)..."
	@$(VXLAN_BIN) -s $(SOCK_DIR)/vxlan.sock &
	@sleep 0.3
	@echo "[vxlan] vxlan_daemon running ($(SOCK_DIR)/vxlan.sock)"

run: run-l3 run-l2 run-ip run-vrf run-evpn run-vxlan
	@echo ""
	@echo "All daemons started. Run 'make status' to verify."

stop:
	@echo "Stopping daemons..."
	@pkill -f '[/]fibd\b'        2>/dev/null; pkill -f 'fibd\b'        2>/dev/null; echo "  fibd stopped"
	@pkill -f '[/]l2d\b'         2>/dev/null; pkill -f 'l2d\b'         2>/dev/null; echo "  l2d stopped"
	@pkill -f '[/]ip_daemon\b'   2>/dev/null; pkill -f 'ip_daemon\b'   2>/dev/null; echo "  ip_daemon stopped"
	@pkill -f '[/]vrf_daemon\b'  2>/dev/null; pkill -f 'vrf_daemon\b'  2>/dev/null; echo "  vrf_daemon stopped"
	@pkill -f '[/]evpn_daemon\b' 2>/dev/null; pkill -f 'evpn_daemon\b' 2>/dev/null; echo "  evpn_daemon stopped"
	@pkill -f '[/]vxlan_daemon\b' 2>/dev/null; pkill -f 'vxlan_daemon\b' 2>/dev/null; echo "  vxlan_daemon stopped"
	@sleep 0.3
	@rm -f $(SOCK_DIR)/ip.sock $(SOCK_DIR)/vrf.sock $(SOCK_DIR)/evpn.sock $(SOCK_DIR)/vxlan.sock
	@rm -f $(SOCK_DIR)/fibd.sock $(SOCK_DIR)/ribd.sock
	@echo "  socket files removed"

status:
	@echo "=== Daemon processes ==="
	@pgrep -a fibd        2>/dev/null || echo "  fibd:         not running"
	@pgrep -a l2d         2>/dev/null || echo "  l2d:          not running"
	@pgrep -a ip_daemon   2>/dev/null || echo "  ip_daemon:    not running"
	@pgrep -a vrf_daemon  2>/dev/null || echo "  vrf_daemon:   not running"
	@pgrep -a evpn_daemon 2>/dev/null || echo "  evpn_daemon:  not running"
	@pgrep -a vxlan_daemon 2>/dev/null || echo "  vxlan_daemon: not running"
	@echo ""
	@echo "=== L3 sockets (SOCK_DIR=$(SOCK_DIR)) ==="
	@for s in $(SOCK_DIR)/fibd.sock $(SOCK_DIR)/ribd.sock; do \
	  if [ -S "$$s" ]; then \
	    printf "  %-30s  " "$$s"; \
	    echo '{"cmd":"ping"}' | nc -U "$$s" -w1 2>/dev/null || echo "no response"; \
	  else \
	    echo "  $$s  (absent)"; \
	  fi; \
	  echo ""; \
	done
	@echo ""
	@echo "=== L2 sockets (SOCK_DIR=$(SOCK_DIR)) ==="
	@for s in $(SOCK_DIR)/fdb.sock $(SOCK_DIR)/rib.sock \
	           $(SOCK_DIR)/stp.sock $(SOCK_DIR)/vlan.sock \
	           $(SOCK_DIR)/portsec.sock $(SOCK_DIR)/storm.sock \
	           $(SOCK_DIR)/igmp.sock $(SOCK_DIR)/arp.sock \
	           $(SOCK_DIR)/lacp.sock; do \
	  if [ -S "$$s" ]; then \
	    printf "  %-30s  " "$$s"; \
	    echo '{"cmd":"ping"}' | nc -U "$$s" -w1 2>/dev/null || echo "no response"; \
	  else \
	    echo "  $$s  (absent)"; \
	  fi; \
	  echo ""; \
	done
	@echo ""
	@echo "=== IP/VRF/EVPN/VXLAN sockets (SOCK_DIR=$(SOCK_DIR)) ==="
	@for s in $(SOCK_DIR)/ip.sock $(SOCK_DIR)/vrf.sock \
	           $(SOCK_DIR)/evpn.sock $(SOCK_DIR)/vxlan.sock; do \
	  if [ -S "$$s" ]; then \
	    printf "  %-30s  " "$$s"; \
	    echo '{"cmd":"ping"}' | nc -U "$$s" -w1 2>/dev/null || echo "no response"; \
	  else \
	    echo "  $$s  (absent)"; \
	  fi; \
	  echo ""; \
	done

# ================================================================
# Smoke tests (delegates to sub-make targets if they exist,
# otherwise runs a quick ping check)
# ================================================================

test-l3: run-l3
	@echo "=== L3 smoke test ==="
	@sleep 0.2
	@echo '{"cmd":"ping"}' | nc -U /tmp/ribd.sock -w1
	@echo '{"cmd":"add","prefix":"10.0.0.0/8","nexthop":"192.168.1.1","iface":"eth0","source":"static"}' \
	  | nc -U /tmp/ribd.sock -w1
	@echo '{"cmd":"lookup","addr":"10.1.2.3"}' | nc -U /tmp/fibd.sock -w1
	@echo '{"cmd":"stats"}' | nc -U /tmp/fibd.sock -w1
	@pkill -x fibd 2>/dev/null; echo "=== L3 test done ==="

test-l2: run-l2
	@echo "=== L2 smoke test ==="
	@sleep 0.2
	@for s in /tmp/fdb.sock /tmp/rib.sock /tmp/stp.sock \
	           /tmp/vlan.sock /tmp/portsec.sock /tmp/storm.sock \
	           /tmp/igmp.sock /tmp/arp.sock /tmp/lacp.sock; do \
	  printf "  %-24s  " "$$s"; \
	  echo '{"cmd":"ping"}' | nc -U "$$s" -w1 2>/dev/null || echo "FAILED"; \
	done
	@pkill -x l2d 2>/dev/null; echo "=== L2 test done ==="

test: test-l3 test-l2
