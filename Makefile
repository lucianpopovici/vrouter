# ================================================================
# Top-level Makefile — Network Stack (L2 + L3)
# ================================================================
#
# Targets:
#   make            build everything (l3 + l2)
#   make l3         build L3 only  (fibd)
#   make l2         build L2 only  (l2d)
#   make clean      clean both
#   make install    install binaries to $(PREFIX)/bin
#   make run-l3     start the L3 daemon (background)
#   make run-l2     start the L2 daemon (background, RSTP mode)
#   make run        start both daemons
#   make stop       kill both daemons
#   make status     show daemon socket status
#
# Variables:
#   MODE=rstp         STP mode for l2d (stp | rstp | mst)
#   SOCK_DIR=/tmp     Directory for all Unix sockets
#   PREFIX=/usr/local install prefix

.PHONY: all l3 l2 clean install \
        run-l3 run-l2 run stop status \
        test-l3 test-l2 test

MODE     ?= rstp
SOCK_DIR ?= /tmp
PREFIX   ?= /usr/local

# ── sub-directories ──────────────────────────────────────────── #
L3_DIR := l3
L2_DIR := l2

L3_BIN := $(L3_DIR)/fibd
L2_BIN := $(L2_DIR)/l2d

# ================================================================
# Build targets
# ================================================================

all: l3 l2
	@echo ""
	@echo "══════════════════════════════════════════"
	@echo "  Build complete"
	@echo "  L3  →  $(L3_BIN)"
	@echo "  L2  →  $(L2_BIN)"
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

# ================================================================
# Clean
# ================================================================

clean:
	@echo "[l3] cleaning..."
	$(MAKE) -C $(L3_DIR) clean
	@echo "[l2] cleaning..."
	$(MAKE) -C $(L2_DIR) clean
	@echo "clean done"

# ================================================================
# Install
# ================================================================

install: all
	install -d $(PREFIX)/bin
	install -m 755 $(L3_BIN) $(PREFIX)/bin/fibd
	install -m 755 $(L2_BIN) $(PREFIX)/bin/l2d
	@echo "installed fibd and l2d to $(PREFIX)/bin"

# ================================================================
# Run / Stop / Status
# ================================================================

run-l3: l3
	@echo "[l3] starting fibd (sock_dir=$(SOCK_DIR))..."
	@$(L3_BIN) -S $(SOCK_DIR) &
	@sleep 0.3
	@echo "[l3] fibd running ($(SOCK_DIR)/fibd.sock  $(SOCK_DIR)/ribd.sock)"

run-l2: l2
	@echo "[l2] starting l2d (mode=$(MODE) sock_dir=$(SOCK_DIR))..."
	@$(L2_BIN) -m $(MODE) -S $(SOCK_DIR) &
	@sleep 0.3
	@echo "[l2] l2d running (9 sockets under $(SOCK_DIR)/)"

run: run-l3 run-l2
	@echo ""
	@echo "Both daemons started. Run 'make status' to verify."

stop:
	@echo "Stopping daemons..."
	@pkill -x fibd 2>/dev/null && echo "  fibd stopped" || echo "  fibd was not running"
	@pkill -x l2d  2>/dev/null && echo "  l2d  stopped" || echo "  l2d  was not running"

status:
	@echo "=== Daemon processes ==="
	@pgrep -a fibd 2>/dev/null || echo "  fibd: not running"
	@pgrep -a l2d  2>/dev/null || echo "  l2d:  not running"
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
