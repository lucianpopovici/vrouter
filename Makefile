# ================================================================
# Root Makefile — vrouter network stack
# ================================================================
#
# Targets:
#   make              build everything (lib + daemons + tests)
#   make lib          build shared library only
#   make daemons      build all daemon binaries
#   make tests        build C unit test binaries
#   make dist         copy Python + config into build/
#   make clean        clean all build output
#   make install      install binaries to $(DESTDIR)/usr/sbin
#   make run          start all daemons
#   make stop         kill all daemons
#   make test-c       run C unit tests
#   make test-py      run Python unit tests (pytest)
#   make test-integration run shell integration tests
#   make test-all     run all tests
#
# Variables:
#   MODE=debug   build with ASan + UBSan + debug symbols

.PHONY: all lib daemons tests dist clean install \
        run stop status \
        test-c test-py test-integration test-all

MODULES  := l3 l2 ip vrf evpn vxlan
BUILDDIR := build

all: lib daemons tests dist
	@echo "Build complete. Outputs in $(BUILDDIR)/"

lib:
	$(MAKE) -C lib

daemons: lib
	@for m in $(MODULES); do $(MAKE) -C src/$$m || exit 1; done

tests: daemons
	$(MAKE) -C tests/unit
	$(MAKE) -C tests/bench

# Copy Python + config into build/ for a self-contained distribution
dist: daemons
	@mkdir -p $(BUILDDIR)/python $(BUILDDIR)/config
	@cp -a python/* $(BUILDDIR)/python/
	@cp -a config/* $(BUILDDIR)/config/

clean:
	$(MAKE) -C lib clean
	@for m in $(MODULES); do $(MAKE) -C src/$$m clean; done
	$(MAKE) -C tests/unit clean
	$(MAKE) -C tests/bench clean
	rm -rf $(BUILDDIR)

install: all
	install -d $(DESTDIR)/usr/sbin
	install -m 755 $(BUILDDIR)/bin/* $(DESTDIR)/usr/sbin/

# ── Run / Stop / Status ──────────────────────────────────────────
SOCK_DIR ?= /tmp/vrouter

run: all
	@mkdir -p $(SOCK_DIR)
	@$(BUILDDIR)/bin/fibd      -S $(SOCK_DIR) &
	@$(BUILDDIR)/bin/l2d       -m rstp -S $(SOCK_DIR) &
	@$(BUILDDIR)/bin/ip_daemon -S $(SOCK_DIR) &
	@$(BUILDDIR)/bin/vrf_daemon -S $(SOCK_DIR) &
	@$(BUILDDIR)/bin/evpn_daemon -S $(SOCK_DIR) &
	@$(BUILDDIR)/bin/vxlan_daemon -S $(SOCK_DIR) &
	@echo "All daemons started (sockets in $(SOCK_DIR))"

stop:
	@for bin in fibd l2d ip_daemon vrf_daemon evpn_daemon vxlan_daemon; do \
	    pkill -x $$bin 2>/dev/null && echo "stopped $$bin" || true; \
	done

status:
	@ls -1 $(SOCK_DIR)/*.sock 2>/dev/null || echo "No sockets found in $(SOCK_DIR)"

# ── Test targets ─────────────────────────────────────────────────
test-c: tests
	@for t in $(BUILDDIR)/tests/test_*; do \
	    [ -x "$$t" ] || continue; \
	    echo "=== $$t ==="; $$t || exit 1; \
	done

test-py:
	cd tests && python -m pytest python/ -v

test-integration: all
	bash tests/integration/test_l3.sh
	bash tests/integration/test_l2.sh
	bash tests/integration/test_persist.sh

test-all: test-c test-py test-integration
