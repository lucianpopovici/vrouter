CC      = gcc
CFLAGS  = -Wall -Wextra -std=c99 -O2 -D_POSIX_C_SOURCE=200809L \
          -Wno-unused-function
LDFLAGS = -pthread

TARGET  = l2d
SRCS    = main_l2.c fdb.c l2rib.c stp.c fdb_ipc.c l2rib_ipc.c stp_ipc.c l2_cli.c \
          vlan.c portsec.c storm.c igmp.c arpsnoop.c lacp.c l2_ipc_extra.c l2_persist.c
OBJS    = $(SRCS:.c=.o)

.PHONY: all clean test

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

test: $(TARGET)
	@echo "=== L2 smoke test ==="
	./$(TARGET) -m rstp &
	@sleep 0.4
	@echo "--- STP ping ---"
	@echo '{"cmd":"ping"}' | nc -U $(STP_SOCK)
	@echo "--- STP: port up ---"
	@echo '{"cmd":"port_up","port":"eth0"}' | nc -U $(STP_SOCK)
	@echo '{"cmd":"port_up","port":"eth1"}' | nc -U $(STP_SOCK)
	@echo "--- STP: inject inferior BPDU (we stay root) ---"
	@echo '{"cmd":"bpdu","port":"eth0","root":"8000.aabbcc000001","bridge":"9000.aabbcc000002","cost":"4","flags":"4"}' | nc -U $(STP_SOCK)
	@echo "--- STP: show topology ---"
	@echo '{"cmd":"show"}' | nc -U $(STP_SOCK)
	@echo "--- L2RIB: add static + dynamic for same MAC ---"
	@echo '{"cmd":"add","mac":"de:ad:be:ef:00:01","vlan":"10","port":"eth0","source":"static"}' | nc -U $(L2RIB_SOCK)
	@echo '{"cmd":"add","mac":"de:ad:be:ef:00:01","vlan":"10","port":"eth1","source":"dynamic"}' | nc -U $(L2RIB_SOCK)
	@echo '{"cmd":"show"}' | nc -U $(L2RIB_SOCK)
	@echo "--- FDB: lookup (static should win) ---"
	@echo '{"cmd":"lookup","mac":"de:ad:be:ef:00:01","vlan":"10"}' | nc -U $(FDB_SOCK)
	@echo "--- FDB: direct learn + stats ---"
	@echo '{"cmd":"learn","mac":"ca:fe:00:00:00:01","vlan":"20","port":"eth2","flags":"dynamic"}' | nc -U $(FDB_SOCK)
	@echo '{"cmd":"stats"}' | nc -U $(FDB_SOCK)
	@kill $$(pgrep l2d) 2>/dev/null || true
	@echo "=== done ==="

STP_SOCK   = /tmp/stp.sock
L2RIB_SOCK = /tmp/rib.sock
FDB_SOCK   = /tmp/fdb.sock

clean:
	rm -f $(OBJS) $(TARGET)
