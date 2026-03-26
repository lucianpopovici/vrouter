CC      = gcc
CFLAGS  = -Wall -Wextra -Wpedantic -std=c99 -O2 -D_POSIX_C_SOURCE=200809L
LDFLAGS = -pthread

TARGET  = fibd
SRCS    = main.c fib.c fib_cli.c fib_ipc.c rib.c rib_ipc.c
OBJS    = $(SRCS:.c=.o)

.PHONY: all clean test

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

# Quick smoke-test: start daemon, run a few commands, stop
test: $(TARGET)
	@echo "=== FIB smoke test ==="
	./$(TARGET) &
	@sleep 0.3
	@echo '{"cmd":"ping"}'                                              | nc -U /tmp/fibd.sock
	@echo '{"cmd":"add","prefix":"10.0.0.0/8","nexthop":"192.168.1.1","iface":"eth0"}' | nc -U /tmp/fibd.sock
	@echo '{"cmd":"add","prefix":"10.1.2.0/24","nexthop":"192.168.1.2","iface":"eth1","metric":"5"}' | nc -U /tmp/fibd.sock
	@echo '{"cmd":"lookup","addr":"10.1.2.5"}'                         | nc -U /tmp/fibd.sock
	@echo '{"cmd":"lookup","addr":"10.99.0.1"}'                        | nc -U /tmp/fibd.sock
	@echo '{"cmd":"show"}'                                              | nc -U /tmp/fibd.sock
	@echo '{"cmd":"stats"}'                                             | nc -U /tmp/fibd.sock
	@echo '{"cmd":"set","key":"MAX_ROUTES","value":"2000"}'            | nc -U /tmp/fibd.sock
	@echo '{"cmd":"del","prefix":"10.0.0.0/8"}'                        | nc -U /tmp/fibd.sock
	@echo '{"cmd":"show"}'                                              | nc -U /tmp/fibd.sock
	@kill $$(cat /tmp/fibd.pid 2>/dev/null || pgrep fibd) 2>/dev/null || true
	@echo "=== done ==="

clean:
	rm -f $(OBJS) $(TARGET) schema.json runtime_config.json
