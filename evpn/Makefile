CC      = gcc
CFLAGS  = -std=c11 -Wall -Wextra -Werror -pthread -I./include -O2
LDFLAGS = -pthread

SRC     = src/evpn.c src/evpn_ipc.c
OBJ     = $(SRC:.c=.o)
DAEMON  = evpn_daemon
TEST    = test_evpn

.PHONY: all daemon test run_test clean

all: daemon test

daemon: $(OBJ) src/evpn_daemon.o
	$(CC) $(LDFLAGS) -o $(DAEMON) $(OBJ) src/evpn_daemon.o

test: $(OBJ) tests/test_evpn.o
	$(CC) $(LDFLAGS) -o $(TEST) $(OBJ) tests/test_evpn.o

run_test: test
	./$(TEST)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) src/evpn_daemon.o tests/test_evpn.o $(DAEMON) $(TEST)
	rm -f evpn_runtime_config.json evpn_schema.json /tmp/evpn_test_config.json
