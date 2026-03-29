CC      ?= gcc
CFLAGS  := -std=c11 -Wall -Wextra -Werror -pthread -I./include -O2
LDFLAGS := -pthread

SRC     := src/vxlan.c src/vxlan_ipc.c
OBJ     := $(SRC:.c=.o)
DAEMON  := vxlan_daemon
TEST    := test_vxlan

.PHONY: all daemon test run_test clean

all: daemon test

daemon: $(OBJ) src/vxlan_daemon.o
	$(CC) $(LDFLAGS) -o $(DAEMON) $^

test: $(OBJ) tests/test_vxlan.o
	$(CC) $(LDFLAGS) -o $(TEST) $^

run_test: test
	./$(TEST)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) src/vxlan_daemon.o tests/test_vxlan.o \
	      $(DAEMON) $(TEST) \
	      vxlan_runtime.json /tmp/vxlan_test.json
