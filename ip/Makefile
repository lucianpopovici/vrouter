CC       ?= gcc
CFLAGS   := -std=c11 -Wall -Wextra -Werror -pthread \
            -I./include $(EXTRA_CFLAGS)
LDFLAGS  := -pthread

SOCK_DIR ?= /var/run/vrouter
MODE     ?= release

ifeq ($(MODE),debug)
  CFLAGS += -g -O0 -fsanitize=address,undefined
  LDFLAGS += -fsanitize=address,undefined
else
  CFLAGS += -O2
endif

SRC      := src/ip.c src/ip_ipc.c
DAEMON   := src/ip_daemon.c
TEST_SRC := tests/test_ip.c

OBJ      := $(SRC:.c=.o)
TARGET   := ip_daemon
TEST_BIN := test_ip

.PHONY: all daemon test clean install

all: daemon test

$(OBJ): %.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

src/ip_daemon.o: src/ip_daemon.c
	$(CC) $(CFLAGS) -c $< -o $@

daemon: $(OBJ) src/ip_daemon.o
	$(CC) $(LDFLAGS) -o $(TARGET) $^

test: $(OBJ) tests/test_ip.o
	$(CC) $(CFLAGS) -c $(TEST_SRC) -o tests/test_ip.o
	$(CC) $(LDFLAGS) -o $(TEST_BIN) $(OBJ) tests/test_ip.o

tests/test_ip.o: $(TEST_SRC)
	$(CC) $(CFLAGS) -c $< -o $@

run_test: test
	./$(TEST_BIN)

stress: EXTRA_CFLAGS=-DSTRESS_THREADS=16 -DSTRESS_OPS=50000
stress: test
	./$(TEST_BIN)

install: daemon
	install -d $(DESTDIR)/usr/sbin
	install -m 755 $(TARGET) $(DESTDIR)/usr/sbin/

clean:
	rm -f $(OBJ) src/ip_daemon.o tests/test_ip.o $(TARGET) $(TEST_BIN) \
	      ip_schema.json ip_runtime_config.json /tmp/ip_test_config.json
