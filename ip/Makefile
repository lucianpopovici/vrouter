CC       ?= gcc
CFLAGS   := -std=c11 -Wall -Wextra -Werror -pthread \
            -I./include $(EXTRA_CFLAGS)
LDFLAGS  := -pthread

SOCK_DIR ?= /var/run/vrouter
MODE     ?= release

ifeq ($(MODE),debug)
  CFLAGS  += -g -O0 -fsanitize=address,undefined
  LDFLAGS += -fsanitize=address,undefined
else
  CFLAGS  += -O2
endif

SRC      := src/vrf.c src/vrf_ipc.c
DAEMON   := src/vrf_daemon.c
TEST_SRC := tests/test_vrf.c

OBJ      := $(SRC:.c=.o)
TARGET   := vrf_daemon
TEST_BIN := test_vrf

.PHONY: all daemon test run_test stress clean install

all: daemon test

$(OBJ): %.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

src/vrf_daemon.o: $(DAEMON)
	$(CC) $(CFLAGS) -c $< -o $@

daemon: $(OBJ) src/vrf_daemon.o
	$(CC) $(LDFLAGS) -o $(TARGET) $^

tests/test_vrf.o: $(TEST_SRC)
	$(CC) $(CFLAGS) -c $< -o $@

test: $(OBJ) tests/test_vrf.o
	$(CC) $(LDFLAGS) -o $(TEST_BIN) $(OBJ) tests/test_vrf.o

run_test: test
	./$(TEST_BIN)

stress: EXTRA_CFLAGS=-DSTRESS_THREADS=16 -DSTRESS_OPS=20000
stress: test
	./$(TEST_BIN)

install: daemon
	install -d $(DESTDIR)/usr/sbin
	install -m 755 $(TARGET) $(DESTDIR)/usr/sbin/

clean:
	rm -f $(OBJ) src/vrf_daemon.o tests/test_vrf.o \
	      $(TARGET) $(TEST_BIN) \
	      vrf_schema.json vrf_runtime_config.json \
	      /tmp/vrf_test_config.json
