ROOTDIR ?= ..
include $(ROOTDIR)/common.mk

SRCS := src/json.c src/net_parse.c src/ipc_server.c
OBJS := $(patsubst src/%.c,$(BUILDDIR)/obj/lib/%.o,$(SRCS))
LIB  := $(BUILDDIR)/lib/libvrouter.a

.PHONY: all clean

all: $(LIB)

$(BUILDDIR)/obj/lib/%.o: src/%.c | $(BUILDDIR)/obj/lib
	$(CC) $(CFLAGS) -I include -c $< -o $@

$(LIB): $(OBJS) | $(BUILDDIR)/lib
	$(AR) rcs $@ $^

$(BUILDDIR)/obj/lib $(BUILDDIR)/lib:
	mkdir -p $@

clean:
	rm -f $(OBJS) $(LIB)
