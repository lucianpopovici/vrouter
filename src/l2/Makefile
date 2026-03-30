ROOTDIR := ../..
include $(ROOTDIR)/common.mk

MODULE  := l2
TARGET  := $(BUILDDIR)/bin/l2d
SRCS    := $(wildcard src/*.c)
OBJDIR  := $(BUILDDIR)/obj/$(MODULE)
OBJS    := $(patsubst src/%.c,$(OBJDIR)/%.o,$(SRCS))

CFLAGS  += -I./include
# l2 has some unused-function warnings for stub implementations
CFLAGS  += -Wno-unused-function

.PHONY: all clean

all: $(TARGET)

$(OBJDIR)/%.o: src/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET): $(OBJS) $(LDLIBS) | $(BUILDDIR)/bin
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

$(OBJDIR) $(BUILDDIR)/bin:
	mkdir -p $@

clean:
	rm -f $(OBJS) $(TARGET)
