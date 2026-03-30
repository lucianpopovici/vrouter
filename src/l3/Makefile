ROOTDIR := ../..
include $(ROOTDIR)/common.mk

MODULE  := l3
TARGET  := $(BUILDDIR)/bin/fibd
SRCS    := $(wildcard src/*.c)
OBJDIR  := $(BUILDDIR)/obj/$(MODULE)
OBJS    := $(patsubst src/%.c,$(OBJDIR)/%.o,$(SRCS))

CFLAGS  += -I./include

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
