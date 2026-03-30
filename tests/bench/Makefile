ROOTDIR := ../..
include $(ROOTDIR)/common.mk

TARGET  := $(BUILDDIR)/tests/bench_thread
OBJDIR  := $(BUILDDIR)/obj/tests/bench

# Only the modules bench_thread.c actually calls
OBJS := \
    $(OBJDIR)/fib.o \
    $(OBJDIR)/fdb.o

.PHONY: all clean

all: $(TARGET)

$(TARGET): bench_thread.c $(OBJS) | $(BUILDDIR)/tests
	$(CC) $(CFLAGS) \
	    -I$(ROOTDIR)/src/l3/include \
	    -I$(ROOTDIR)/src/l2/include \
	    $< $(OBJS) $(LDLIBS) $(LDFLAGS) -o $@

$(OBJDIR)/fib.o: $(ROOTDIR)/src/l3/src/fib.c | $(OBJDIR)
	$(CC) $(CFLAGS) -I$(ROOTDIR)/src/l3/include -c $< -o $@

$(OBJDIR)/fdb.o: $(ROOTDIR)/src/l2/src/fdb.c | $(OBJDIR)
	$(CC) $(CFLAGS) -I$(ROOTDIR)/src/l2/include -c $< -o $@

$(BUILDDIR)/tests $(OBJDIR):
	mkdir -p $@

clean:
	rm -f $(TARGET)
	rm -rf $(OBJDIR)
