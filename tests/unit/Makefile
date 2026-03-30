ROOTDIR := ../..
include $(ROOTDIR)/common.mk

TESTS   := test_ip test_vrf test_evpn test_vxlan
OUTDIR  := $(BUILDDIR)/tests
OBJDIR  := $(BUILDDIR)/obj/tests

MODULES_SRCS_ALL = \
    $(wildcard $(ROOTDIR)/src/ip/src/*.c)   \
    $(wildcard $(ROOTDIR)/src/vrf/src/*.c)  \
    $(wildcard $(ROOTDIR)/src/evpn/src/*.c) \
    $(wildcard $(ROOTDIR)/src/vxlan/src/*.c)

# Exclude main.c from module sources when building tests
MODULES_SRCS = $(filter-out %/main.c,$(MODULES_SRCS_ALL))

MODULES_OBJS = $(patsubst $(ROOTDIR)/src/%.c,$(OBJDIR)/mod/%.o,$(MODULES_SRCS))

IP_OBJS   := $(filter $(OBJDIR)/mod/ip/%,$(MODULES_OBJS))
VRF_OBJS  := $(filter $(OBJDIR)/mod/vrf/%,$(MODULES_OBJS))
EVPN_OBJS := $(filter $(OBJDIR)/mod/evpn/%,$(MODULES_OBJS))
VXLAN_OBJS := $(filter $(OBJDIR)/mod/vxlan/%,$(MODULES_OBJS))

.PHONY: all clean

all: $(addprefix $(OUTDIR)/,$(TESTS))

$(OUTDIR)/test_ip: test_ip.c $(IP_OBJS) | $(OUTDIR)
	$(CC) $(CFLAGS) -I$(ROOTDIR)/src/ip/include \
	    $< $(IP_OBJS) \
	    $(LDLIBS) $(LDFLAGS) -o $@

$(OUTDIR)/test_vrf: test_vrf.c $(VRF_OBJS) | $(OUTDIR)
	$(CC) $(CFLAGS) -I$(ROOTDIR)/src/vrf/include \
	    $< $(VRF_OBJS) \
	    $(LDLIBS) $(LDFLAGS) -o $@

$(OUTDIR)/test_evpn: test_evpn.c $(EVPN_OBJS) | $(OUTDIR)
	$(CC) $(CFLAGS) -I$(ROOTDIR)/src/evpn/include \
	    $< $(EVPN_OBJS) \
	    $(LDLIBS) $(LDFLAGS) -o $@

$(OUTDIR)/test_vxlan: test_vxlan.c $(VXLAN_OBJS) | $(OUTDIR)
	$(CC) $(CFLAGS) -I$(ROOTDIR)/src/vxlan/include \
	    $< $(VXLAN_OBJS) \
	    $(LDLIBS) $(LDFLAGS) -o $@

# Build module objects
$(OBJDIR)/mod/ip/src/%.o: $(ROOTDIR)/src/ip/src/%.c | $(OBJDIR)/mod/ip/src
	$(CC) $(CFLAGS) -I$(ROOTDIR)/src/ip/include -c $< -o $@

$(OBJDIR)/mod/vrf/src/%.o: $(ROOTDIR)/src/vrf/src/%.c | $(OBJDIR)/mod/vrf/src
	$(CC) $(CFLAGS) -I$(ROOTDIR)/src/vrf/include -c $< -o $@

$(OBJDIR)/mod/evpn/src/%.o: $(ROOTDIR)/src/evpn/src/%.c | $(OBJDIR)/mod/evpn/src
	$(CC) $(CFLAGS) -I$(ROOTDIR)/src/evpn/include -c $< -o $@

$(OBJDIR)/mod/vxlan/src/%.o: $(ROOTDIR)/src/vxlan/src/%.c | $(OBJDIR)/mod/vxlan/src
	$(CC) $(CFLAGS) -I$(ROOTDIR)/src/vxlan/include -c $< -o $@

$(OUTDIR) $(OBJDIR)/mod/ip/src $(OBJDIR)/mod/vrf/src $(OBJDIR)/mod/evpn/src $(OBJDIR)/mod/vxlan/src:
	mkdir -p $@

clean:
	rm -f $(addprefix $(OUTDIR)/,$(TESTS))
	rm -rf $(OBJDIR)/mod
