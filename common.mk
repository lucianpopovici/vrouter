# common.mk — included by all module Makefiles
# Set ROOTDIR before including this file (e.g., ROOTDIR := ../..)

CC      ?= gcc
AR      ?= ar
CSTD    := -std=c11
CWARN   := -Wall -Wextra -Wpedantic -Werror
COPT    ?= -O2
CFLAGS  := $(CSTD) $(CWARN) $(COPT) -pthread -D_POSIX_C_SOURCE=200809L

LDFLAGS := -pthread

BUILDDIR := $(ROOTDIR)/build
LIBDIR   := $(ROOTDIR)/lib

# Shared library include path and link target
CFLAGS  += -I$(LIBDIR)/include
LDLIBS  := $(BUILDDIR)/lib/libvrouter.a

ifeq ($(MODE),debug)
  COPT    :=
  CFLAGS  += -g -O0 -fsanitize=address,undefined -fno-omit-frame-pointer
  LDFLAGS += -fsanitize=address,undefined
endif
