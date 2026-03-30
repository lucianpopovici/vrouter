# vrouter — Full C Codebase Refactoring

## Goals

1. Uniform directory structure for every C module
2. Shared library (`libvrouter.a`) for all duplicated code
3. All tests (C unit, Python, shell integration) in one place
4. Unified build system — single root `make` produces `build/` with everything needed to run
5. Consistent C standard, compiler flags, and conventions across all modules

---

## Current problems

### Inconsistent module layouts
- `l3/` and `l2/` have flat files (`fib.c`, `fib.h`, `main.c`, all in one dir)
- `ip/`, `vrf/`, `evpn/`, `vxlan/` use `src/`, `include/`, `tests/` subdirs
- Each module has its own Makefile with duplicated boilerplate

### Massive code duplication
- **FNV-1a hash** — 8 separate copies across `l3/rib.c`, `l3/fib.c`, `l2/fdb.c`, `l2/l2rib.c`, `l2/arpsnoop.c`, `ip/src/ip.c`, `vrf/src/vrf.c`, `vxlan/src/vxlan.c`, `evpn/src/evpn.c`
- **JSON parser** — 10 copies of `jget()` / `jstr()` across all IPC and persist files
- **Address/prefix/MAC parsers** — near-identical `addr_parse`, `prefix_parse`, `mac_parse`, `prefix_contains` reimplemented per module (`ip.c`, `vrf.c`, `vxlan.c`, `evpn.c`)
- **IPC server loop** — the same `socket → bind → listen → select → accept → recv → handle → send → close` loop is copy-pasted 7+ times
- **Pool allocator** — same bump-allocator pattern in `fib.c`, `rib.c`, `fdb.c`, etc.

### Build inconsistencies
- `l3/` and `l2/` use `-std=c99`, everything else uses `-std=c11`
- Some Makefiles have `-Werror`, some don't
- Some have `MODE=debug` with sanitizer support, some don't
- Build artifacts (`.o`, binaries) land in source directories
- A compiled binary `vrf/vrf_daemon` is committed to git

### Scattered files
- Schema JSON files dumped in repo root (`schema.json`, `bfd_schema.json`, etc.)
- Runtime config files in repo root (`ip_runtime_config.json`, etc.)
- Tests split between `tests/` (Python + shell + bench_thread.c), and per-module `tests/` dirs (C unit tests)
- `.gitignore` only covers `l2/l2d` and `l3/fibd`, not `ip_daemon`, `vrf_daemon`, `evpn_daemon`, `vxlan_daemon`

---

## Target directory structure

```
vrouter/
├── Makefile                          # Root Makefile: orchestrates everything
├── common.mk                        # Shared variables, flags, pattern rules
│
├── lib/                              # Shared C library → build/lib/libvrouter.a
│   ├── include/vrouter/
│   │   ├── hash.h                    # FNV-1a: fnv1a(), fnv1a_addr(), fnv1a_prefix()
│   │   ├── json.h                    # jget(), jstr(), jint(), jbool()
│   │   ├── ipc_server.h             # ipc_server_t, ipc_serve(), ipc_stop()
│   │   ├── net_types.h              # vr_addr_t, vr_prefix_t, vr_mac_t (unified types)
│   │   ├── net_parse.h              # vr_addr_parse(), vr_prefix_parse(), vr_mac_parse(), vr_prefix_contains()
│   │   └── pool.h                    # Generic slab pool with free-list (macros or inline)
│   ├── src/
│   │   ├── hash.c
│   │   ├── json.c
│   │   ├── ipc_server.c
│   │   └── net_parse.c
│   └── Makefile                      # Builds build/lib/libvrouter.a
│
├── src/                              # All C daemon modules
│   ├── l2/
│   │   ├── include/                  # l2-specific headers
│   │   │   ├── fdb.h
│   │   │   ├── stp.h
│   │   │   ├── vlan.h
│   │   │   ├── lacp.h
│   │   │   ├── portsec.h
│   │   │   ├── storm.h
│   │   │   ├── igmp.h
│   │   │   ├── arpsnoop.h
│   │   │   ├── l2rib.h
│   │   │   ├── l2_cli.h
│   │   │   ├── l2_persist.h
│   │   │   └── rw_lock.h
│   │   ├── src/
│   │   │   ├── main.c               # (renamed from main_l2.c)
│   │   │   ├── fdb.c
│   │   │   ├── fdb_ipc.c
│   │   │   ├── stp.c
│   │   │   ├── stp_ipc.c
│   │   │   ├── vlan.c
│   │   │   ├── lacp.c
│   │   │   ├── portsec.c
│   │   │   ├── storm.c
│   │   │   ├── igmp.c
│   │   │   ├── arpsnoop.c
│   │   │   ├── l2rib.c
│   │   │   ├── l2rib_ipc.c
│   │   │   ├── l2_cli.c
│   │   │   ├── l2_ipc_extra.c
│   │   │   └── l2_persist.c
│   │   └── Makefile                  # Daemon: build/bin/l2d
│   │
│   ├── l3/
│   │   ├── include/
│   │   │   ├── fib.h
│   │   │   ├── rib.h
│   │   │   ├── fib_cli.h
│   │   │   ├── fib_ipc.h
│   │   │   ├── rib_ipc.h
│   │   │   └── persist.h
│   │   ├── src/
│   │   │   ├── main.c
│   │   │   ├── fib.c
│   │   │   ├── fib_cli.c
│   │   │   ├── fib_ipc.c
│   │   │   ├── rib.c
│   │   │   ├── rib_ipc.c
│   │   │   └── persist.c
│   │   └── Makefile                  # Daemon: build/bin/fibd
│   │
│   ├── ip/
│   │   ├── include/
│   │   │   ├── ip.h
│   │   │   └── ip_ipc.h
│   │   ├── src/
│   │   │   ├── main.c               # (renamed from ip_daemon.c)
│   │   │   ├── ip.c
│   │   │   └── ip_ipc.c
│   │   └── Makefile                  # Daemon: build/bin/ip_daemon
│   │
│   ├── vrf/
│   │   ├── include/
│   │   │   ├── vrf.h
│   │   │   └── vrf_ipc.h
│   │   ├── src/
│   │   │   ├── main.c               # (renamed from vrf_daemon.c)
│   │   │   ├── vrf.c
│   │   │   └── vrf_ipc.c
│   │   └── Makefile                  # Daemon: build/bin/vrf_daemon
│   │
│   ├── evpn/
│   │   ├── include/
│   │   │   ├── evpn.h
│   │   │   └── evpn_ipc.h
│   │   ├── src/
│   │   │   ├── main.c               # (renamed from evpn_daemon.c)
│   │   │   ├── evpn.c
│   │   │   └── evpn_ipc.c
│   │   └── Makefile                  # Daemon: build/bin/evpn_daemon
│   │
│   └── vxlan/
│       ├── include/
│       │   ├── vxlan.h
│       │   └── vxlan_ipc.h
│       ├── src/
│       │   ├── main.c               # (renamed from vxlan_daemon.c)
│       │   ├── vxlan.c
│       │   └── vxlan_ipc.c
│       └── Makefile                  # Daemon: build/bin/vxlan_daemon
│
├── python/                           # All Python code
│   ├── bfd/                          # BFD package (moved from ./bfd/)
│   ├── lldp/                         # LLDP package (moved from ./lldp/)
│   ├── modules/                      # Orchestrator modules (moved from ./modules/)
│   ├── main.py                       # Control plane entry point
│   └── project-cli                   # CLI tool
│
├── tests/
│   ├── unit/                         # All C unit tests
│   │   ├── test_ip.c                 # moved from ip/tests/test_ip.c
│   │   ├── test_vrf.c                # moved from vrf/tests/test_vrf.c
│   │   ├── test_evpn.c              # moved from evpn/tests/test_evpn.c
│   │   ├── test_vxlan.c             # moved from vxlan/tests/test_vxlan.c
│   │   └── Makefile                  # Builds all test binaries into build/tests/
│   ├── integration/                  # Shell-based functional tests
│   │   ├── test_l2.sh
│   │   ├── test_l3.sh
│   │   └── test_persist.sh
│   ├── python/                       # Python unit tests
│   │   ├── conftest.py               # shared fixtures
│   │   ├── test_bfd_config.py
│   │   ├── test_bfd_config_manager.py
│   │   ├── test_bfd_packet.py
│   │   ├── test_bfd_session.py
│   │   ├── test_bfd_session_manager.py
│   │   └── test_modules_base.py
│   ├── bench/
│   │   ├── bench_thread.c
│   │   └── Makefile
│   └── pytest.ini                    # moved from root
│
├── config/                           # Schema + default configs
│   ├── schema.json
│   ├── bfd_schema.json
│   ├── l2d_schema.json
│   ├── ip_schema.json
│   ├── vrf_schema.json
│   ├── evpn_schema.json
│   ├── vxlan_schema.json
│   ├── ip_runtime_config.json
│   ├── vrf_runtime_config.json
│   ├── evpn_runtime_config.json
│   ├── vxlan_runtime.json
│   ├── vrouter_routes.json
│   ├── vrouter_l2.json
│   ├── project_config.json
│   └── interfaces.txt
│
├── build/                            # ALL build output (gitignored)
│   ├── bin/                          # Daemon binaries
│   │   ├── fibd
│   │   ├── l2d
│   │   ├── ip_daemon
│   │   ├── vrf_daemon
│   │   ├── evpn_daemon
│   │   └── vxlan_daemon
│   ├── lib/
│   │   └── libvrouter.a
│   ├── tests/                        # Test binaries
│   │   ├── test_ip
│   │   ├── test_vrf
│   │   ├── test_evpn
│   │   └── test_vxlan
│   ├── obj/                          # All .o files (mirrored source tree)
│   │   ├── lib/
│   │   ├── l2/
│   │   ├── l3/
│   │   ├── ip/
│   │   ├── vrf/
│   │   ├── evpn/
│   │   └── vxlan/
│   ├── python/                       # Copied/symlinked Python tree
│   │   ├── bfd/
│   │   ├── lldp/
│   │   ├── modules/
│   │   ├── main.py
│   │   └── project-cli
│   └── config/                       # Copied config files
│       └── *.json
│
├── .github/workflows/ci.yml
├── .gitignore                        # Updated
├── LICENSE
└── README.md                         # Updated for new layout
```

---

## Detailed refactoring instructions

### Phase 1: Create the shared library (`lib/`)

This is the foundation — everything else depends on it.

#### 1.1 — `lib/include/vrouter/hash.h` + `lib/src/hash.c`

Extract the FNV-1a hash that is duplicated 8+ times. Create a single implementation:

```c
/* hash.h */
#ifndef VROUTER_HASH_H
#define VROUTER_HASH_H
#include <stdint.h>
#include <stddef.h>

#define VR_FNV_OFFSET 2166136261u
#define VR_FNV_PRIME  16777619u

/* Generic FNV-1a over arbitrary bytes. Returns raw hash (caller does % n). */
static inline uint32_t vr_fnv1a(const uint8_t *data, size_t len)
{
    uint32_t h = VR_FNV_OFFSET;
    for (size_t i = 0; i < len; i++) { h ^= data[i]; h *= VR_FNV_PRIME; }
    return h;
}

/* Convenience: hash and modulo a bucket count in one call. */
static inline uint32_t vr_fnv1a_mod(const uint8_t *data, size_t len, uint32_t n)
{
    return n ? vr_fnv1a(data, len) % n : 0;
}

#endif
```

Since it's all `static inline`, there's no `.c` file needed — it's header-only.

Each module currently has its own `fnv1a()` or inline hash. Replace them all with `#include <vrouter/hash.h>` and calls to `vr_fnv1a()` or `vr_fnv1a_mod()`. The module-specific typed wrappers (like `evpn_fnv1a_mac()`) can stay in their own module headers but should call `vr_fnv1a()` internally.

Affected files:
- `l3/fib.c` (inline `fib_hash`) → call `vr_fnv1a` on the 5 bytes
- `l3/rib.c` (inline `rib_hash`) → same
- `l2/fdb.c` (`fdb_hash`) → same
- `l2/l2rib.c` → same
- `l2/arpsnoop.c` → same
- `ip/src/ip.c` (`fnv1a`, `ip_fnv1a_addr`, `ip_fnv1a_prefix`, `flow_hash`) → inner loop → `vr_fnv1a`
- `vrf/src/vrf.c` → same pattern as ip
- `vxlan/src/vxlan.c` → same
- `evpn/src/evpn.c` → same

#### 1.2 — `lib/include/vrouter/json.h` + `lib/src/json.c`

Unify the two parser variants (`jget` from l3/l2 and `jstr`/`jint`/`jbool` from ip/vrf/evpn/vxlan) into a single API:

```c
/* json.h */
#ifndef VROUTER_JSON_H
#define VROUTER_JSON_H
#include <stddef.h>
#include <stdbool.h>

/* Extract string value for "key" from flat JSON. Returns 0 on success, -1 if key not found. */
int         vr_json_get_str(const char *json, const char *key, char *buf, size_t sz);

/* Extract integer value. Returns the value, or fallback if key not found. */
long        vr_json_get_int(const char *json, const char *key, long fallback);

/* Extract boolean value (looks for "key":true). */
bool        vr_json_get_bool(const char *json, const char *key);

#endif
```

The implementation in `json.c` merges the best of both `jget` (handles unquoted values) and `jstr` (returns pointer for chaining). Keep a single, well-tested parser.

Remove every `static int jget(...)` and `static const char *jstr(...)` from:
- `l3/rib_ipc.c`, `l3/fib_ipc.c`, `l3/persist.c`
- `l2/fdb_ipc.c`, `l2/l2rib_ipc.c`, `l2/stp_ipc.c`, `l2/l2_ipc_extra.c`, `l2/l2_persist.c`
- `ip/src/ip_ipc.c`, `ip/src/ip.c`
- `vrf/src/vrf.c`, `vrf/src/vrf_ipc.c`
- `vxlan/src/vxlan.c`, `vxlan/src/vxlan_ipc.c`
- `evpn/src/evpn_ipc.c`

Replace all call sites. The `jget(json, "key", buf, sz)` calls map directly to `vr_json_get_str()`. The `jint(json, "key")` calls map to `vr_json_get_int(json, "key", -1)`. The `jbool(json, "key")` calls map to `vr_json_get_bool()`.

#### 1.3 — `lib/include/vrouter/net_types.h` + `lib/include/vrouter/net_parse.h` + `lib/src/net_parse.c`

Unify the duplicated type definitions and parsers. Currently there are 4 independent copies:
- `ip_addr_t` / `ip_prefix_t` in `ip/include/ip.h`
- `vrf_addr_t` / `vrf_prefix_t` in `vrf/include/vrf.h`
- `evpn_addr_t` / `evpn_prefix_t` / `evpn_mac_t` in `evpn/include/evpn.h`
- `vxlan_addr_t` / `vxlan_mac_t` in `vxlan/include/vxlan.h`

They're all structurally identical (af + union of in_addr/in6_addr). Create common types:

```c
/* net_types.h */
#ifndef VROUTER_NET_TYPES_H
#define VROUTER_NET_TYPES_H

#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>

typedef struct vr_addr {
    sa_family_t af;
    union { struct in_addr v4; struct in6_addr v6; } u;
} vr_addr_t;

typedef struct vr_prefix {
    vr_addr_t addr;
    uint8_t   plen;
} vr_prefix_t;

typedef struct vr_mac {
    uint8_t b[6];
} vr_mac_t;

#endif
```

```c
/* net_parse.h */
int  vr_addr_parse(const char *str, vr_addr_t *out);
int  vr_prefix_parse(const char *str, vr_prefix_t *out);
int  vr_mac_parse(const char *str, vr_mac_t *out);
void vr_addr_to_str(const vr_addr_t *addr, char *buf, size_t len);
void vr_prefix_to_str(const vr_prefix_t *pfx, char *buf, size_t len);
void vr_mac_to_str(const vr_mac_t *mac, char *buf, size_t len);
bool vr_addr_eq(const vr_addr_t *a, const vr_addr_t *b);
bool vr_prefix_contains(const vr_prefix_t *pfx, const vr_addr_t *addr);
bool vr_is_martian_v4(const struct in_addr *addr);
bool vr_is_martian_v6(const struct in6_addr *addr);
```

Then in each module header, replace the local type with a typedef alias or use `vr_addr_t` directly:
```c
/* In ip.h: */
#include <vrouter/net_types.h>
typedef vr_addr_t   ip_addr_t;    /* backward compat */
typedef vr_prefix_t ip_prefix_t;
```

Or better: just replace all uses of `ip_addr_t` with `vr_addr_t` across the module. Same for vrf, evpn, vxlan.

Delete the per-module `*_addr_parse`, `*_prefix_parse`, `*_mac_parse`, `*_prefix_contains`, `*_addr_to_str`, `*_prefix_to_str`, `*_mac_to_str`, `*_addr_eq` functions from:
- `ip/src/ip.c` (lines ~133-200)
- `vrf/src/vrf.c` (lines ~92-140)
- `evpn/src/evpn.c` (lines ~80-145)
- `vxlan/src/vxlan.c` (lines ~69-110)

Replace call sites with `vr_*` equivalents.

#### 1.4 — `lib/include/vrouter/ipc_server.h` + `lib/src/ipc_server.c`

Extract the duplicated IPC accept loop. Create a generic server:

```c
/* ipc_server.h */
#ifndef VROUTER_IPC_SERVER_H
#define VROUTER_IPC_SERVER_H

#include <stddef.h>

/* Callback: given request buffer + length, write response into resp, return resp length. */
typedef int (*vr_ipc_handler_fn)(const char *req, size_t req_len,
                                  char *resp, size_t resp_cap,
                                  void *ctx);

typedef struct {
    int          fd;             /* listening socket */
    const char  *sock_path;
    volatile int running;
} vr_ipc_server_t;

/* Create + bind + listen. Returns 0 on success. */
int  vr_ipc_server_init(vr_ipc_server_t *srv, const char *sock_path, int backlog);

/* Blocking serve loop: select + accept + recv + handler + send + close.
 * Runs until srv->running is set to 0. */
int  vr_ipc_server_run(vr_ipc_server_t *srv, vr_ipc_handler_fn handler, void *ctx,
                        size_t req_buf_sz, size_t resp_buf_sz);

/* Cleanup: close fd, unlink socket. */
void vr_ipc_server_destroy(vr_ipc_server_t *srv);

#endif
```

Each daemon's IPC file then reduces to just the handler function. For example, `l3/fib_ipc.c` would become:

```c
static int fib_handle_cmd(const char *req, size_t req_len,
                           char *resp, size_t resp_cap, void *ctx) {
    /* existing handle_cmd logic, but using vr_json_get_str etc. */
}

int fib_ipc_serve(fib_table_t *fib, const char *sock_path, volatile int *running) {
    vr_ipc_server_t srv = { .running = 1 };
    /* ... */
}
```

This removes ~40 lines of boilerplate from each of the 7+ IPC files.

#### 1.5 — `lib/Makefile`

```makefile
# lib/Makefile — builds build/lib/libvrouter.a
include ../common.mk

SRCS := src/json.c src/net_parse.c src/ipc_server.c
OBJS := $(patsubst src/%.c,$(BUILDDIR)/obj/lib/%.o,$(SRCS))
LIB  := $(BUILDDIR)/lib/libvrouter.a

all: $(LIB)

$(BUILDDIR)/obj/lib/%.o: src/%.c | $(BUILDDIR)/obj/lib
	$(CC) $(CFLAGS) -I include -c $< -o $@

$(LIB): $(OBJS) | $(BUILDDIR)/lib
	$(AR) rcs $@ $^

$(BUILDDIR)/obj/lib $(BUILDDIR)/lib:
	mkdir -p $@

clean:
	rm -f $(OBJS) $(LIB)
```

---

### Phase 2: Standardize module directory layout

Every C module gets the same structure:

```
src/<module>/
├── include/       # Module-specific headers
│   └── *.h
├── src/           # Implementation files
│   ├── main.c     # Daemon entry point (if applicable)
│   └── *.c
└── Makefile       # Module Makefile
```

#### Files to move:

**l3/ → src/l3/**
```
l3/fib.h          → src/l3/include/fib.h
l3/rib.h          → src/l3/include/rib.h
l3/fib_cli.h      → src/l3/include/fib_cli.h
l3/fib_ipc.h      → src/l3/include/fib_ipc.h
l3/rib_ipc.h      → src/l3/include/rib_ipc.h
l3/persist.h      → src/l3/include/persist.h
l3/main.c         → src/l3/src/main.c
l3/fib.c          → src/l3/src/fib.c
l3/fib_cli.c      → src/l3/src/fib_cli.c
l3/fib_ipc.c      → src/l3/src/fib_ipc.c
l3/rib.c          → src/l3/src/rib.c
l3/rib_ipc.c      → src/l3/src/rib_ipc.c
l3/persist.c      → src/l3/src/persist.c
```

**l2/ → src/l2/**
```
l2/*.h            → src/l2/include/
l2/*.c            → src/l2/src/
l2/main_l2.c      → src/l2/src/main.c  (rename)
```

**ip/, vrf/, evpn/, vxlan/ → src/ip/, src/vrf/, src/evpn/, src/vxlan/**
Already have the right internal structure (`include/` + `src/`). Just move them under `src/` and rename daemon entry points:
```
ip/src/ip_daemon.c    → src/ip/src/main.c
vrf/src/vrf_daemon.c  → src/vrf/src/main.c
evpn/src/evpn_daemon.c → src/evpn/src/main.c
vxlan/src/vxlan_daemon.c → src/vxlan/src/main.c
```

#### Delete the committed binary:
```
rm vrf/vrf_daemon
```

---

### Phase 3: Standardize module Makefiles

Create `common.mk` in the repo root with shared settings:

```makefile
# common.mk — included by all module Makefiles

CC       ?= gcc
AR       ?= ar
CSTD     := -std=c11
CWARN    := -Wall -Wextra -Wpedantic -Werror
COPT     ?= -O2
CFLAGS   := $(CSTD) $(CWARN) $(COPT) -pthread -D_POSIX_C_SOURCE=200809L
LDFLAGS  := -pthread

# Root of the repo (each sub-Makefile sets this via relative path)
ROOTDIR  ?= ../..
BUILDDIR := $(ROOTDIR)/build
LIBDIR   := $(ROOTDIR)/lib

# Common library include path + link
CFLAGS   += -I$(LIBDIR)/include
LDLIBS   := $(BUILDDIR)/lib/libvrouter.a

ifeq ($(MODE),debug)
  CFLAGS  += -g -O0 -fsanitize=address,undefined -fno-omit-frame-pointer
  LDFLAGS += -fsanitize=address,undefined
  COPT    :=
endif
```

Each module Makefile then becomes minimal — e.g. `src/l3/Makefile`:

```makefile
ROOTDIR := ../..
include $(ROOTDIR)/common.mk

MODULE  := l3
TARGET  := $(BUILDDIR)/bin/fibd
SRCS    := $(wildcard src/*.c)
OBJDIR  := $(BUILDDIR)/obj/$(MODULE)
OBJS    := $(patsubst src/%.c,$(OBJDIR)/%.o,$(SRCS))

CFLAGS  += -I./include

all: $(TARGET)

$(OBJDIR)/%.o: src/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET): $(OBJS) $(LDLIBS) | $(BUILDDIR)/bin
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

$(OBJDIR) $(BUILDDIR)/bin:
	mkdir -p $@

clean:
	rm -f $(OBJS) $(TARGET)
```

All 6 module Makefiles follow this exact pattern, differing only in `MODULE`, `TARGET`, and `CFLAGS += -I./include`.

---

### Phase 4: Centralize tests

#### 4.1 — C unit tests → `tests/unit/`

Move all C test files:
```
ip/tests/test_ip.c       → tests/unit/test_ip.c
vrf/tests/test_vrf.c     → tests/unit/test_vrf.c
evpn/tests/test_evpn.c   → tests/unit/test_evpn.c
vxlan/tests/test_vxlan.c → tests/unit/test_vxlan.c
```

Create `tests/unit/Makefile` that builds each test binary by linking the module's `.o` files (minus `main.o`) with the test source and `libvrouter.a`. Output to `build/tests/`.

Each test binary must include the module's header path via `-I../../src/<module>/include -I../../lib/include`.

#### 4.2 — Shell integration tests → `tests/integration/`

Move:
```
tests/test_l2.sh     → tests/integration/test_l2.sh
tests/test_l3.sh     → tests/integration/test_l3.sh
tests/test_persist.sh → tests/integration/test_persist.sh
```

Update paths inside the scripts to reference `../../build/bin/fibd` etc.

#### 4.3 — Python tests → `tests/python/`

Move:
```
tests/test_bfd_*.py         → tests/python/
tests/test_modules_base.py  → tests/python/
tests/__init__.py            → tests/python/__init__.py
```

Update `pytest.ini` (moved to `tests/pytest.ini`) so `testpaths` points to `python/` and the Python source root includes `../python/`.

#### 4.4 — Bench → `tests/bench/`

Move `tests/bench_thread.c` → `tests/bench/bench_thread.c`. Add a minimal Makefile.

---

### Phase 5: Move Python code under `python/`

```
bfd/         → python/bfd/
lldp/        → python/lldp/
modules/     → python/modules/
main.py      → python/main.py
project-cli  → python/project-cli
```

Update import paths in `python/main.py` if needed (they should stay the same since the package-relative imports don't change).

---

### Phase 6: Move config/schema files under `config/`

```
schema.json             → config/schema.json
bfd_schema.json         → config/bfd_schema.json
l2d_schema.json         → config/l2d_schema.json
ip_schema.json          → config/ip_schema.json
vrf_schema.json         → config/vrf_schema.json
evpn_schema.json        → config/evpn_schema.json
vxlan_schema.json       → config/vxlan_schema.json
ip_runtime_config.json  → config/ip_runtime_config.json
vrf_runtime_config.json → config/vrf_runtime_config.json
evpn_runtime_config.json → config/evpn_runtime_config.json
vxlan_runtime.json      → config/vxlan_runtime.json
vrouter_routes.json     → config/vrouter_routes.json
vrouter_l2.json         → config/vrouter_l2.json
project_config.json     → config/project_config.json
interfaces.txt          → config/interfaces.txt
```

Update any C code or Python code that references these files by path. The daemons that write `schema.json` at startup should write to `$CONFIG_DIR/` (default `./config/` or `/etc/vrouter/`).

---

### Phase 7: Root Makefile

The new root Makefile orchestrates everything:

```makefile
.PHONY: all lib daemons tests clean install run stop status

MODULES := l3 l2 ip vrf evpn vxlan
BUILDDIR := build

all: lib daemons tests dist
	@echo "Build complete. Outputs in $(BUILDDIR)/"

lib:
	$(MAKE) -C lib

daemons: lib
	@for m in $(MODULES); do $(MAKE) -C src/$$m; done

tests: daemons
	$(MAKE) -C tests/unit
	$(MAKE) -C tests/bench

# Copy Python + config into build/ for a self-contained distribution
dist: daemons
	@mkdir -p $(BUILDDIR)/python $(BUILDDIR)/config
	cp -a python/* $(BUILDDIR)/python/
	cp -a config/* $(BUILDDIR)/config/

clean:
	$(MAKE) -C lib clean
	@for m in $(MODULES); do $(MAKE) -C src/$$m clean; done
	$(MAKE) -C tests/unit clean
	rm -rf $(BUILDDIR)

install: all
	install -d $(DESTDIR)/usr/sbin
	install -m 755 $(BUILDDIR)/bin/* $(DESTDIR)/usr/sbin/

# Run / Stop / Status targets (adapt from existing Makefile)
run: all
	@for bin in $(BUILDDIR)/bin/*; do \
	    echo "Starting $$(basename $$bin)..."; \
	    $$bin &  \
	done

stop:
	@for bin in fibd l2d ip_daemon vrf_daemon evpn_daemon vxlan_daemon; do \
	    pkill -x $$bin 2>/dev/null && echo "stopped $$bin" || true; \
	done

test-c: tests
	@for t in $(BUILDDIR)/tests/test_*; do echo "=== $$t ==="; $$t || exit 1; done

test-py:
	cd tests && python -m pytest python/

test-integration: all
	bash tests/integration/test_l3.sh
	bash tests/integration/test_l2.sh
	bash tests/integration/test_persist.sh

test-all: test-c test-py test-integration
```

---

### Phase 8: Update `.gitignore`

Replace the current `.gitignore` with a project-specific one:

```gitignore
# Build output
build/

# Object files
*.o
*.a

# Editor / OS
.vscode/
.idea/
*.swp
*.swo
.DS_Store

# Python
__pycache__/
*.py[codz]
*.egg-info/
.pytest_cache/
.mypy_cache/

# Runtime artifacts
*.sock
*.pid
*_runtime_config.json
```

---

### Phase 9: Update CI (`.github/workflows/ci.yml`)

Update all CI jobs to use the new build system:
- `make all` from root now builds everything
- Test binaries are in `build/tests/`
- Daemon binaries are in `build/bin/`
- Integration tests are in `tests/integration/`
- Python tests: `cd tests && python -m pytest python/`
- Add a sanitizer job with `MODE=debug make all`
- Upload `build/bin/*` as artifacts (all 6 daemons)

---

### Phase 10: Update `README.md`

Rewrite to reflect new layout:
- Updated build instructions (`make`, `make MODE=debug`, `make test-all`)
- New directory structure overview
- Updated socket paths and run/stop commands
- Note about `build/` being the distribution output

---

## Additional improvements to consider during refactoring

### Consistent error codes
Currently `l3/` returns `-errno` values, `ip/` returns `IP_OK`/`IP_ERR_*` enums, `evpn/` returns `EVPN_OK`/`EVPN_ERR_*`, etc. Consider a shared `lib/include/vrouter/errors.h` with unified `VR_OK`, `VR_ERR_INVAL`, `VR_ERR_NOMEM`, `VR_ERR_EXISTS`, `VR_ERR_NOTFOUND`, `VR_ERR_FULL` codes that all modules use.

### Consistent logging
Currently daemons use `fprintf(stderr, ...)` directly. A minimal `lib/include/vrouter/log.h` with `VR_LOG_INFO(...)`, `VR_LOG_ERR(...)`, `VR_LOG_DBG(...)` macros that prepend daemon name + timestamp would improve debuggability and could be redirected to syslog later.

### Header include guards
Standardize all include guards to the `VROUTER_<MODULE>_<FILE>_H` pattern for consistency and to avoid collisions.

---

## Recommended execution order

1. Phase 1 (lib/) — build the shared library first
2. Phase 2 (move files) — restructure directories
3. Phase 3 (Makefiles) — unify build system
4. Phase 4 (tests) — centralize tests
5. Phase 5-6 (Python + config) — move supporting files
6. Phase 7 (root Makefile) — wire it all together
7. Phase 8-9 (.gitignore + CI) — update infrastructure
8. Phase 10 (README) — document
9. Verify: `make clean && make all && make test-all`

Within Phase 1, do `json` first (most duplicated, easiest to validate), then `net_types`/`net_parse`, then `hash`, then `ipc_server` (most invasive).
