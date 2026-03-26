#ifndef FIB_H
#define FIB_H

#include <stdint.h>
#include <netinet/in.h>

/* ─── Constants ─────────────────────────────────────────────── */
#define FIB_MAX_ROUTES      4096
#define FIB_IFACE_LEN       16
#define FIB_NEXTHOP_LEN     16
#define FIB_DEFAULT_METRIC  1
#define FIB_FLAG_ACTIVE     (1 << 0)
#define FIB_FLAG_CONNECTED  (1 << 1)
#define FIB_FLAG_STATIC     (1 << 2)

/* ─── Route entry ───────────────────────────────────────────── */
typedef struct fib_entry {
    uint32_t prefix;        /* network-order prefix */
    uint8_t  prefix_len;    /* 0-32                  */
    uint32_t nexthop;       /* network-order nexthop */
    char     iface[FIB_IFACE_LEN];
    uint32_t metric;
    uint32_t flags;
    uint64_t hit_count;     /* lookup hits           */
} fib_entry_t;

/* ─── FIB table ─────────────────────────────────────────────── */
typedef struct fib_table {
    fib_entry_t entries[FIB_MAX_ROUTES];
    int         count;
    uint32_t    max_routes;   /* runtime-configurable  */
    uint64_t    total_lookups;
    uint64_t    total_hits;
} fib_table_t;

/* ─── API ───────────────────────────────────────────────────── */
void fib_init(fib_table_t *fib);
int  fib_add(fib_table_t *fib, const char *prefix_cidr,
             const char *nexthop, const char *iface, uint32_t metric,
             uint32_t flags);
int  fib_del(fib_table_t *fib, const char *prefix_cidr);
const fib_entry_t *fib_lookup(fib_table_t *fib, const char *addr_str);
void fib_flush(fib_table_t *fib);
int  fib_count(const fib_table_t *fib);

/* helpers */
int  fib_parse_cidr(const char *cidr, uint32_t *prefix, uint8_t *len);
void fib_entry_to_str(const fib_entry_t *e, char *buf, size_t bufsz);

#endif /* FIB_H */
