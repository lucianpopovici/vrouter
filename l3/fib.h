#ifndef FIB_H
#define FIB_H

#include <stdint.h>
#include <netinet/in.h>
#include <pthread.h>

/* ─── Constants ─────────────────────────────────────────────── */
#define FIB_BUCKETS        8192        /* power of 2              */
#define FIB_POOL_DEFAULT   524288      /* 512K active routes       */
#define FIB_IFNAME_LEN     16
#define FIB_DEFAULT_METRIC 1

#define FIB_FLAG_ACTIVE     (1 << 0)
#define FIB_FLAG_CONNECTED  (1 << 1)
#define FIB_FLAG_STATIC     (1 << 2)

/* ─── Route entry (hash-chained) ────────────────────────────── */
typedef struct fib_entry {
    uint32_t          prefix;       /* host-byte-order            */
    uint8_t           prefix_len;
    uint8_t           _pad[3];
    uint32_t          nexthop;      /* host-byte-order            */
    char              iface[FIB_IFNAME_LEN];
    uint32_t          metric;
    uint32_t          flags;
    uint64_t          hit_count;
    struct fib_entry *next;         /* hash chain                 */
} fib_entry_t;

/* ─── FIB table ─────────────────────────────────────────────── */
typedef struct {
    fib_entry_t     **buckets;      /* heap: FIB_BUCKETS ptrs     */
    uint32_t          n_buckets;
    fib_entry_t      *pool;         /* heap: entry slab           */
    uint32_t          pool_size;
    uint32_t          pool_used;
    uint32_t          max_routes;   /* runtime cap (≤ pool_size)  */
    int               count;
    uint64_t          total_lookups;
    uint64_t          total_hits;
    pthread_rwlock_t  lock;
} fib_table_t;

/* ─── API ───────────────────────────────────────────────────── */
void fib_init(fib_table_t *fib);
void fib_destroy(fib_table_t *fib);

int  fib_add(fib_table_t *fib, const char *prefix_cidr,
             const char *nexthop, const char *iface,
             uint32_t metric, uint32_t flags);
int  fib_del(fib_table_t *fib, const char *prefix_cidr);

const fib_entry_t *fib_lookup(fib_table_t *fib, const char *addr_str);

void fib_flush(fib_table_t *fib);
int  fib_count(const fib_table_t *fib);

int  fib_parse_cidr(const char *cidr, uint32_t *prefix, uint8_t *len);
void fib_entry_to_str(const fib_entry_t *e, char *buf, size_t bufsz);

/* Iterate all entries — caller holds no lock (snapshot via callback) */
typedef void (*fib_iter_cb)(const fib_entry_t *e, void *ctx);
void fib_iterate(fib_table_t *fib, fib_iter_cb cb, void *ctx);

#endif /* FIB_H */
