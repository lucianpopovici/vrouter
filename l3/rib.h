#ifndef RIB_H
#define RIB_H

#include <stdint.h>
#include "fib.h"

/* ─── Route sources & their default admin distances ─────────── */
typedef enum {
    RIB_SRC_CONNECTED = 0,
    RIB_SRC_STATIC    = 1,
    RIB_SRC_EBGP      = 2,
    RIB_SRC_OSPF      = 3,
    RIB_SRC_IBGP      = 4,
    RIB_SRC_UNKNOWN   = 5,
    RIB_SRC_COUNT
} rib_source_t;

static const uint8_t RIB_DEFAULT_AD[RIB_SRC_COUNT] = {
    [RIB_SRC_CONNECTED] =   0,
    [RIB_SRC_STATIC]    =   1,
    [RIB_SRC_EBGP]      =  20,
    [RIB_SRC_OSPF]      = 110,
    [RIB_SRC_IBGP]      = 200,
    [RIB_SRC_UNKNOWN]   = 255,
};

static const char * const RIB_SRC_NAME[RIB_SRC_COUNT] = {
    [RIB_SRC_CONNECTED] = "connected",
    [RIB_SRC_STATIC]    = "static",
    [RIB_SRC_EBGP]      = "ebgp",
    [RIB_SRC_OSPF]      = "ospf",
    [RIB_SRC_IBGP]      = "ibgp",
    [RIB_SRC_UNKNOWN]   = "unknown",
};

/* ─── Hash table parameters ─────────────────────────────────── */
#define RIB_BUCKETS        1048576  /* 1M buckets: O(1) to 800K routes */
#define RIB_POOL_DEFAULT   1048576  /* 1M entries  — full internet BGP  */
#define RIB_MAX_CANDIDATES 8

/* ─── One candidate route ───────────────────────────────────── */
typedef struct rib_candidate {
    uint32_t     nexthop;
    char         iface[FIB_IFACE_LEN];
    uint32_t     metric;
    rib_source_t source;
    uint8_t      admin_dist;
    uint8_t      active;
} rib_candidate_t;

/* ─── Prefix entry (hash-chained) ──────────────────────────── */
typedef struct rib_entry {
    uint32_t         prefix;
    uint8_t          prefix_len;
    uint8_t          _pad[3];
    int              n_candidates;
    rib_candidate_t  candidates[RIB_MAX_CANDIDATES];
    struct rib_entry *next;
} rib_entry_t;

/* ─── RIB table ─────────────────────────────────────────────── */
typedef struct {
    rib_entry_t **buckets;    /* heap: RIB_BUCKETS pointers      */
    uint32_t      n_buckets;
    rib_entry_t  *pool;       /* heap: pre-allocated entry slab  */
    uint32_t      pool_size;
    uint32_t      pool_used;
    int           count;
    uint64_t      n_added;
    uint64_t      n_deleted;
    uint64_t      n_fib_updates;
    uint64_t      n_collisions;
} rib_table_t;

/* ─── Callback ──────────────────────────────────────────────── */
typedef void (*rib_fib_cb)(const rib_entry_t   *entry,
                           const rib_candidate_t *best,
                           int install, void *ctx);

/* ─── Public API ────────────────────────────────────────────── */
void rib_init(rib_table_t *rib);
void rib_destroy(rib_table_t *rib);

int  rib_add(rib_table_t *rib,
             const char  *prefix_cidr,
             const char  *nexthop_str,
             const char  *iface,
             uint32_t     metric,
             rib_source_t source,
             uint8_t      admin_dist,
             rib_fib_cb   cb, void *cb_ctx);

int  rib_del(rib_table_t *rib,
             const char  *prefix_cidr,
             const char  *nexthop_str,
             rib_source_t source,
             rib_fib_cb   cb, void *cb_ctx);

const rib_entry_t     *rib_find(const rib_table_t *rib,
                                 const char *prefix_cidr);
const rib_candidate_t *rib_best(const rib_entry_t *entry);

int  rib_source_from_str(const char *s);
void rib_entry_to_str(const rib_entry_t *e, char *buf, size_t sz);

static inline double rib_load_factor(const rib_table_t *r) {
    return r->n_buckets ? (double)r->count / r->n_buckets : 0.0;
}

#endif /* RIB_H */
