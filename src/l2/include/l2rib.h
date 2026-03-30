#ifndef L2RIB_H
#define L2RIB_H

#include "fdb.h"
#include <stdint.h>

/* ─── Source priorities (lower = more preferred) ─────────────── */
typedef enum {
    L2_SRC_STATIC   = 0,   /* admin-configured, never overridden  */
    L2_SRC_LOCAL    = 1,   /* our own MACs                        */
    L2_SRC_EVPN     = 2,   /* learned via BGP-EVPN                */
    L2_SRC_STP      = 3,   /* STP-designated port wins            */
    L2_SRC_DYNAMIC  = 4,   /* data-plane source learning          */
    L2_SRC_COUNT
} l2rib_source_t;

static const char * const L2_SRC_NAME[L2_SRC_COUNT] = {
    [L2_SRC_STATIC]  = "static",
    [L2_SRC_LOCAL]   = "local",
    [L2_SRC_EVPN]    = "evpn",
    [L2_SRC_STP]     = "stp",
    [L2_SRC_DYNAMIC] = "dynamic",
};

/* ─── One candidate ──────────────────────────────────────────── */
#define L2RIB_MAX_CANDIDATES 4

typedef struct {
    char           port[FDB_IFNAME_LEN];
    l2rib_source_t source;
    uint8_t        priority;     /* 0=use source default           */
    uint8_t        active;       /* 1 = currently in FDB           */
    uint32_t       age_sec;
} l2rib_candidate_t;

/* ─── One L2 RIB entry (key = MAC + VLAN) ───────────────────── */
typedef struct l2rib_entry {
    uint8_t           mac[6];
    uint16_t          vlan;
    int               n_candidates;
    l2rib_candidate_t candidates[L2RIB_MAX_CANDIDATES];
    struct l2rib_entry *next;    /* hash chain                     */
} l2rib_entry_t;

/* ─── L2 RIB table ───────────────────────────────────────────── */
#define L2RIB_BUCKETS    4096
#define L2RIB_MAX_ENTRIES 65536

typedef struct {
    l2rib_entry_t *buckets[L2RIB_BUCKETS];
    int            count;
    uint64_t       n_added;
    uint64_t       n_deleted;
    uint64_t       n_fdb_updates;
    l2rib_entry_t  pool[L2RIB_MAX_ENTRIES];
    int            pool_used;
} l2rib_table_t;

/* ─── Callback: fired when best candidate changes ────────────── */
typedef void (*l2rib_fdb_cb)(const l2rib_entry_t   *entry,
                              const l2rib_candidate_t *best,
                              int install,   /* 1=add, 0=withdraw  */
                              void *ctx);

/* ─── API ────────────────────────────────────────────────────── */
void l2rib_init(l2rib_table_t *rib);

int l2rib_add(l2rib_table_t *rib,
              const uint8_t mac[6], uint16_t vlan,
              const char *port, l2rib_source_t source,
              uint8_t priority, uint32_t age_sec,
              l2rib_fdb_cb cb, void *ctx);

int l2rib_del(l2rib_table_t *rib,
              const uint8_t mac[6], uint16_t vlan,
              l2rib_source_t source,
              l2rib_fdb_cb cb, void *ctx);

int l2rib_flush_port(l2rib_table_t *rib, const char *port,
                     l2rib_fdb_cb cb, void *ctx);

const l2rib_entry_t     *l2rib_find(const l2rib_table_t *rib,
                                     const uint8_t mac[6], uint16_t vlan);
const l2rib_candidate_t *l2rib_best(const l2rib_entry_t *entry);
int                       l2rib_source_from_str(const char *s);

#endif /* L2RIB_H */
