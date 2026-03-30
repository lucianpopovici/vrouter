#ifndef FDB_H
#define FDB_H

#include <stdint.h>
#include <time.h>
#include <pthread.h>
#include <stdatomic.h>

/* ─── Constants ─────────────────────────────────────────────── */
#define FDB_BUCKETS         4096        /* must be power of 2        */
#define FDB_MAX_ENTRIES     65536
#define FDB_IFNAME_LEN      16
#define FDB_DEFAULT_AGE_SEC 300         /* dynamic entry lifetime    */

#define FDB_FLAG_STATIC     (1 << 0)   /* never ages out            */
#define FDB_FLAG_LOCAL      (1 << 1)   /* our own MAC               */
#define FDB_FLAG_EVPN       (1 << 2)   /* learned via EVPN/BGP      */
#define FDB_FLAG_STP_BLOCK  (1 << 3)   /* port is STP-blocked       */
#define FDB_FLAG_DYNAMIC    (1 << 4)   /* data-plane source learn   */

/* ─── FDB entry ─────────────────────────────────────────────── */
typedef struct fdb_entry {
    uint8_t  mac[6];
    uint16_t vlan;
    char     port[FDB_IFNAME_LEN];
    uint32_t flags;
    uint32_t age_sec;           /* max lifetime (0 = use default)   */
    time_t   last_seen;         /* unix timestamp                    */
    atomic_uint_fast64_t hit_count;
    struct fdb_entry *next;     /* hash chain                        */
} fdb_entry_t;

/* ─── FDB table ─────────────────────────────────────────────── */
typedef struct fdb_table {
    fdb_entry_t *buckets[FDB_BUCKETS];
    int          count;
    uint32_t     age_sec;           /* default aging timer           */
    atomic_uint_fast64_t total_lookups;
    atomic_uint_fast64_t total_hits;
    atomic_uint_fast64_t total_misses;      /* → flood               */
    atomic_uint_fast64_t entries_aged;
    /* entry pool */
    fdb_entry_t  pool[FDB_MAX_ENTRIES];
    int          pool_used;
    fdb_entry_t *free_list;     /* singly-linked reclaim list        */
    pthread_rwlock_t lock;   /* protects entire table        */
} fdb_table_t;

/* ─── API ───────────────────────────────────────────────────── */
void          fdb_init(fdb_table_t *fdb);

/* learn: insert or refresh; returns 0=ok, -1=table full          */
int           fdb_learn(fdb_table_t *fdb,
                        const uint8_t mac[6], uint16_t vlan,
                        const char *port, uint32_t flags, uint32_t age_sec);

/* lookup: returns 0 on hit (result copied into *out), -1 on miss */
int fdb_lookup(fdb_table_t *fdb,
               const uint8_t mac[6], uint16_t vlan, fdb_entry_t *out);

/* delete one entry; returns 0=ok, -1=not found                   */
int           fdb_delete(fdb_table_t *fdb,
                         const uint8_t mac[6], uint16_t vlan);

/* flush: 0=all, else by port or vlan                             */
int           fdb_flush_port(fdb_table_t *fdb, const char *port);
int           fdb_flush_vlan(fdb_table_t *fdb, uint16_t vlan);
void          fdb_flush_all(fdb_table_t *fdb);

/* age sweep: remove expired dynamic entries; returns count removed */
int           fdb_age_sweep(fdb_table_t *fdb);

/* helpers */
void          fdb_mac_parse(const char *s, uint8_t mac[6]);
void          fdb_mac_str(const uint8_t mac[6], char *buf, size_t sz);

#endif /* FDB_H */
