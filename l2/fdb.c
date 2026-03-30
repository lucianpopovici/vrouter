#include "fdb.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <stdatomic.h>

/* ─── Hash: FNV-1a over mac[6] + vlan ──────────────────────── */
static uint32_t fdb_hash(const uint8_t mac[6], uint16_t vlan)
{
    uint32_t h = 2166136261u;
    for (int i = 0; i < 6; i++) { h ^= mac[i]; h *= 16777619u; }
    h ^= (vlan & 0xFF);  h *= 16777619u;
    h ^= (vlan >> 8);    h *= 16777619u;
    return h & (FDB_BUCKETS - 1);
}

/* ─── Pool allocator (caller must hold write lock) ───────────── */
static fdb_entry_t *pool_alloc(fdb_table_t *fdb)
{
    fdb_entry_t *e = NULL;
    if (fdb->free_list) {
        e = fdb->free_list;
        fdb->free_list = e->next;
    } else if (fdb->pool_used < FDB_MAX_ENTRIES) {
        e = &fdb->pool[fdb->pool_used++];
    }
    if (e) memset(e, 0, sizeof(*e));
    return e;
}

/* ─── Init ──────────────────────────────────────────────────── */
void fdb_init(fdb_table_t *fdb)
{
    memset(fdb, 0, sizeof(*fdb));
    fdb->age_sec = FDB_DEFAULT_AGE_SEC;
    pthread_rwlock_init(&fdb->lock, NULL);
}

/* ─── MAC helpers ────────────────────────────────────────────── */
void fdb_mac_str(const uint8_t mac[6], char *buf, size_t sz)
{
    snprintf(buf, sz, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void fdb_mac_parse(const char *s, uint8_t mac[6])
{
    unsigned int v[6] = {0};
    sscanf(s, "%x:%x:%x:%x:%x:%x",
           &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]);
    for (int i = 0; i < 6; i++) mac[i] = (uint8_t)v[i];
}

/* ─── Learn ─────────────────────────────────────────────────── */
int fdb_learn(fdb_table_t *fdb, const uint8_t mac[6], uint16_t vlan,
              const char *port, uint32_t flags, uint32_t age_sec)
{
    uint32_t    idx  = fdb_hash(mac, vlan);
    time_t      now  = time(NULL);
    int         rc   = 0;

    pthread_rwlock_wrlock(&fdb->lock);

    /* update existing? */
    fdb_entry_t *e = fdb->buckets[idx];
    while (e) {
        if (memcmp(e->mac, mac, 6) == 0 && e->vlan == vlan) {
            strncpy(e->port, port, FDB_IFNAME_LEN - 1);
            e->flags     = flags;
            e->last_seen = now;
            if (age_sec) e->age_sec = age_sec;
            goto out;
        }
        e = e->next;
    }

    /* allocate new */
    e = pool_alloc(fdb);
    if (!e) { rc = -ENOMEM; goto out; }

    memcpy(e->mac, mac, 6);
    e->vlan      = vlan;
    e->flags     = flags;
    e->last_seen = now;
    e->age_sec   = age_sec ? age_sec : fdb->age_sec;
    e->hit_count = 0;
    strncpy(e->port, port, FDB_IFNAME_LEN - 1);

    e->next           = fdb->buckets[idx];
    fdb->buckets[idx] = e;
    fdb->count++;

out:
    pthread_rwlock_unlock(&fdb->lock);
    return rc;
}

/* ─── Lookup ─────────────────────────────────────────────────── */
int fdb_lookup(fdb_table_t *fdb,
               const uint8_t mac[6], uint16_t vlan, fdb_entry_t *out)
{
    pthread_rwlock_rdlock(&fdb->lock);

    atomic_fetch_add_explicit(&fdb->total_lookups, 1, memory_order_relaxed);
    uint32_t     idx = fdb_hash(mac, vlan);
    fdb_entry_t *e   = fdb->buckets[idx];

    while (e) {
        if (memcmp(e->mac, mac, 6) == 0 && e->vlan == vlan) {
            atomic_fetch_add_explicit(&e->hit_count,     1, memory_order_relaxed);
            atomic_fetch_add_explicit(&fdb->total_hits,  1, memory_order_relaxed);
            if (out) *out = *e;
            pthread_rwlock_unlock(&fdb->lock);
            return 0;
        }
        e = e->next;
    }

    atomic_fetch_add_explicit(&fdb->total_misses, 1, memory_order_relaxed);
    pthread_rwlock_unlock(&fdb->lock);
    return -1;  /* miss → flood */
}

/* ─── Delete ─────────────────────────────────────────────────── */
int fdb_delete(fdb_table_t *fdb, const uint8_t mac[6], uint16_t vlan)
{
    uint32_t      idx = fdb_hash(mac, vlan);
    int           rc  = -ENOENT;

    pthread_rwlock_wrlock(&fdb->lock);

    fdb_entry_t **pp = &fdb->buckets[idx];
    while (*pp) {
        fdb_entry_t *e = *pp;
        if (memcmp(e->mac, mac, 6) == 0 && e->vlan == vlan) {
            *pp = e->next;
            memset(e, 0, sizeof(*e));
            e->next = fdb->free_list;
            fdb->free_list = e;
            fdb->count--;
            rc = 0;
            break;
        }
        pp = &e->next;
    }

    pthread_rwlock_unlock(&fdb->lock);
    return rc;
}

/* ─── Flush helpers ─────────────────────────────────────────── */
int fdb_flush_port(fdb_table_t *fdb, const char *port)
{
    int removed = 0;

    pthread_rwlock_wrlock(&fdb->lock);

    for (int i = 0; i < FDB_BUCKETS; i++) {
        fdb_entry_t **pp = &fdb->buckets[i];
        while (*pp) {
            fdb_entry_t *e = *pp;
            if (strncmp(e->port, port, FDB_IFNAME_LEN) == 0) {
                *pp = e->next;
                memset(e, 0, sizeof(*e));
                e->next = fdb->free_list;
                fdb->free_list = e;
                fdb->count--;
                removed++;
            } else {
                pp = &e->next;
            }
        }
    }

    pthread_rwlock_unlock(&fdb->lock);
    return removed;
}

int fdb_flush_vlan(fdb_table_t *fdb, uint16_t vlan)
{
    int removed = 0;

    pthread_rwlock_wrlock(&fdb->lock);

    for (int i = 0; i < FDB_BUCKETS; i++) {
        fdb_entry_t **pp = &fdb->buckets[i];
        while (*pp) {
            fdb_entry_t *e = *pp;
            if (e->vlan == vlan) {
                *pp = e->next;
                memset(e, 0, sizeof(*e));
                e->next = fdb->free_list;
                fdb->free_list = e;
                fdb->count--;
                removed++;
            } else {
                pp = &e->next;
            }
        }
    }

    pthread_rwlock_unlock(&fdb->lock);
    return removed;
}

void fdb_flush_all(fdb_table_t *fdb)
{
    pthread_rwlock_wrlock(&fdb->lock);
    memset(fdb->buckets, 0, sizeof(fdb->buckets));
    memset(fdb->pool,    0, sizeof(fdb->pool));
    fdb->count     = 0;
    fdb->pool_used = 0;
    fdb->free_list = NULL;
    pthread_rwlock_unlock(&fdb->lock);
}

/* ─── Age sweep ─────────────────────────────────────────────── */
int fdb_age_sweep(fdb_table_t *fdb)
{
    time_t now     = time(NULL);
    int    removed = 0;

    pthread_rwlock_wrlock(&fdb->lock);

    for (int i = 0; i < FDB_BUCKETS; i++) {
        fdb_entry_t **pp = &fdb->buckets[i];
        while (*pp) {
            fdb_entry_t *e = *pp;
            if (!(e->flags & (FDB_FLAG_STATIC | FDB_FLAG_LOCAL)) &&
                (now - e->last_seen) >= (time_t)e->age_sec) {
                *pp = e->next;
                memset(e, 0, sizeof(*e));
                e->next = fdb->free_list;
                fdb->free_list = e;
                fdb->count--;
                atomic_fetch_add_explicit(&fdb->entries_aged, 1, memory_order_relaxed);
                removed++;
            } else {
                pp = &e->next;
            }
        }
    }

    pthread_rwlock_unlock(&fdb->lock);
    return removed;
}
