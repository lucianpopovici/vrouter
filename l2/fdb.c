#include "fdb.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

/* ─── Hash: FNV-1a over mac[6] + vlan ──────────────────────── */
static uint32_t fdb_hash(const uint8_t mac[6], uint16_t vlan)
{
    uint32_t h = 2166136261u;
    for (int i = 0; i < 6; i++) { h ^= mac[i]; h *= 16777619u; }
    h ^= (vlan & 0xFF);  h *= 16777619u;
    h ^= (vlan >> 8);    h *= 16777619u;
    return h & (FDB_BUCKETS - 1);
}

/* ─── Pool allocator ─────────────────────────────────────────── */
static fdb_entry_t *pool_alloc(fdb_table_t *fdb)
{
    if (fdb->pool_used >= FDB_MAX_ENTRIES) return NULL;
    fdb_entry_t *e = &fdb->pool[fdb->pool_used++];
    memset(e, 0, sizeof(*e));
    return e;
}

/* ─── Init ──────────────────────────────────────────────────── */
void fdb_init(fdb_table_t *fdb)
{
    memset(fdb, 0, sizeof(*fdb));
    fdb->age_sec = FDB_DEFAULT_AGE_SEC;
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
    uint32_t    idx = fdb_hash(mac, vlan);
    fdb_entry_t *e  = fdb->buckets[idx];
    time_t       now = time(NULL);

    /* update existing? */
    while (e) {
        if (memcmp(e->mac, mac, 6) == 0 && e->vlan == vlan) {
            strncpy(e->port, port, FDB_IFNAME_LEN - 1);
            e->flags     = flags;
            e->last_seen = now;
            if (age_sec) e->age_sec = age_sec;
            return 0;
        }
        e = e->next;
    }

    /* allocate new */
    e = pool_alloc(fdb);
    if (!e) return -ENOMEM;

    memcpy(e->mac, mac, 6);
    e->vlan      = vlan;
    e->flags     = flags;
    e->last_seen = now;
    e->age_sec   = age_sec ? age_sec : fdb->age_sec;
    e->hit_count = 0;
    strncpy(e->port, port, FDB_IFNAME_LEN - 1);

    e->next            = fdb->buckets[idx];
    fdb->buckets[idx]  = e;
    fdb->count++;
    return 0;
}

/* ─── Lookup ─────────────────────────────────────────────────── */
const fdb_entry_t *fdb_lookup(fdb_table_t *fdb,
                               const uint8_t mac[6], uint16_t vlan)
{
    fdb->total_lookups++;
    uint32_t     idx = fdb_hash(mac, vlan);
    fdb_entry_t *e   = fdb->buckets[idx];
    while (e) {
        if (memcmp(e->mac, mac, 6) == 0 && e->vlan == vlan) {
            e->hit_count++;
            fdb->total_hits++;
            return e;
        }
        e = e->next;
    }
    fdb->total_misses++;
    return NULL;  /* miss → flood */
}

/* ─── Delete ─────────────────────────────────────────────────── */
int fdb_delete(fdb_table_t *fdb, const uint8_t mac[6], uint16_t vlan)
{
    uint32_t     idx  = fdb_hash(mac, vlan);
    fdb_entry_t **pp  = &fdb->buckets[idx];
    while (*pp) {
        fdb_entry_t *e = *pp;
        if (memcmp(e->mac, mac, 6) == 0 && e->vlan == vlan) {
            *pp = e->next;
            memset(e, 0, sizeof(*e));
            fdb->count--;
            return 0;
        }
        pp = &e->next;
    }
    return -ENOENT;
}

/* ─── Flush helpers ─────────────────────────────────────────── */
int fdb_flush_port(fdb_table_t *fdb, const char *port)
{
    int removed = 0;
    for (int i = 0; i < FDB_BUCKETS; i++) {
        fdb_entry_t **pp = &fdb->buckets[i];
        while (*pp) {
            fdb_entry_t *e = *pp;
            if (strncmp(e->port, port, FDB_IFNAME_LEN) == 0) {
                *pp = e->next;
                memset(e, 0, sizeof(*e));
                fdb->count--;
                removed++;
            } else {
                pp = &e->next;
            }
        }
    }
    return removed;
}

int fdb_flush_vlan(fdb_table_t *fdb, uint16_t vlan)
{
    int removed = 0;
    for (int i = 0; i < FDB_BUCKETS; i++) {
        fdb_entry_t **pp = &fdb->buckets[i];
        while (*pp) {
            fdb_entry_t *e = *pp;
            if (e->vlan == vlan) {
                *pp = e->next;
                memset(e, 0, sizeof(*e));
                fdb->count--;
                removed++;
            } else {
                pp = &e->next;
            }
        }
    }
    return removed;
}

void fdb_flush_all(fdb_table_t *fdb)
{
    memset(fdb->buckets, 0, sizeof(fdb->buckets));
    memset(fdb->pool,    0, sizeof(fdb->pool));
    fdb->count     = 0;
    fdb->pool_used = 0;
}

/* ─── Age sweep ─────────────────────────────────────────────── */
int fdb_age_sweep(fdb_table_t *fdb)
{
    time_t now     = time(NULL);
    int    removed = 0;

    for (int i = 0; i < FDB_BUCKETS; i++) {
        fdb_entry_t **pp = &fdb->buckets[i];
        while (*pp) {
            fdb_entry_t *e = *pp;
            if (!(e->flags & (FDB_FLAG_STATIC | FDB_FLAG_LOCAL)) &&
                (now - e->last_seen) >= (time_t)e->age_sec) {
                *pp = e->next;
                memset(e, 0, sizeof(*e));
                fdb->count--;
                fdb->entries_aged++;
                removed++;
            } else {
                pp = &e->next;
            }
        }
    }
    return removed;
}
