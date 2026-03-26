#include "l2rib.h"
#include "fdb.h"

#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <strings.h>

/* ─── Hash (reuse FNV-1a over mac+vlan) ─────────────────────── */
static uint32_t l2rib_hash(const uint8_t mac[6], uint16_t vlan)
{
    uint32_t h = 2166136261u;
    for (int i = 0; i < 6; i++) { h ^= mac[i]; h *= 16777619u; }
    h ^= (vlan & 0xFF); h *= 16777619u;
    h ^= (vlan >> 8);   h *= 16777619u;
    return h & (L2RIB_BUCKETS - 1);
}

static l2rib_entry_t *pool_alloc(l2rib_table_t *rib)
{
    if (rib->pool_used >= L2RIB_MAX_ENTRIES) return NULL;
    l2rib_entry_t *e = &rib->pool[rib->pool_used++];
    memset(e, 0, sizeof(*e));
    return e;
}

void l2rib_init(l2rib_table_t *rib) { memset(rib, 0, sizeof(*rib)); }

int l2rib_source_from_str(const char *s)
{
    if (!s) return L2_SRC_DYNAMIC;
    for (int i = 0; i < L2_SRC_COUNT; i++)
        if (strcasecmp(s, L2_SRC_NAME[i]) == 0) return i;
    return L2_SRC_DYNAMIC;
}

/* ─── Best candidate selection ───────────────────────────────── */
const l2rib_candidate_t *l2rib_best(const l2rib_entry_t *e)
{
    const l2rib_candidate_t *best = NULL;
    for (int i = 0; i < e->n_candidates; i++) {
        const l2rib_candidate_t *c = &e->candidates[i];
        if (!best) { best = c; continue; }
        uint8_t cp = c->priority    ? c->priority    : (uint8_t)c->source;
        uint8_t bp = best->priority ? best->priority : (uint8_t)best->source;
        if (cp < bp) best = c;
    }
    return best;
}

/* ─── Reselect and fire callback ─────────────────────────────── */
static void reselect(l2rib_table_t *rib, l2rib_entry_t *e,
                     const l2rib_candidate_t *old_best,
                     l2rib_fdb_cb cb, void *ctx)
{
    for (int i = 0; i < e->n_candidates; i++)
        e->candidates[i].active = 0;

    const l2rib_candidate_t *nb = l2rib_best(e);
    if (nb) ((l2rib_candidate_t *)nb)->active = 1;

    if (!cb) return;

    int same = (old_best && nb &&
                strncmp(old_best->port, nb->port, FDB_IFNAME_LEN) == 0 &&
                old_best->source == nb->source);
    if (!same) {
        if (old_best && !nb)  cb(e, old_best, 0, ctx);
        else if (nb)          cb(e, nb, 1, ctx);
        rib->n_fdb_updates++;
    }
}

/* ─── Find existing entry ────────────────────────────────────── */
static l2rib_entry_t *rib_find_mut(l2rib_table_t *rib,
                                    const uint8_t mac[6], uint16_t vlan)
{
    uint32_t idx = l2rib_hash(mac, vlan);
    l2rib_entry_t *e = rib->buckets[idx];
    while (e) {
        if (memcmp(e->mac, mac, 6) == 0 && e->vlan == vlan) return e;
        e = e->next;
    }
    return NULL;
}

const l2rib_entry_t *l2rib_find(const l2rib_table_t *rib,
                                  const uint8_t mac[6], uint16_t vlan)
{
    return rib_find_mut((l2rib_table_t *)rib, mac, vlan);
}

/* ─── Add ────────────────────────────────────────────────────── */
int l2rib_add(l2rib_table_t *rib,
              const uint8_t mac[6], uint16_t vlan,
              const char *port, l2rib_source_t source,
              uint8_t priority, uint32_t age_sec,
              l2rib_fdb_cb cb, void *ctx)
{
    uint32_t       idx = l2rib_hash(mac, vlan);
    l2rib_entry_t *e   = rib_find_mut(rib, mac, vlan);

    if (!e) {
        e = pool_alloc(rib);
        if (!e) return -ENOMEM;
        memcpy(e->mac, mac, 6);
        e->vlan     = vlan;
        e->next     = rib->buckets[idx];
        rib->buckets[idx] = e;
        rib->count++;
    }

    /* snapshot old best */
    l2rib_candidate_t old_snap;
    const l2rib_candidate_t *ob = l2rib_best(e);
    int had = (ob != NULL);
    if (had) old_snap = *ob;

    /* update existing candidate from same source? */
    for (int i = 0; i < e->n_candidates; i++) {
        l2rib_candidate_t *c = &e->candidates[i];
        if (c->source == source) {
            strncpy(c->port, port, FDB_IFNAME_LEN - 1);
            c->priority = priority;
            c->age_sec  = age_sec;
            reselect(rib, e, had ? &old_snap : NULL, cb, ctx);
            rib->n_added++;
            return 0;
        }
    }

    if (e->n_candidates >= L2RIB_MAX_CANDIDATES) return -ENOMEM;

    l2rib_candidate_t *c = &e->candidates[e->n_candidates++];
    memset(c, 0, sizeof(*c));
    strncpy(c->port, port, FDB_IFNAME_LEN - 1);
    c->source   = source;
    c->priority = priority;
    c->age_sec  = age_sec;

    reselect(rib, e, had ? &old_snap : NULL, cb, ctx);
    rib->n_added++;
    return 0;
}

/* ─── Delete ─────────────────────────────────────────────────── */
int l2rib_del(l2rib_table_t *rib,
              const uint8_t mac[6], uint16_t vlan,
              l2rib_source_t source,
              l2rib_fdb_cb cb, void *ctx)
{
    l2rib_entry_t *e = rib_find_mut(rib, mac, vlan);
    if (!e) return -ENOENT;

    l2rib_candidate_t old_snap;
    const l2rib_candidate_t *ob = l2rib_best(e);
    int had = (ob != NULL);
    if (had) old_snap = *ob;

    int removed = 0;
    for (int i = 0; i < e->n_candidates; ) {
        if (e->candidates[i].source == source) {
            e->candidates[i] = e->candidates[--e->n_candidates];
            removed++;
        } else { i++; }
    }
    if (!removed) return -ENOENT;

    reselect(rib, e, had ? &old_snap : NULL, cb, ctx);
    rib->n_deleted += (uint64_t)removed;

    if (e->n_candidates == 0) {
        /* remove entry from hash chain */
        uint32_t idx = l2rib_hash(mac, vlan);
        l2rib_entry_t **pp = &rib->buckets[idx];
        while (*pp && *pp != e) pp = &(*pp)->next;
        if (*pp) { *pp = e->next; rib->count--; }
    }
    return 0;
}

/* ─── Flush by port ──────────────────────────────────────────── */
int l2rib_flush_port(l2rib_table_t *rib, const char *port,
                     l2rib_fdb_cb cb, void *ctx)
{
    int total = 0;
    for (int b = 0; b < L2RIB_BUCKETS; b++) {
        l2rib_entry_t *e = rib->buckets[b];
        while (e) {
            for (int i = 0; i < e->n_candidates; i++) {
                if (strncmp(e->candidates[i].port, port,
                            FDB_IFNAME_LEN) == 0) {
                    l2rib_del(rib, e->mac, e->vlan,
                              e->candidates[i].source, cb, ctx);
                    total++;
                    break;
                }
            }
            e = e->next;
        }
    }
    return total;
}
