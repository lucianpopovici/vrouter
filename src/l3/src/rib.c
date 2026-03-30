#include "rib.h"
#include <vrouter/hash.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <arpa/inet.h>
#include <errno.h>

const uint8_t RIB_DEFAULT_AD[RIB_SRC_COUNT] = {
    [RIB_SRC_CONNECTED] =   0,
    [RIB_SRC_STATIC]    =   1,
    [RIB_SRC_EBGP]      =  20,
    [RIB_SRC_OSPF]      = 110,
    [RIB_SRC_IBGP]      = 200,
    [RIB_SRC_UNKNOWN]   = 255,
};

const char *const RIB_SRC_NAME[RIB_SRC_COUNT] = {
    [RIB_SRC_CONNECTED] = "connected",
    [RIB_SRC_STATIC]    = "static",
    [RIB_SRC_EBGP]      = "ebgp",
    [RIB_SRC_OSPF]      = "ospf",
    [RIB_SRC_IBGP]      = "ibgp",
    [RIB_SRC_UNKNOWN]   = "unknown",
};

/* ═══════════════════════════════════════════════════════════════
 * Hash: FNV-1a over {prefix u32, prefix_len u8}
 * ═══════════════════════════════════════════════════════════════ */
static inline uint32_t rib_hash(uint32_t prefix, uint8_t len,
                                  uint32_t n_buckets)
{
    uint8_t buf[5] = {
        (uint8_t)((prefix >> 24) & 0xFF),
        (uint8_t)((prefix >> 16) & 0xFF),
        (uint8_t)((prefix >>  8) & 0xFF),
        (uint8_t)((prefix >>  0) & 0xFF),
        len
    };
    return vr_fnv1a_mod(buf, 5, n_buckets);
}

/* ═══════════════════════════════════════════════════════════════
 * Init / Destroy
 * ═══════════════════════════════════════════════════════════════ */
void rib_init(rib_table_t *rib)
{
    memset(rib, 0, sizeof(*rib));
    rib->n_buckets = RIB_BUCKETS;
    rib->pool_size = RIB_POOL_DEFAULT;
    rib->buckets   = calloc(rib->n_buckets, sizeof(rib_entry_t *));
    rib->pool      = calloc(rib->pool_size,  sizeof(rib_entry_t));
    if (!rib->buckets || !rib->pool) {
        free(rib->buckets); free(rib->pool);
        rib->buckets = NULL; rib->pool = NULL;
    }
    pthread_rwlock_init(&rib->lock, NULL);
}

void rib_destroy(rib_table_t *rib)
{
    pthread_rwlock_destroy(&rib->lock);
    free(rib->buckets);
    free(rib->pool);
    rib->buckets = NULL;
    rib->pool    = NULL;
    rib->count   = 0;
}

/* ═══════════════════════════════════════════════════════════════
 * Source helpers
 * ═══════════════════════════════════════════════════════════════ */
int rib_source_from_str(const char *s)
{
    if (!s) return RIB_SRC_UNKNOWN;
    for (int i = 0; i < RIB_SRC_COUNT; i++)
        if (strcasecmp(s, RIB_SRC_NAME[i]) == 0) return i;
    return RIB_SRC_UNKNOWN;
}

/* ═══════════════════════════════════════════════════════════════
 * Pool allocator — O(1), caller must hold write lock
 * ═══════════════════════════════════════════════════════════════ */
static rib_entry_t *pool_alloc(rib_table_t *rib)
{
    rib_entry_t *e = NULL;
    if (rib->free_list) {
        e = rib->free_list;
        rib->free_list = e->next;
    } else if (rib->pool && rib->pool_used < rib->pool_size) {
        e = &rib->pool[rib->pool_used++];
    }
    if (e) memset(e, 0, sizeof(*e));
    return e;
}

/* ═══════════════════════════════════════════════════════════════
 * Internal: find entry — O(1) average, caller holds any lock
 * ═══════════════════════════════════════════════════════════════ */
static rib_entry_t *entry_find_locked(rib_table_t *rib,
                                       uint32_t prefix, uint8_t len)
{
    if (!rib->buckets) return NULL;
    uint32_t idx = rib_hash(prefix, len, rib->n_buckets);
    rib_entry_t *e = rib->buckets[idx];
    while (e) {
        if (e->prefix == prefix && e->prefix_len == len) return e;
        e = e->next;
    }
    return NULL;
}

/* ═══════════════════════════════════════════════════════════════
 * Best-route selection (no lock needed — caller holds at least rdlock)
 * ═══════════════════════════════════════════════════════════════ */
const rib_candidate_t *rib_best(const rib_entry_t *entry)
{
    const rib_candidate_t *best = NULL;
    for (int i = 0; i < entry->n_candidates; i++) {
        const rib_candidate_t *c = &entry->candidates[i];
        if (!best) { best = c; continue; }
        if (c->admin_dist < best->admin_dist) { best = c; continue; }
        if (c->admin_dist == best->admin_dist &&
            c->metric < best->metric)          { best = c; continue; }
    }
    return best;
}

/* ═══════════════════════════════════════════════════════════════
 * Reselect & fire callback — caller holds write lock
 * ═══════════════════════════════════════════════════════════════ */
static void reselect_locked(rib_table_t *rib, rib_entry_t *entry,
                              const rib_candidate_t *old_best,
                              rib_fib_cb cb, void *ctx)
{
    for (int i = 0; i < entry->n_candidates; i++)
        entry->candidates[i].active = 0;

    const rib_candidate_t *nb = rib_best(entry);
    if (nb) ((rib_candidate_t *)nb)->active = 1;

    if (!cb) return;

    int same = (old_best && nb &&
                old_best->nexthop    == nb->nexthop &&
                old_best->admin_dist == nb->admin_dist &&
                old_best->metric     == nb->metric);
    if (!same) {
        if (old_best && !nb)  cb(entry, old_best, 0, ctx);
        else if (nb)          cb(entry, nb,        1, ctx);
        rib->n_fib_updates++;
    }
}

/* ═══════════════════════════════════════════════════════════════
 * rib_add — O(1) average, thread-safe
 * ═══════════════════════════════════════════════════════════════ */
int rib_add(rib_table_t *rib,
            const char  *prefix_cidr,
            const char  *nexthop_str,
            const char  *iface,
            uint32_t     metric,
            rib_source_t source,
            uint8_t      ad,
            rib_fib_cb   cb, void *ctx)
{
    uint32_t pfx; uint8_t len;
    if (fib_parse_cidr(prefix_cidr, &pfx, &len) != 0) return -EINVAL;

    struct in_addr nh_in;
    if (inet_pton(AF_INET, nexthop_str, &nh_in) != 1) return -EINVAL;
    uint32_t nh = ntohl(nh_in.s_addr);

    if (source < 0 || source >= RIB_SRC_COUNT) source = RIB_SRC_UNKNOWN;
    if (ad == 0) ad = RIB_DEFAULT_AD[source];

    int rc = 0;
    pthread_rwlock_wrlock(&rib->lock);

    /* get-or-create */
    rib_entry_t *entry = entry_find_locked(rib, pfx, len);
    if (!entry) {
        entry = pool_alloc(rib);
        if (!entry) { rc = -ENOMEM; goto out; }
        entry->prefix     = pfx;
        entry->prefix_len = len;
        uint32_t idx = rib_hash(pfx, len, rib->n_buckets);
        entry->next        = rib->buckets[idx];
        rib->buckets[idx]  = entry;
        rib->count++;
    }

    /* snapshot old best */
    rib_candidate_t old_snap;
    const rib_candidate_t *ob = rib_best(entry);
    int had = (ob != NULL);
    if (had) old_snap = *ob;

    /* update existing candidate from same source+nexthop */
    for (int i = 0; i < entry->n_candidates; i++) {
        rib_candidate_t *c = &entry->candidates[i];
        if (c->source == source && c->nexthop == nh) {
            c->metric     = metric;
            c->admin_dist = ad;
            if (iface && iface[0])
                strncpy(c->iface, iface, FIB_IFNAME_LEN - 1);
            reselect_locked(rib, entry, had ? &old_snap : NULL, cb, ctx);
            rib->n_added++;
            goto out;
        }
    }

    if (entry->n_candidates >= RIB_MAX_CANDIDATES) { rc = -ENOSPC; goto out; }

    {
        rib_candidate_t *c = &entry->candidates[entry->n_candidates++];
        memset(c, 0, sizeof(*c));
        c->nexthop    = nh;
        c->metric     = metric;
        c->source     = source;
        c->admin_dist = ad;
        if (iface && iface[0])
            strncpy(c->iface, iface, FIB_IFNAME_LEN - 1);
    }

    reselect_locked(rib, entry, had ? &old_snap : NULL, cb, ctx);
    rib->n_added++;

out:
    pthread_rwlock_unlock(&rib->lock);
    return rc;
}

/* ═══════════════════════════════════════════════════════════════
 * rib_del — O(1) average, thread-safe
 * ═══════════════════════════════════════════════════════════════ */
int rib_del(rib_table_t *rib,
            const char  *prefix_cidr,
            const char  *nexthop_str,
            rib_source_t source,
            rib_fib_cb   cb, void *ctx)
{
    uint32_t pfx; uint8_t len;
    if (fib_parse_cidr(prefix_cidr, &pfx, &len) != 0) return -EINVAL;

    struct in_addr nh_in;
    uint32_t nh = 0;
    int match_nh = (nexthop_str && nexthop_str[0] &&
                    inet_pton(AF_INET, nexthop_str, &nh_in) == 1);
    if (match_nh) nh = ntohl(nh_in.s_addr);

    int rc = -ENOENT;
    pthread_rwlock_wrlock(&rib->lock);

    rib_entry_t *entry = entry_find_locked(rib, pfx, len);
    if (!entry) goto out;

    rib_candidate_t old_snap;
    const rib_candidate_t *ob = rib_best(entry);
    int had = (ob != NULL);
    if (had) old_snap = *ob;

    int removed = 0;
    for (int i = 0; i < entry->n_candidates; ) {
        rib_candidate_t *c = &entry->candidates[i];
        int match = (c->source == source ||
                     source == RIB_SRC_UNKNOWN) &&
                    (!match_nh || c->nexthop == nh);
        if (match) {
            entry->candidates[i] = entry->candidates[--entry->n_candidates];
            removed++;
        } else { i++; }
    }
    if (!removed) goto out;

    reselect_locked(rib, entry, had ? &old_snap : NULL, cb, ctx);
    rib->n_deleted += (uint64_t)removed;
    rc = 0;

    /* remove entry if no candidates remain */
    if (entry->n_candidates == 0) {
        uint32_t idx = rib_hash(pfx, len, rib->n_buckets);
        rib_entry_t **pp = &rib->buckets[idx];
        while (*pp && *pp != entry) pp = &(*pp)->next;
        if (*pp) {
            *pp = entry->next;
            rib->count--;
            memset(entry, 0, sizeof(*entry));
            entry->next = rib->free_list;
            rib->free_list = entry;
        }
    }

out:
    pthread_rwlock_unlock(&rib->lock);
    return rc;
}

/* ═══════════════════════════════════════════════════════════════
 * rib_find — O(1) average, thread-safe (read lock)
 * ═══════════════════════════════════════════════════════════════ */
int rib_find(const rib_table_t *rib,
             const char *prefix_cidr, rib_entry_t *out)
{
    uint32_t pfx; uint8_t len;
    if (fib_parse_cidr(prefix_cidr, &pfx, &len) != 0) return -1;

    pthread_rwlock_rdlock((pthread_rwlock_t *)&rib->lock);
    rib_entry_t *e = entry_find_locked((rib_table_t *)rib, pfx, len);
    int rc = -1;
    if (e && out) { *out = *e; rc = 0; }
    pthread_rwlock_unlock((pthread_rwlock_t *)&rib->lock);
    return rc;
}

/* ═══════════════════════════════════════════════════════════════
 * Human-readable dump — takes read lock
 * ═══════════════════════════════════════════════════════════════ */
void rib_entry_to_str(const rib_entry_t *e, char *buf, size_t sz)
{
    struct in_addr pfx_in = { htonl(e->prefix) };
    char ps[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &pfx_in, ps, sizeof(ps));

    int pos = snprintf(buf, sz, "%s/%u (%d candidates)\n",
                       ps, e->prefix_len, e->n_candidates);
    for (int i = 0; i < e->n_candidates && pos < (int)sz - 80; i++) {
        const rib_candidate_t *c = &e->candidates[i];
        struct in_addr nh_in = { htonl(c->nexthop) };
        char ns[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &nh_in, ns, sizeof(ns));
        pos += snprintf(buf + pos, sz - (size_t)pos,
            "  %s via %s dev %s metric %u ad %u%s\n",
            RIB_SRC_NAME[c->source], ns, c->iface,
            c->metric, c->admin_dist,
            c->active ? " *" : "");
    }
}
