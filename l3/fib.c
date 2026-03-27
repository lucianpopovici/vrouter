#include "fib.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>

/* ═══════════════════════════════════════════════════════════════
 * Hash: FNV-1a over prefix(u32) + prefix_len(u8)
 * ═══════════════════════════════════════════════════════════════ */
static inline uint32_t fib_hash(uint32_t prefix, uint8_t len,
                                 uint32_t n_buckets)
{
    uint32_t h = 2166136261u;
    h ^= (prefix >> 24) & 0xFF; h *= 16777619u;
    h ^= (prefix >> 16) & 0xFF; h *= 16777619u;
    h ^= (prefix >>  8) & 0xFF; h *= 16777619u;
    h ^= (prefix >>  0) & 0xFF; h *= 16777619u;
    h ^= len;                    h *= 16777619u;
    return h & (n_buckets - 1);
}

/* ═══════════════════════════════════════════════════════════════
 * Init / Destroy
 * ═══════════════════════════════════════════════════════════════ */
void fib_init(fib_table_t *fib)
{
    memset(fib, 0, sizeof(*fib));
    fib->n_buckets  = FIB_BUCKETS;
    fib->pool_size  = FIB_POOL_DEFAULT;
    fib->max_routes = FIB_POOL_DEFAULT;

    fib->buckets = calloc(fib->n_buckets, sizeof(fib_entry_t *));
    fib->pool    = calloc(fib->pool_size,  sizeof(fib_entry_t));

    if (!fib->buckets || !fib->pool) {
        free(fib->buckets); free(fib->pool);
        fib->buckets = NULL; fib->pool = NULL;
    }
    pthread_rwlock_init(&fib->lock, NULL);
}

void fib_destroy(fib_table_t *fib)
{
    pthread_rwlock_destroy(&fib->lock);
    free(fib->buckets);
    free(fib->pool);
    fib->buckets = NULL;
    fib->pool    = NULL;
}

/* ═══════════════════════════════════════════════════════════════
 * CIDR parser
 * ═══════════════════════════════════════════════════════════════ */
int fib_parse_cidr(const char *cidr, uint32_t *prefix, uint8_t *len)
{
    char buf[32];
    if (!cidr || strlen(cidr) >= sizeof(buf)) return -1;
    strncpy(buf, cidr, sizeof(buf) - 1);
    buf[sizeof(buf)-1] = '\0';

    char *slash = strchr(buf, '/');
    if (slash) {
        *slash = '\0';
        int l = atoi(slash + 1);
        if (l < 0 || l > 32) return -1;
        *len = (uint8_t)l;
    } else {
        *len = 32;
    }

    struct in_addr in;
    if (inet_pton(AF_INET, buf, &in) != 1) return -1;
    *prefix = ntohl(in.s_addr);
    if (*len < 32) *prefix &= (0xFFFFFFFFu << (32 - *len));
    return 0;
}

/* ═══════════════════════════════════════════════════════════════
 * Pool allocator (caller holds write lock)
 * ═══════════════════════════════════════════════════════════════ */
static fib_entry_t *pool_alloc(fib_table_t *fib)
{
    if (!fib->pool || fib->pool_used >= fib->pool_size) return NULL;
    fib_entry_t *e = &fib->pool[fib->pool_used++];
    memset(e, 0, sizeof(*e));
    return e;
}

/* ═══════════════════════════════════════════════════════════════
 * Internal find (caller holds any lock)
 * ═══════════════════════════════════════════════════════════════ */
static fib_entry_t *entry_find(fib_table_t *fib,
                                uint32_t prefix, uint8_t len)
{
    if (!fib->buckets) return NULL;
    uint32_t idx = fib_hash(prefix, len, fib->n_buckets);
    fib_entry_t *e = fib->buckets[idx];
    while (e) {
        if (e->prefix == prefix && e->prefix_len == len) return e;
        e = e->next;
    }
    return NULL;
}

/* ═══════════════════════════════════════════════════════════════
 * fib_add — O(1) average
 * ═══════════════════════════════════════════════════════════════ */
int fib_add(fib_table_t *fib, const char *prefix_cidr,
            const char *nexthop_str, const char *iface,
            uint32_t metric, uint32_t flags)
{
    uint32_t pfx; uint8_t len;
    if (fib_parse_cidr(prefix_cidr, &pfx, &len) != 0) return -EINVAL;

    struct in_addr nh_in;
    if (inet_pton(AF_INET, nexthop_str, &nh_in) != 1) return -EINVAL;
    uint32_t nh = ntohl(nh_in.s_addr);

    int rc = 0;
    pthread_rwlock_wrlock(&fib->lock);

    fib_entry_t *e = entry_find(fib, pfx, len);
    if (e) {
        /* update existing */
        e->nexthop = nh;
        strncpy(e->iface, iface, FIB_IFNAME_LEN - 1);
        e->metric  = metric;
        e->flags   = flags | FIB_FLAG_ACTIVE;
        goto out;
    }

    if ((uint32_t)fib->count >= fib->max_routes) { rc = -ENOMEM; goto out; }

    e = pool_alloc(fib);
    if (!e) { rc = -ENOMEM; goto out; }

    e->prefix     = pfx;
    e->prefix_len = len;
    e->nexthop    = nh;
    strncpy(e->iface, iface, FIB_IFNAME_LEN - 1);
    e->metric     = metric;
    e->flags      = flags | FIB_FLAG_ACTIVE;
    e->hit_count  = 0;
    {
        uint32_t idx = fib_hash(pfx, len, fib->n_buckets);
        e->next           = fib->buckets[idx];
        fib->buckets[idx] = e;
        fib->count++;
    }

out:
    pthread_rwlock_unlock(&fib->lock);
    return rc;
}

/* ═══════════════════════════════════════════════════════════════
 * fib_del — O(1) average
 * ═══════════════════════════════════════════════════════════════ */
int fib_del(fib_table_t *fib, const char *prefix_cidr)
{
    uint32_t pfx; uint8_t len;
    if (fib_parse_cidr(prefix_cidr, &pfx, &len) != 0) return -EINVAL;

    int rc = -ENOENT;
    pthread_rwlock_wrlock(&fib->lock);

    if (fib->buckets) {
        uint32_t idx = fib_hash(pfx, len, fib->n_buckets);
        fib_entry_t **pp = &fib->buckets[idx];
        while (*pp) {
            fib_entry_t *e = *pp;
            if (e->prefix == pfx && e->prefix_len == len) {
                *pp = e->next;
                memset(e, 0, sizeof(*e));
                fib->count--;
                rc = 0;
                break;
            }
            pp = &e->next;
        }
    }

    pthread_rwlock_unlock(&fib->lock);
    return rc;
}

/* ═══════════════════════════════════════════════════════════════
 * fib_lookup — LPM, O(prefix_len) hash lookups
 * Walk /32 → /0 to find longest matching prefix.
 * For typical routing tables (a few thousand routes) with a
 * well-distributed hash, each lookup is effectively O(1).
 * ═══════════════════════════════════════════════════════════════ */
const fib_entry_t *fib_lookup(fib_table_t *fib, const char *addr_str)
{
    struct in_addr in;
    if (inet_pton(AF_INET, addr_str, &in) != 1) return NULL;
    uint32_t addr = ntohl(in.s_addr);

    pthread_rwlock_rdlock(&fib->lock);
    fib->total_lookups++;

    const fib_entry_t *best = NULL;

    /* Walk from most-specific (/32) to least-specific (/0) */
    for (int l = 32; l >= 0; l--) {
        uint32_t mask = (l == 0) ? 0 : (0xFFFFFFFFu << (32 - l));
        uint32_t pfx  = addr & mask;
        const fib_entry_t *e = entry_find(fib, pfx, (uint8_t)l);
        if (e && (e->flags & FIB_FLAG_ACTIVE)) {
            best = e;
            break;   /* longest match found */
        }
    }

    if (best) {
        ((fib_entry_t *)best)->hit_count++;
        fib->total_hits++;
    }

    pthread_rwlock_unlock(&fib->lock);
    return best;
}

/* ═══════════════════════════════════════════════════════════════
 * fib_flush
 * ═══════════════════════════════════════════════════════════════ */
void fib_flush(fib_table_t *fib)
{
    pthread_rwlock_wrlock(&fib->lock);
    if (fib->buckets)
        memset(fib->buckets, 0, fib->n_buckets * sizeof(fib_entry_t *));
    if (fib->pool)
        memset(fib->pool, 0, fib->pool_used * sizeof(fib_entry_t));
    fib->pool_used     = 0;
    fib->count         = 0;
    fib->total_lookups = 0;
    fib->total_hits    = 0;
    pthread_rwlock_unlock(&fib->lock);
}

/* ═══════════════════════════════════════════════════════════════
 * fib_count
 * ═══════════════════════════════════════════════════════════════ */
int fib_count(const fib_table_t *fib)
{
    pthread_rwlock_rdlock((pthread_rwlock_t *)&fib->lock);
    int c = fib->count;
    pthread_rwlock_unlock((pthread_rwlock_t *)&fib->lock);
    return c;
}

/* ═══════════════════════════════════════════════════════════════
 * fib_iterate — snapshot all entries under read lock
 * ═══════════════════════════════════════════════════════════════ */
void fib_iterate(fib_table_t *fib, fib_iter_cb cb, void *ctx)
{
    pthread_rwlock_rdlock(&fib->lock);
    if (fib->buckets) {
        for (uint32_t i = 0; i < fib->n_buckets; i++) {
            const fib_entry_t *e = fib->buckets[i];
            while (e) { cb(e, ctx); e = e->next; }
        }
    }
    pthread_rwlock_unlock(&fib->lock);
}

/* ═══════════════════════════════════════════════════════════════
 * fib_entry_to_str
 * ═══════════════════════════════════════════════════════════════ */
void fib_entry_to_str(const fib_entry_t *e, char *buf, size_t bufsz)
{
    struct in_addr pfx_in = { htonl(e->prefix) };
    struct in_addr nh_in  = { htonl(e->nexthop) };
    char pfx_s[INET_ADDRSTRLEN], nh_s[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &pfx_in, pfx_s, sizeof(pfx_s));
    inet_ntop(AF_INET, &nh_in,  nh_s,  sizeof(nh_s));
    snprintf(buf, bufsz, "%s/%u via %s dev %s metric %u hits %llu",
             pfx_s, e->prefix_len, nh_s, e->iface, e->metric,
             (unsigned long long)e->hit_count);
}
