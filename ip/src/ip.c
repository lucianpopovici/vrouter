/*
 * ip.c — IPv4/IPv6 address + ECMP forwarding module
 *
 * Each ip_fwd_entry_t now holds a nexthop group of 1..IP_ECMP_MAX_PATHS
 * paths. Path selection for a given flow is done in ip_ecmp_select() using
 * a weighted FNV-1a hash over configurable flow fields.
 *
 * Locking: fwd_table.lock (rwlock) guards the bucket array; individual
 * ip_fwd_entry_t objects are mutated only under a write-lock on the table.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <pthread.h>

#include "ip.h"
#include "ip_ipc.h"

/* -----------------------------------------------------------------------
 * FNV-1a helpers
 * --------------------------------------------------------------------- */
#define FNV_OFFSET  2166136261u
#define FNV_PRIME   16777619u

static uint32_t fnv1a(const uint8_t *data, size_t len, uint32_t n_buckets)
{
    uint32_t h = FNV_OFFSET;
    for (size_t i = 0; i < len; i++) { h ^= data[i]; h *= FNV_PRIME; }
    return h % n_buckets;
}

uint32_t ip_fnv1a_addr(const ip_addr_t *addr, uint32_t n_buckets)
{
    if (addr->af == AF_INET)
        return fnv1a((const uint8_t *)&addr->u.v4, 4, n_buckets);
    return fnv1a((const uint8_t *)&addr->u.v6, 16, n_buckets);
}

uint32_t ip_fnv1a_prefix(const ip_prefix_t *pfx, uint32_t n_buckets)
{
    uint8_t buf[17];
    size_t  alen = (pfx->addr.af == AF_INET) ? 4 : 16;
    if (pfx->addr.af == AF_INET) memcpy(buf, &pfx->addr.u.v4, 4);
    else                         memcpy(buf, &pfx->addr.u.v6, 16);
    buf[alen] = pfx->plen;
    return fnv1a(buf, alen + 1, n_buckets);
}

/* Flow hash: hash over whichever fields are enabled in ecmp_hash_mode */
static uint32_t flow_hash(const ip_fwd_entry_t *entry,
                          const ip_flow_key_t  *flow)
{
    uint32_t mode = entry->ecmp_hash_mode
                  ? entry->ecmp_hash_mode
                  : IP_ECMP_HASH_DEFAULT;
    uint32_t h = FNV_OFFSET;

#define MIX(data, len) do { \
    for (size_t _i = 0; _i < (len); _i++) { \
        h ^= ((const uint8_t *)(data))[_i]; h *= FNV_PRIME; \
    } \
} while(0)

    if (!flow) {
        /* no flow key: hash on prefix only for deterministic single-path */
        if (entry->prefix.addr.af == AF_INET)
            MIX(&entry->prefix.addr.u.v4, 4);
        else
            MIX(&entry->prefix.addr.u.v6, 16);
        return h;
    }

    if ((mode & IP_ECMP_HASH_SRC_IP) && flow->src.af == AF_INET)
        MIX(&flow->src.u.v4, 4);
    else if ((mode & IP_ECMP_HASH_SRC_IP) && flow->src.af == AF_INET6)
        MIX(&flow->src.u.v6, 16);

    if ((mode & IP_ECMP_HASH_DST_IP) && flow->dst.af == AF_INET)
        MIX(&flow->dst.u.v4, 4);
    else if ((mode & IP_ECMP_HASH_DST_IP) && flow->dst.af == AF_INET6)
        MIX(&flow->dst.u.v6, 16);

    if (mode & IP_ECMP_HASH_SRC_PORT) MIX(&flow->src_port, 2);
    if (mode & IP_ECMP_HASH_DST_PORT) MIX(&flow->dst_port, 2);
    if (mode & IP_ECMP_HASH_PROTO)    MIX(&flow->proto,    1);

#undef MIX
    return h;
}

/*
 * ip_ecmp_select — weighted path selection.
 *
 * Builds a virtual slot array of total_weight slots, maps hash → slot,
 * then walks paths to find which path owns that slot.
 * Inactive paths are skipped (their weight is not counted).
 * Returns index into entry->paths[].
 * Returns 0 if no active paths (caller must handle).
 */
uint8_t ip_ecmp_select(const ip_fwd_entry_t *entry,
                       const ip_flow_key_t  *flow)
{
    uint32_t total = 0;
    for (uint8_t i = 0; i < entry->n_paths; i++)
        if (entry->paths[i].active)
            total += entry->paths[i].weight ? entry->paths[i].weight : 1;

    if (total == 0) return 0;

    uint32_t h   = flow_hash(entry, flow) % total;
    uint32_t acc = 0;
    for (uint8_t i = 0; i < entry->n_paths; i++) {
        if (!entry->paths[i].active) continue;
        acc += entry->paths[i].weight ? entry->paths[i].weight : 1;
        if (h < acc) return i;
    }
    return 0;
}

/* -----------------------------------------------------------------------
 * Address helpers
 * --------------------------------------------------------------------- */
int ip_addr_parse(const char *str, ip_addr_t *out)
{
    if (!str || !out) return IP_ERR_INVAL;
    if (inet_pton(AF_INET,  str, &out->u.v4) == 1) { out->af = AF_INET;  return IP_OK; }
    if (inet_pton(AF_INET6, str, &out->u.v6) == 1) { out->af = AF_INET6; return IP_OK; }
    return IP_ERR_INVAL;
}

int ip_prefix_parse(const char *str, ip_prefix_t *out)
{
    if (!str || !out) return IP_ERR_INVAL;
    char buf[INET6_ADDRSTRLEN + 4];
    strncpy(buf, str, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    char *slash = strchr(buf, '/');
    int plen = -1;
    if (slash) { *slash = '\0'; plen = atoi(slash + 1); }
    if (ip_addr_parse(buf, &out->addr) != IP_OK) return IP_ERR_INVAL;
    uint8_t maxp = (out->addr.af == AF_INET) ? IPV4_MAX_PREFIXLEN : IPV6_MAX_PREFIXLEN;
    if (plen < 0 || plen > maxp) plen = maxp;
    out->plen = (uint8_t)plen;
    return IP_OK;
}

void ip_addr_to_str(const ip_addr_t *addr, char *buf, size_t len)
{
    if (addr->af == AF_INET) inet_ntop(AF_INET,  &addr->u.v4, buf, len);
    else                     inet_ntop(AF_INET6, &addr->u.v6, buf, len);
}

void ip_prefix_to_str(const ip_prefix_t *pfx, char *buf, size_t len)
{
    char ab[INET6_ADDRSTRLEN];
    ip_addr_to_str(&pfx->addr, ab, sizeof(ab));
    snprintf(buf, len, "%s/%u", ab, pfx->plen);
}

bool ip_prefix_contains(const ip_prefix_t *pfx, const ip_addr_t *addr)
{
    if (pfx->addr.af != addr->af) return false;
    uint8_t plen = pfx->plen;
    if (addr->af == AF_INET) {
        uint32_t mask = plen ? htonl(~0u << (32 - plen)) : 0;
        return (addr->u.v4.s_addr & mask) == (pfx->addr.u.v4.s_addr & mask);
    }
    uint8_t full = plen / 8, rem = plen % 8;
    const uint8_t *a = addr->u.v6.s6_addr, *p = pfx->addr.u.v6.s6_addr;
    if (memcmp(a, p, full) != 0) return false;
    if (!rem) return true;
    uint8_t mask = (uint8_t)(0xffu << (8 - rem));
    return (a[full] & mask) == (p[full] & mask);
}

bool ip_is_martian_v4(const struct in_addr *addr)
{
    uint32_t a = ntohl(addr->s_addr);
    if ((a >> 24) == 0)      return true;
    if ((a >> 24) == 127)    return true;
    if ((a >> 16) == 0xa9fe) return true;
    if ((a >> 8)  == (0xc0000200u >> 8)) return true;
    if ((a >> 8)  == (0xc6336400u >> 8)) return true;
    if ((a >> 8)  == (0xcb007100u >> 8)) return true;
    if ((a >> 28) == 0xf)    return true;
    return false;
}

bool ip_is_martian_v6(const struct in6_addr *addr)
{
    static const uint8_t lo[16]  = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
    static const uint8_t any[16] = {0};
    if (memcmp(addr->s6_addr, lo,  16) == 0) return true;
    if (memcmp(addr->s6_addr, any, 16) == 0) return true;
    if (addr->s6_addr[0]==0x20 && addr->s6_addr[1]==0x01 &&
        addr->s6_addr[2]==0x0d && addr->s6_addr[3]==0xb8) return true;
    return false;
}

bool ip_is_loopback(const ip_addr_t *addr)
{
    if (addr->af == AF_INET)
        return (ntohl(addr->u.v4.s_addr) >> 24) == 127;
    static const uint8_t lo[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
    return memcmp(addr->u.v6.s6_addr, lo, 16) == 0;
}

bool ip_is_link_local(const ip_addr_t *addr)
{
    if (addr->af == AF_INET)
        return (ntohl(addr->u.v4.s_addr) >> 16) == 0xa9fe;
    return addr->u.v6.s6_addr[0] == 0xfe &&
           (addr->u.v6.s6_addr[1] & 0xc0) == 0x80;
}

bool ip_is_multicast(const ip_addr_t *addr)
{
    if (addr->af == AF_INET)
        return (ntohl(addr->u.v4.s_addr) >> 28) == 0xe;
    return addr->u.v6.s6_addr[0] == 0xff;
}

/* -----------------------------------------------------------------------
 * Interface table
 * --------------------------------------------------------------------- */
static int if_table_init(ip_if_table_t *t)
{
    t->n_buckets = IP_IF_TABLE_BUCKETS;
    t->buckets   = calloc(t->n_buckets, sizeof(*t->buckets));
    if (!t->buckets) return IP_ERR_NOMEM;
    t->n_entries = 0;
    return pthread_rwlock_init(&t->lock, NULL) ? IP_ERR_NOMEM : IP_OK;
}

static void if_table_destroy(ip_if_table_t *t)
{
    for (uint32_t i = 0; i < t->n_buckets; i++) {
        ip_interface_t *c = t->buckets[i];
        while (c) {
            ip_interface_t *n = c->next;
            ip_if_addr_t *a = c->addrs;
            while (a) { ip_if_addr_t *an = a->next; free(a); a = an; }
            pthread_rwlock_destroy(&c->lock);
            free(c);
            c = n;
        }
    }
    free(t->buckets);
    pthread_rwlock_destroy(&t->lock);
}

static uint32_t if_bucket(const ip_if_table_t *t, uint32_t ifindex)
{
    return fnv1a((const uint8_t *)&ifindex, sizeof(ifindex), t->n_buckets);
}

int ip_if_add(ip_ctx_t *ctx, const char *name, uint32_t ifindex,
              uint32_t flags, uint32_t mtu, const uint8_t mac[6])
{
    if (!ctx || !name) return IP_ERR_INVAL;
    ip_if_table_t *t = &ctx->if_table;
    uint32_t b = if_bucket(t, ifindex);
    int rc = IP_OK;

    pthread_rwlock_wrlock(&t->lock);
    for (ip_interface_t *c = t->buckets[b]; c; c = c->next)
        if (c->ifindex == ifindex) { rc = IP_ERR_EXISTS; goto out; }

    ip_interface_t *ifc = calloc(1, sizeof(*ifc));
    if (!ifc) { rc = IP_ERR_NOMEM; goto out; }
    strncpy(ifc->name, name, IFNAMSIZ - 1);
    ifc->ifindex = ifindex; ifc->flags = flags; ifc->mtu = mtu;
    ifc->ip6_hop_limit = 64;
    if (mac) memcpy(ifc->mac, mac, 6);
    pthread_rwlock_init(&ifc->lock, NULL);
    ifc->next = t->buckets[b]; t->buckets[b] = ifc; t->n_entries++;

out:
    pthread_rwlock_unlock(&t->lock);
    return rc;
}

int ip_if_del(ip_ctx_t *ctx, uint32_t ifindex)
{
    if (!ctx) return IP_ERR_INVAL;
    ip_if_table_t *t = &ctx->if_table;
    uint32_t b = if_bucket(t, ifindex);
    int rc = IP_ERR_NOTFOUND;

    pthread_rwlock_wrlock(&t->lock);
    ip_interface_t **pp = &t->buckets[b];
    while (*pp) {
        if ((*pp)->ifindex == ifindex) {
            ip_interface_t *del = *pp; *pp = del->next;
            ip_if_addr_t *a = del->addrs;
            while (a) { ip_if_addr_t *an = a->next; free(a); a = an; }
            pthread_rwlock_destroy(&del->lock);
            free(del); t->n_entries--; rc = IP_OK; break;
        }
        pp = &(*pp)->next;
    }
    pthread_rwlock_unlock(&t->lock);
    return rc;
}

ip_interface_t *ip_if_find(ip_ctx_t *ctx, uint32_t ifindex)
{
    if (!ctx) return NULL;
    ip_if_table_t *t = &ctx->if_table;
    uint32_t b = if_bucket(t, ifindex);
    ip_interface_t *found = NULL;
    pthread_rwlock_rdlock(&t->lock);
    for (ip_interface_t *c = t->buckets[b]; c; c = c->next)
        if (c->ifindex == ifindex) { found = c; break; }
    pthread_rwlock_unlock(&t->lock);
    return found;
}

ip_interface_t *ip_if_find_by_name(ip_ctx_t *ctx, const char *name)
{
    if (!ctx || !name) return NULL;
    ip_if_table_t *t = &ctx->if_table;
    ip_interface_t *found = NULL;
    pthread_rwlock_rdlock(&t->lock);
    for (uint32_t i = 0; i < t->n_buckets && !found; i++)
        for (ip_interface_t *c = t->buckets[i]; c; c = c->next)
            if (strcmp(c->name, name) == 0) { found = c; break; }
    pthread_rwlock_unlock(&t->lock);
    return found;
}

int ip_if_set_flags(ip_ctx_t *ctx, uint32_t ifindex, uint32_t flags)
{
    ip_interface_t *ifc = ip_if_find(ctx, ifindex);
    if (!ifc) return IP_ERR_NOTFOUND;
    pthread_rwlock_wrlock(&ifc->lock);
    ifc->flags = flags;
    pthread_rwlock_unlock(&ifc->lock);
    return IP_OK;
}

/* -----------------------------------------------------------------------
 * Address management
 * --------------------------------------------------------------------- */
int ip_addr_add(ip_ctx_t *ctx, uint32_t ifindex, const ip_prefix_t *pfx,
                uint32_t valid_lft, uint32_t pref_lft)
{
    if (!ctx || !pfx) return IP_ERR_INVAL;
    ip_interface_t *ifc = ip_if_find(ctx, ifindex);
    if (!ifc) return IP_ERR_NOTFOUND;

    int rc = IP_OK;
    pthread_rwlock_wrlock(&ifc->lock);

    for (ip_if_addr_t *a = ifc->addrs; a; a = a->next) {
        if (a->prefix.plen == pfx->plen && a->prefix.addr.af == pfx->addr.af &&
            memcmp(&a->prefix.addr.u, &pfx->addr.u,
                   pfx->addr.af == AF_INET ? 4 : 16) == 0) {
            rc = IP_ERR_EXISTS; goto out;
        }
    }
    if (ifc->n_addrs >= IP_MAX_ADDRS_PER_IF) { rc = IP_ERR_NOMEM; goto out; }

    ip_if_addr_t *entry = calloc(1, sizeof(*entry));
    if (!entry) { rc = IP_ERR_NOMEM; goto out; }
    entry->prefix = *pfx;
    entry->valid_lft = valid_lft; entry->pref_lft = pref_lft;
    entry->state = IP_ADDR_PREFERRED; entry->assigned_at = time(NULL);
    if (pfx->addr.af == AF_INET && pfx->plen < 32) {
        uint32_t mask = pfx->plen ? htonl(~0u << (32 - pfx->plen)) : 0;
        entry->broadcast.af = AF_INET;
        entry->broadcast.u.v4.s_addr = (pfx->addr.u.v4.s_addr & mask) | ~mask;
    }
    entry->next = ifc->addrs; ifc->addrs = entry; ifc->n_addrs++;

out:
    pthread_rwlock_unlock(&ifc->lock);
    return rc;
}

int ip_addr_del(ip_ctx_t *ctx, uint32_t ifindex, const ip_prefix_t *pfx)
{
    if (!ctx || !pfx) return IP_ERR_INVAL;
    ip_interface_t *ifc = ip_if_find(ctx, ifindex);
    if (!ifc) return IP_ERR_NOTFOUND;

    int rc = IP_ERR_NOTFOUND;
    pthread_rwlock_wrlock(&ifc->lock);
    ip_if_addr_t **pp = &ifc->addrs;
    while (*pp) {
        ip_if_addr_t *a = *pp;
        if (a->prefix.plen == pfx->plen && a->prefix.addr.af == pfx->addr.af &&
            memcmp(&a->prefix.addr.u, &pfx->addr.u,
                   pfx->addr.af == AF_INET ? 4 : 16) == 0) {
            *pp = a->next; free(a); ifc->n_addrs--; rc = IP_OK; break;
        }
        pp = &(*pp)->next;
    }
    pthread_rwlock_unlock(&ifc->lock);
    return rc;
}

/* -----------------------------------------------------------------------
 * Forwarding table internals
 * --------------------------------------------------------------------- */
static int fwd_table_init(ip_fwd_table_t *t)
{
    t->n_buckets = IP_ADDR_TABLE_BUCKETS;
    t->buckets   = calloc(t->n_buckets, sizeof(*t->buckets));
    if (!t->buckets) return IP_ERR_NOMEM;
    t->n_entries = 0;
    return pthread_rwlock_init(&t->lock, NULL) ? IP_ERR_NOMEM : IP_OK;
}

static void fwd_table_destroy(ip_fwd_table_t *t)
{
    for (uint32_t i = 0; i < t->n_buckets; i++) {
        ip_fwd_entry_t *c = t->buckets[i];
        while (c) { ip_fwd_entry_t *n = c->next; free(c); c = n; }
    }
    free(t->buckets);
    pthread_rwlock_destroy(&t->lock);
}

/* Find entry for a prefix (caller holds at least rdlock on table) */
static ip_fwd_entry_t *fwd_find_locked(ip_fwd_table_t *t,
                                       const ip_prefix_t *pfx)
{
    uint32_t b = ip_fnv1a_prefix(pfx, t->n_buckets);
    for (ip_fwd_entry_t *e = t->buckets[b]; e; e = e->next) {
        if (e->prefix.plen == pfx->plen &&
            e->prefix.addr.af == pfx->addr.af &&
            memcmp(&e->prefix.addr.u, &pfx->addr.u,
                   pfx->addr.af == AF_INET ? 4 : 16) == 0)
            return e;
    }
    return NULL;
}

/* nexthop addr+ifindex equality */
static bool nh_eq(const ip_nexthop_t *a,
                  const ip_addr_t *addr, uint32_t ifindex)
{
    if (a->ifindex != ifindex || a->addr.af != addr->af) return false;
    return memcmp(&a->addr.u, &addr->u,
                  addr->af == AF_INET ? 4 : 16) == 0;
}

/* -----------------------------------------------------------------------
 * Public forwarding table API
 * --------------------------------------------------------------------- */

/*
 * ip_fwd_add — add or update a route.
 * If the prefix already exists: if the new AD is strictly better, replace
 * the whole nexthop group; if AD is equal, just add the path if not already
 * present. weight=0 is treated as 1.
 */
int ip_fwd_add(ip_ctx_t *ctx, const ip_prefix_t *pfx,
               const ip_addr_t *nexthop, uint32_t out_ifindex,
               uint8_t ad, uint32_t metric, uint32_t weight)
{
    if (!ctx || !pfx) return IP_ERR_INVAL;
    ip_fwd_table_t *t = (pfx->addr.af == AF_INET) ? &ctx->fwd4 : &ctx->fwd6;
    uint32_t b = ip_fnv1a_prefix(pfx, t->n_buckets);
    if (!weight) weight = 1;
    int rc = IP_OK;

    pthread_rwlock_wrlock(&t->lock);
    ip_fwd_entry_t *e = fwd_find_locked(t, pfx);

    if (e) {
        if (ad < e->ad) {
            /* Better AD: replace entire nexthop group */
            e->ad = ad; e->metric = metric;
            memset(e->paths, 0, sizeof(e->paths));
            e->n_paths = 1;
            if (nexthop) e->paths[0].addr = *nexthop;
            e->paths[0].ifindex = out_ifindex;
            e->paths[0].weight  = weight;
            e->paths[0].active  = true;
        } else if (ad == e->ad) {
            /* Same AD: add path to ECMP group if not duplicate */
            for (uint8_t i = 0; i < e->n_paths; i++)
                if (nh_eq(&e->paths[i], nexthop, out_ifindex)) goto out;
            if (e->n_paths >= IP_ECMP_MAX_PATHS) { rc = IP_ERR_FULL; goto out; }
            uint8_t idx = e->n_paths++;
            if (nexthop) e->paths[idx].addr = *nexthop;
            e->paths[idx].ifindex = out_ifindex;
            e->paths[idx].weight  = weight;
            e->paths[idx].active  = true;
        }
        /* Worse AD: ignore */
        goto out;
    }

    /* New entry */
    if (t->n_entries >= IP_MAX_STATIC_ROUTES) { rc = IP_ERR_NOMEM; goto out; }
    e = calloc(1, sizeof(*e));
    if (!e) { rc = IP_ERR_NOMEM; goto out; }
    e->prefix = *pfx; e->ad = ad; e->metric = metric;
    e->n_paths = 1;
    if (nexthop) e->paths[0].addr = *nexthop;
    e->paths[0].ifindex = out_ifindex;
    e->paths[0].weight  = weight;
    e->paths[0].active  = true;
    pthread_rwlock_rdlock(&ctx->cfg.lock);
    e->ecmp_hash_mode = ctx->cfg.ecmp_hash_mode;
    pthread_rwlock_unlock(&ctx->cfg.lock);
    e->installed_at = time(NULL);
    e->next = t->buckets[b]; t->buckets[b] = e; t->n_entries++;

out:
    pthread_rwlock_unlock(&t->lock);
    return rc;
}

int ip_nexthop_add(ip_ctx_t *ctx, const ip_prefix_t *pfx,
                   const ip_addr_t *nexthop, uint32_t out_ifindex,
                   uint32_t weight)
{
    if (!ctx || !pfx || !nexthop) return IP_ERR_INVAL;
    ip_fwd_table_t *t = (pfx->addr.af == AF_INET) ? &ctx->fwd4 : &ctx->fwd6;
    if (!weight) weight = 1;
    int rc = IP_ERR_NOTFOUND;

    pthread_rwlock_wrlock(&t->lock);
    ip_fwd_entry_t *e = fwd_find_locked(t, pfx);
    if (!e) goto out;

    for (uint8_t i = 0; i < e->n_paths; i++)
        if (nh_eq(&e->paths[i], nexthop, out_ifindex)) {
            /* already present — update weight */
            e->paths[i].weight = weight;
            e->paths[i].active = true;
            rc = IP_OK; goto out;
        }
    if (e->n_paths >= IP_ECMP_MAX_PATHS) { rc = IP_ERR_FULL; goto out; }
    uint8_t idx = e->n_paths++;
    e->paths[idx].addr    = *nexthop;
    e->paths[idx].ifindex = out_ifindex;
    e->paths[idx].weight  = weight;
    e->paths[idx].active  = true;
    rc = IP_OK;

out:
    pthread_rwlock_unlock(&t->lock);
    return rc;
}

int ip_nexthop_del(ip_ctx_t *ctx, const ip_prefix_t *pfx,
                   const ip_addr_t *nexthop, uint32_t out_ifindex)
{
    if (!ctx || !pfx || !nexthop) return IP_ERR_INVAL;
    ip_fwd_table_t *t = (pfx->addr.af == AF_INET) ? &ctx->fwd4 : &ctx->fwd6;
    int rc = IP_ERR_NOTFOUND;

    pthread_rwlock_wrlock(&t->lock);
    ip_fwd_entry_t *e = fwd_find_locked(t, pfx);
    if (!e) goto out;

    for (uint8_t i = 0; i < e->n_paths; i++) {
        if (!nh_eq(&e->paths[i], nexthop, out_ifindex)) continue;
        /* Shift remaining paths down */
        memmove(&e->paths[i], &e->paths[i+1],
                (e->n_paths - i - 1) * sizeof(ip_nexthop_t));
        memset(&e->paths[e->n_paths - 1], 0, sizeof(ip_nexthop_t));
        e->n_paths--;
        rc = IP_OK;

        /* If last path removed, delete the whole entry */
        if (e->n_paths == 0) {
            uint32_t b = ip_fnv1a_prefix(pfx, t->n_buckets);
            ip_fwd_entry_t **pp = &t->buckets[b];
            while (*pp && *pp != e) pp = &(*pp)->next;
            if (*pp) { *pp = e->next; free(e); t->n_entries--; }
        }
        goto out;
    }

out:
    pthread_rwlock_unlock(&t->lock);
    return rc;
}

int ip_fwd_del(ip_ctx_t *ctx, const ip_prefix_t *pfx)
{
    if (!ctx || !pfx) return IP_ERR_INVAL;
    ip_fwd_table_t *t = (pfx->addr.af == AF_INET) ? &ctx->fwd4 : &ctx->fwd6;
    uint32_t b = ip_fnv1a_prefix(pfx, t->n_buckets);
    int rc = IP_ERR_NOTFOUND;

    pthread_rwlock_wrlock(&t->lock);
    ip_fwd_entry_t **pp = &t->buckets[b];
    while (*pp) {
        ip_fwd_entry_t *e = *pp;
        if (e->prefix.plen == pfx->plen &&
            e->prefix.addr.af == pfx->addr.af &&
            memcmp(&e->prefix.addr.u, &pfx->addr.u,
                   pfx->addr.af == AF_INET ? 4 : 16) == 0) {
            *pp = e->next; free(e); t->n_entries--; rc = IP_OK; break;
        }
        pp = &(*pp)->next;
    }
    pthread_rwlock_unlock(&t->lock);
    return rc;
}

/*
 * ip_fwd_lookup — LPM + ECMP path selection.
 * Finds the longest-prefix match, then selects a path using the flow hash.
 */
int ip_fwd_lookup(ip_ctx_t *ctx, const ip_addr_t *dst,
                  const ip_flow_key_t *flow,
                  ip_fwd_entry_t *entry_out,
                  ip_nexthop_t   *path_out)
{
    if (!ctx || !dst) return IP_ERR_INVAL;
    ip_fwd_table_t *t = (dst->af == AF_INET) ? &ctx->fwd4 : &ctx->fwd6;
    int rc = IP_ERR_NOTFOUND;
    ip_fwd_entry_t *best = NULL;

    pthread_rwlock_rdlock(&t->lock);
    for (uint32_t i = 0; i < t->n_buckets; i++) {
        for (ip_fwd_entry_t *e = t->buckets[i]; e; e = e->next) {
            if (!ip_prefix_contains(&e->prefix, dst)) continue;
            if (!best ||
                e->prefix.plen > best->prefix.plen ||
                (e->prefix.plen == best->prefix.plen && e->ad < best->ad))
                best = e;
        }
    }

    if (best) {
        uint8_t idx = ip_ecmp_select(best, flow);
        best->hit_count++;
        best->paths[idx].hit_count++;
        if (entry_out) *entry_out = *best;
        if (path_out)  *path_out  = best->paths[idx];
        rc = IP_OK;
    }
    pthread_rwlock_unlock(&t->lock);
    return rc;
}

int ip_set_ecmp_hash(ip_ctx_t *ctx, const ip_prefix_t *pfx, uint32_t mode)
{
    if (!ctx || !pfx) return IP_ERR_INVAL;
    ip_fwd_table_t *t = (pfx->addr.af == AF_INET) ? &ctx->fwd4 : &ctx->fwd6;
    int rc = IP_ERR_NOTFOUND;

    pthread_rwlock_wrlock(&t->lock);
    ip_fwd_entry_t *e = fwd_find_locked(t, pfx);
    if (e) { e->ecmp_hash_mode = mode; rc = IP_OK; }
    pthread_rwlock_unlock(&t->lock);
    return rc;
}

/* -----------------------------------------------------------------------
 * Forwarding configuration
 * --------------------------------------------------------------------- */
int ip_set_forwarding(ip_ctx_t *ctx, sa_family_t af, bool enable)
{
    if (!ctx) return IP_ERR_INVAL;
    pthread_rwlock_wrlock(&ctx->cfg.lock);
    if (af == AF_INET) ctx->cfg.ipv4_forwarding = enable;
    else               ctx->cfg.ipv6_forwarding = enable;
    pthread_rwlock_unlock(&ctx->cfg.lock);
    return IP_OK;
}

bool ip_get_forwarding(ip_ctx_t *ctx, sa_family_t af)
{
    if (!ctx) return false;
    pthread_rwlock_rdlock(&ctx->cfg.lock);
    bool v = (af == AF_INET) ? ctx->cfg.ipv4_forwarding : ctx->cfg.ipv6_forwarding;
    pthread_rwlock_unlock(&ctx->cfg.lock);
    return v;
}

int ip_set_fwd_flags(ip_ctx_t *ctx, uint32_t flags, bool enable)
{
    if (!ctx) return IP_ERR_INVAL;
    pthread_rwlock_wrlock(&ctx->cfg.lock);
    if (enable) ctx->cfg.flags |= flags; else ctx->cfg.flags &= ~flags;
    pthread_rwlock_unlock(&ctx->cfg.lock);
    return IP_OK;
}

int ip_set_if_forwarding(ip_ctx_t *ctx, uint32_t ifindex,
                         sa_family_t af, bool enable)
{
    ip_interface_t *ifc = ip_if_find(ctx, ifindex);
    if (!ifc) return IP_ERR_NOTFOUND;
    pthread_rwlock_wrlock(&ifc->lock);
    if (af == AF_INET) ifc->ip4_fwd = enable;
    else               ifc->ip6_fwd = enable;
    pthread_rwlock_unlock(&ifc->lock);
    return IP_OK;
}

/* -----------------------------------------------------------------------
 * Stats
 * --------------------------------------------------------------------- */
void ip_stats_get(ip_ctx_t *ctx, sa_family_t af, ip_stats_t *out)
{
    if (!ctx || !out) return;
    ip_stats_t *s = (af == AF_INET) ? &ctx->stats4 : &ctx->stats6;
    pthread_rwlock_rdlock(&s->lock);
    *out = *s;
    pthread_rwlock_unlock(&s->lock);
}

void ip_stats_clear(ip_ctx_t *ctx, sa_family_t af)
{
    if (!ctx) return;
    ip_stats_t *s = (af == AF_INET) ? &ctx->stats4 : &ctx->stats6;
    pthread_rwlock_wrlock(&s->lock);
    pthread_rwlock_t saved = s->lock;
    memset(s, 0, sizeof(*s));
    s->lock = saved;
    pthread_rwlock_unlock(&s->lock);
}

/* -----------------------------------------------------------------------
 * Persistence
 * --------------------------------------------------------------------- */
int ip_save_config(ip_ctx_t *ctx, const char *path)
{
    if (!ctx || !path) return IP_ERR_INVAL;
    char tmp[512];
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    FILE *f = fopen(tmp, "w");
    if (!f) return IP_ERR_INVAL;

    pthread_rwlock_rdlock(&ctx->cfg.lock);
    fprintf(f, "{\"type\":\"fwd_config\","
               "\"ipv4_fwd\":%s,\"ipv6_fwd\":%s,"
               "\"flags\":%u,\"default_ttl\":%u,"
               "\"default_hop_limit\":%u,\"ecmp_hash_mode\":%u}\n",
            ctx->cfg.ipv4_forwarding ? "true" : "false",
            ctx->cfg.ipv6_forwarding ? "true" : "false",
            ctx->cfg.flags, ctx->cfg.default_ttl,
            ctx->cfg.default_hop_limit, ctx->cfg.ecmp_hash_mode);
    pthread_rwlock_unlock(&ctx->cfg.lock);

    pthread_rwlock_rdlock(&ctx->if_table.lock);
    for (uint32_t i = 0; i < ctx->if_table.n_buckets; i++) {
        for (ip_interface_t *ifc = ctx->if_table.buckets[i]; ifc; ifc = ifc->next) {
            pthread_rwlock_rdlock(&ifc->lock);
            fprintf(f, "{\"type\":\"interface\","
                       "\"name\":\"%s\",\"ifindex\":%u,"
                       "\"flags\":%u,\"mtu\":%u,"
                       "\"mac\":\"%02x:%02x:%02x:%02x:%02x:%02x\","
                       "\"ip4_fwd\":%s,\"ip6_fwd\":%s}\n",
                    ifc->name, ifc->ifindex, ifc->flags, ifc->mtu,
                    ifc->mac[0],ifc->mac[1],ifc->mac[2],
                    ifc->mac[3],ifc->mac[4],ifc->mac[5],
                    ifc->ip4_fwd ? "true":"false",
                    ifc->ip6_fwd ? "true":"false");
            for (ip_if_addr_t *a = ifc->addrs; a; a = a->next) {
                char ps[INET6_ADDRSTRLEN+4];
                ip_prefix_to_str(&a->prefix, ps, sizeof(ps));
                fprintf(f, "{\"type\":\"address\",\"ifindex\":%u,"
                           "\"prefix\":\"%s\",\"valid_lft\":%u,"
                           "\"pref_lft\":%u,\"state\":%u}\n",
                        ifc->ifindex, ps, a->valid_lft, a->pref_lft, a->state);
            }
            pthread_rwlock_unlock(&ifc->lock);
        }
    }
    pthread_rwlock_unlock(&ctx->if_table.lock);

    /* routes: one line per prefix, paths serialised inline */
    for (int af = 0; af < 2; af++) {
        ip_fwd_table_t *t = af == 0 ? &ctx->fwd4 : &ctx->fwd6;
        pthread_rwlock_rdlock(&t->lock);
        for (uint32_t i = 0; i < t->n_buckets; i++) {
            for (ip_fwd_entry_t *e = t->buckets[i]; e; e = e->next) {
                char ps[INET6_ADDRSTRLEN+4];
                ip_prefix_to_str(&e->prefix, ps, sizeof(ps));
                fprintf(f, "{\"type\":\"route\","
                           "\"prefix\":\"%s\",\"ad\":%u,\"metric\":%u,"
                           "\"ecmp_hash_mode\":%u,\"n_paths\":%u",
                        ps, e->ad, e->metric,
                        e->ecmp_hash_mode, e->n_paths);
                for (uint8_t p = 0; p < e->n_paths; p++) {
                    char nh[INET6_ADDRSTRLEN] = "::";
                    ip_addr_to_str(&e->paths[p].addr, nh, sizeof(nh));
                    fprintf(f, ",\"nh%u\":\"%s\",\"if%u\":%u,"
                               "\"w%u\":%u,\"act%u\":%u",
                            p, nh, p, e->paths[p].ifindex,
                            p, e->paths[p].weight,
                            p, (unsigned)e->paths[p].active);
                }
                fprintf(f, "}\n");
            }
        }
        pthread_rwlock_unlock(&t->lock);
    }

    fflush(f); fclose(f);
    rename(tmp, path);
    return IP_OK;
}

static const char *jstr(const char *line, const char *key, char *out, size_t olen)
{
    char search[128];
    snprintf(search, sizeof(search), "\"%s\":\"", key);
    const char *p = strstr(line, search);
    if (!p) return NULL;
    p += strlen(search);
    size_t i = 0;
    while (*p && *p != '"' && i + 1 < olen) out[i++] = *p++;
    out[i] = '\0';
    return out;
}

static long json_int(const char *line, const char *key)
{
    char search[128];
    snprintf(search, sizeof(search), "\"%s\":", key);
    const char *p = strstr(line, search);
    if (!p) return -1;
    p += strlen(search);
    if (*p == '"') p++;
    return strtol(p, NULL, 10);
}

static bool json_bool(const char *line, const char *key)
{
    char search[128];
    snprintf(search, sizeof(search), "\"%s\":true", key);
    return strstr(line, search) != NULL;
}

int ip_load_config(ip_ctx_t *ctx, const char *path)
{
    if (!ctx || !path) return IP_ERR_INVAL;
    FILE *f = fopen(path, "r");
    if (!f) return IP_ERR_INVAL;
    char line[8192], type_buf[32], str_buf[INET6_ADDRSTRLEN+4];

    while (fgets(line, sizeof(line), f)) {
        if (!jstr(line, "type", type_buf, sizeof(type_buf))) continue;

        if (strcmp(type_buf, "fwd_config") == 0) {
            pthread_rwlock_wrlock(&ctx->cfg.lock);
            ctx->cfg.ipv4_forwarding  = json_bool(line, "ipv4_fwd");
            ctx->cfg.ipv6_forwarding  = json_bool(line, "ipv6_fwd");
            ctx->cfg.flags            = (uint32_t)json_int(line, "flags");
            long ttl = json_int(line, "default_ttl");
            ctx->cfg.default_ttl      = ttl > 0 ? (uint8_t)ttl : 64;
            long hl  = json_int(line, "default_hop_limit");
            ctx->cfg.default_hop_limit = hl > 0 ? (uint8_t)hl : 64;
            long hm  = json_int(line, "ecmp_hash_mode");
            ctx->cfg.ecmp_hash_mode   = hm >= 0 ? (uint32_t)hm : IP_ECMP_HASH_DEFAULT;
            pthread_rwlock_unlock(&ctx->cfg.lock);

        } else if (strcmp(type_buf, "interface") == 0) {
            char ifname[IFNAMSIZ]={0}, mac_str[32]={0};
            jstr(line,"name",ifname,sizeof(ifname));
            jstr(line,"mac", mac_str,sizeof(mac_str));
            uint32_t ifindex=(uint32_t)json_int(line,"ifindex");
            uint32_t flags  =(uint32_t)json_int(line,"flags");
            uint32_t mtu    =(uint32_t)json_int(line,"mtu");
            uint8_t mac[6]={0};
            sscanf(mac_str,"%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                   &mac[0],&mac[1],&mac[2],&mac[3],&mac[4],&mac[5]);
            ip_if_add(ctx, ifname, ifindex, flags, mtu, mac);
            ip_set_if_forwarding(ctx,ifindex,AF_INET, json_bool(line,"ip4_fwd"));
            ip_set_if_forwarding(ctx,ifindex,AF_INET6,json_bool(line,"ip6_fwd"));

        } else if (strcmp(type_buf, "address") == 0) {
            uint32_t ifindex=(uint32_t)json_int(line,"ifindex");
            jstr(line,"prefix",str_buf,sizeof(str_buf));
            ip_prefix_t pfx;
            if (ip_prefix_parse(str_buf,&pfx)==IP_OK) {
                uint32_t vl=(uint32_t)json_int(line,"valid_lft");
                uint32_t pl=(uint32_t)json_int(line,"pref_lft");
                ip_addr_add(ctx,ifindex,&pfx,vl,pl);
            }

        } else if (strcmp(type_buf, "route") == 0) {
            jstr(line,"prefix",str_buf,sizeof(str_buf));
            ip_prefix_t pfx;
            if (ip_prefix_parse(str_buf,&pfx) != IP_OK) continue;
            uint8_t  ad     = (uint8_t) json_int(line,"ad");
            uint32_t metric = (uint32_t)json_int(line,"metric");
            uint32_t hmode  = (uint32_t)json_int(line,"ecmp_hash_mode");
            long     np_l   = json_int(line,"n_paths");
            uint8_t  n_paths = np_l > 0 ? (uint8_t)np_l : 1;

            for (uint8_t p = 0; p < n_paths; p++) {
                char nhk[16], ifk[16], wk[16];
                snprintf(nhk,sizeof(nhk),"nh%u",p);
                snprintf(ifk,sizeof(ifk),"if%u",p);
                snprintf(wk, sizeof(wk), "w%u", p);
                char nhstr[INET6_ADDRSTRLEN]={0};
                jstr(line, nhk, nhstr, sizeof(nhstr));
                ip_addr_t nh; memset(&nh,0,sizeof(nh));
                ip_addr_parse(nhstr, &nh);
                uint32_t oif    = (uint32_t)json_int(line, ifk);
                long     wl     = json_int(line, wk);
                uint32_t weight = wl > 0 ? (uint32_t)wl : 1;
                ip_fwd_add(ctx, &pfx, &nh, oif, ad, metric, weight);
            }
            /* restore per-prefix hash mode */
            if (hmode) ip_set_ecmp_hash(ctx, &pfx, hmode);
        }
    }
    fclose(f);
    return IP_OK;
}

/* -----------------------------------------------------------------------
 * Lifecycle + signals
 * --------------------------------------------------------------------- */
static ip_ctx_t *g_ctx = NULL;

static void sig_handler(int sig)
{
    if (!g_ctx) return;
    if (sig == SIGHUP) ip_save_config(g_ctx, "ip_runtime_config.json");
    else if (sig == SIGTERM || sig == SIGINT) g_ctx->running = false;
}

ip_ctx_t *ip_ctx_create(void)
{
    ip_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return NULL;
    if (if_table_init(&ctx->if_table) != IP_OK ||
        fwd_table_init(&ctx->fwd4)    != IP_OK ||
        fwd_table_init(&ctx->fwd6)    != IP_OK ||
        pthread_rwlock_init(&ctx->cfg.lock,    NULL) ||
        pthread_rwlock_init(&ctx->stats4.lock, NULL) ||
        pthread_rwlock_init(&ctx->stats6.lock, NULL)) {
        ip_ctx_destroy(ctx); return NULL;
    }
    ctx->cfg.ipv4_forwarding   = true;
    ctx->cfg.ipv6_forwarding   = true;
    ctx->cfg.default_ttl       = 64;
    ctx->cfg.default_hop_limit = 64;
    ctx->cfg.flags             = IP_FWD_MARTIAN_DROP | IP_FWD_ICMP_UNREACH;
    ctx->cfg.ecmp_hash_mode    = IP_ECMP_HASH_DEFAULT;
    ctx->sock_fd = -1;
    return ctx;
}

void ip_ctx_destroy(ip_ctx_t *ctx)
{
    if (!ctx) return;
    if_table_destroy(&ctx->if_table);
    fwd_table_destroy(&ctx->fwd4);
    fwd_table_destroy(&ctx->fwd6);
    pthread_rwlock_destroy(&ctx->cfg.lock);
    pthread_rwlock_destroy(&ctx->stats4.lock);
    pthread_rwlock_destroy(&ctx->stats6.lock);
    free(ctx);
}

int ip_init(ip_ctx_t *ctx, const char *sock_path)
{
    if (!ctx || !sock_path) return IP_ERR_INVAL;
    strncpy(ctx->sock_path, sock_path, sizeof(ctx->sock_path) - 1);
    g_ctx = ctx;
    struct sigaction sa = { .sa_handler = sig_handler };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGHUP,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT,  &sa, NULL);
    ctx->running = true;
    if (ip_ipc_init(ctx) != IP_OK) return IP_ERR_INVAL;
    if (pthread_create(&ctx->ipc_thread, NULL, ip_ipc_thread, ctx))
        return IP_ERR_NOMEM;
    return IP_OK;
}

void ip_shutdown(ip_ctx_t *ctx)
{
    if (!ctx) return;
    ctx->running = false;
    ip_save_config(ctx, "ip_runtime_config.json");
    ip_ipc_stop(ctx);
    pthread_join(ctx->ipc_thread, NULL);
}
